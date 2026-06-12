/**
 * Mount the `/aa/*` HTTP surface on the authority's koa app
 * (WP-5 of EW-S1).
 *
 * Three routes:
 *
 *   GET  /aa/address?userId=<hex>         — predict a Citrate user's
 *                                            smart-wallet address
 *                                            (deterministic; no auth)
 *   POST /aa/enroll-validator             — mint a CitrateWalletFactory
 *                                            deploy permit signed by the
 *                                            authority's identity key;
 *                                            requires an OIDC access
 *                                            token for the userId
 *   GET  /aa/validators?userId=<hex>      — list the validators
 *                                            currently installed on the
 *                                            wallet (chain read)
 *
 * Wired into `server.ts` next to `mountKycRoutes`.
 */

import type Provider from 'oidc-provider';
import { createPublicClient, http, type Address, type Hex } from 'viem';

import { type AaConfig } from './config.js';
import { buildPermit } from './permit.js';
import { predictWalletAddress } from './predict.js';
import { accountIdToAaUserId } from './wallet-claims.js';

type Ctx = Parameters<Parameters<Provider['use']>[0]>[0];
type Next = Parameters<Parameters<Provider['use']>[0]>[1];

interface AaRouteOptions {
  config: AaConfig;
  /** Authority's chain JSON-RPC URL. Used for /aa/validators reads. */
  rpcUrl: string;
}

/**
 * Mount /aa/* on the provider's koa app. Idempotent — calling twice
 * registers the routes twice (callers should mount once at boot).
 */
export function mountAaRoutes(provider: Provider, options: AaRouteOptions): void {
  const { config, rpcUrl } = options;

  // The chain client is shared across requests; cheap to construct.
  const chainClient = createPublicClient({
    transport: http(rpcUrl),
  });

  provider.use(async (ctx: Ctx, next: Next) => {
    if (!ctx.path.startsWith('/aa/')) return next();

    // GET /aa/address ──────────────────────────────────────────
    if (ctx.method === 'GET' && ctx.path === '/aa/address') {
      const userId = parseUserIdQuery(ctx);
      if (userId === null) {
        respondJson(ctx, 400, {
          error: 'invalid_request',
          reason: 'userId must be a 0x-prefixed 32-byte hex string',
        });
        return;
      }
      try {
        const address = predictWalletAddress(config.factory, config.kernelImpl, userId);
        respondJson(ctx, 200, { userId, address, chainId: config.chainId.toString() });
      } catch (err) {
        respondJson(ctx, 400, {
          error: 'invalid_request',
          reason: (err as Error).message,
        });
      }
      return;
    }

    // POST /aa/enroll-validator ────────────────────────────────
    if (ctx.method === 'POST' && ctx.path === '/aa/enroll-validator') {
      const account = await resolveAccount(provider, ctx);
      if (!account) {
        respondJson(ctx, 401, { error: 'unauthorized', reason: 'access token required' });
        return;
      }
      const body = await readJsonBody(ctx);
      if (!body) {
        respondJson(ctx, 400, { error: 'invalid_request', reason: 'JSON body required' });
        return;
      }

      const userId = stringField(body, 'userId') as Hex | null;
      const initData = stringField(body, 'initData') as Hex | null;
      const expiresAtNum = numberField(body, 'expiresAt');

      if (!userId || !initData || expiresAtNum === null) {
        respondJson(ctx, 400, {
          error: 'invalid_request',
          reason: 'userId, initData, expiresAt are required',
        });
        return;
      }
      if (!userId.startsWith('0x') || userId.length !== 66) {
        respondJson(ctx, 400, {
          error: 'invalid_request',
          reason: 'userId must be a 0x-prefixed 32-byte hex string',
        });
        return;
      }
      if (!initData.startsWith('0x') || initData.length < 4) {
        respondJson(ctx, 400, {
          error: 'invalid_request',
          reason: 'initData must be a 0x-prefixed hex string',
        });
        return;
      }
      // The authenticated user MUST claim their own userId. This is
      // the gate that stops one user from minting a permit that
      // deploys a wallet at another user's identity-keyed address.
      if (account !== userId) {
        respondJson(ctx, 403, {
          error: 'forbidden',
          reason: 'userId in body must match the authenticated subject',
        });
        return;
      }
      const expiresAt = BigInt(expiresAtNum);
      if (expiresAt <= BigInt(Math.floor(Date.now() / 1000))) {
        respondJson(ctx, 400, {
          error: 'invalid_request',
          reason: 'expiresAt must be in the future',
        });
        return;
      }

      try {
        const { digest, signature } = await buildPermit({
          factory: config.factory,
          chainId: config.chainId,
          userId,
          initData,
          expiresAt,
          identitySignerHex: config.identitySignerKey,
        });
        const predicted = predictWalletAddress(
          config.factory,
          config.kernelImpl,
          userId,
        );
        respondJson(ctx, 200, {
          userId,
          factory: config.factory,
          chainId: config.chainId.toString(),
          predictedAddress: predicted,
          permitDigest: digest,
          signature,
          expiresAt: expiresAt.toString(),
        });
      } catch (err) {
        respondJson(ctx, 500, {
          error: 'permit_sign_failed',
          reason: (err as Error).message,
        });
      }
      return;
    }

    // GET /aa/validators ──────────────────────────────────────
    if (ctx.method === 'GET' && ctx.path === '/aa/validators') {
      const userId = parseUserIdQuery(ctx);
      if (userId === null) {
        respondJson(ctx, 400, {
          error: 'invalid_request',
          reason: 'userId must be a 0x-prefixed 32-byte hex string',
        });
        return;
      }
      const account = predictWalletAddress(config.factory, config.kernelImpl, userId);
      let deployed = false;
      try {
        const code = await chainClient.getBytecode({ address: account });
        deployed = code !== undefined && code !== '0x';
      } catch (err) {
        respondJson(ctx, 502, {
          error: 'chain_unreachable',
          reason: (err as Error).message,
        });
        return;
      }
      respondJson(ctx, 200, {
        userId,
        account,
        deployed,
        // Per ADR-2026-06-05-ew-surface-interop the dashboard reads
        // validators from indexed chain events; this v1 endpoint
        // surfaces the deploy status so the SDK can decide whether
        // to render a "deploy" vs "already deployed" CTA. The
        // validator-list enumeration ships in a follow-up commit
        // alongside the event-indexer wiring.
        validators: deployed ? '(query event indexer)' : [],
      });
      return;
    }

    return next();
  });
}

// ─────────────────────────────────────────────────────────────────────

function parseUserIdQuery(ctx: Ctx): Hex | null {
  const q = ctx.query?.userId;
  if (typeof q !== 'string') return null;
  if (!q.startsWith('0x') || q.length !== 66) return null;
  return q as Hex;
}

async function readJsonBody(ctx: Ctx): Promise<Record<string, unknown> | null> {
  // panva exposes the koa context with a request.body usually set by
  // a body parser if mounted; otherwise we read raw.
  const existing = (ctx.request as { body?: unknown }).body;
  if (existing && typeof existing === 'object' && !Array.isArray(existing)) {
    return existing as Record<string, unknown>;
  }
  const chunks: Buffer[] = [];
  await new Promise<void>((resolve, reject) => {
    const req = ctx.req as NodeJS.ReadableStream;
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => resolve());
    req.on('error', reject);
  });
  if (chunks.length === 0) return null;
  try {
    const parsed = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      return parsed as Record<string, unknown>;
    }
    return null;
  } catch {
    return null;
  }
}

function stringField(body: Record<string, unknown>, key: string): string | null {
  const v = body[key];
  return typeof v === 'string' && v.length > 0 ? v : null;
}

function numberField(body: Record<string, unknown>, key: string): number | null {
  const v = body[key];
  if (typeof v === 'number' && Number.isFinite(v) && v >= 0) return v;
  if (typeof v === 'string') {
    const n = Number(v);
    if (Number.isFinite(n) && n >= 0) return n;
  }
  return null;
}

function respondJson(ctx: Ctx, status: number, body: unknown): void {
  ctx.status = status;
  ctx.type = 'application/json';
  ctx.body = body;
}

/**
 * Resolve the bearer-token-authenticated subject to the user's userId.
 *
 * The OIDC access token's `accountId` claim is what we treat as the
 * Citrate userId. Users sign in with SIWE or (later) email/password and
 * the panva account id is the wallet address (current SIWE flow) or
 * the user's UUID (post-WP-6 multi-method flow). Either way, the
 * subject identifies "the human" and matches the `userId` parameter
 * the factory will salt with.
 */
async function resolveAccount(provider: Provider, ctx: Ctx): Promise<Hex | null> {
  const auth = ctx.headers.authorization;
  if (typeof auth !== 'string') return null;
  const m = /^Bearer\s+(.+)$/i.exec(auth.trim());
  if (!m) return null;
  const tokenStr = m[1].trim();
  try {
    const token = await provider.AccessToken.find(tokenStr);
    if (!token || token.isExpired) return null;
    const acct = token.accountId;
    if (typeof acct !== 'string') return null;
    // All three account shapes resolve to a 32-byte AA userId:
    // raw 32-byte hex, zero-padded SIWE EOA, or keccak256(uuid) for
    // the UUID-keyed passkey/email/Google users (EW-S1 WP-6).
    return accountIdToAaUserId(acct);
  } catch {
    return null;
  }
}

/**
 * Compute the userId form an OIDC account string. Public so callers
 * (and tests) can reproduce the same wrapping logic without going
 * through the HTTP layer. Delegates to the wallet-claims seam so the
 * UUID mapping has exactly one definition.
 */
export function accountIdToUserId(accountId: string): Hex | null {
  return accountIdToAaUserId(accountId);
}

// Re-export the route helper types for callers.
export type { Address, Hex };
