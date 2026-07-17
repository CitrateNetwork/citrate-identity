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

import { timingSafeEqual } from 'node:crypto';

import type Provider from 'oidc-provider';
import { createPublicClient, getAddress, http, type Address, type Hex } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';

import { type AaConfig } from './config.js';
import { buildPermit } from './permit.js';
import { registerWalletIfNeeded, WalletNotDeployedError } from './register-wallet.js';
import { predictWalletAddress } from './predict.js';
import { accountIdToAaUserId } from './wallet-claims.js';
import {
  buildSponsorship,
  computeSponsorWindow,
  SponsorCategory,
} from './sponsor.js';

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

  // WS-6 boot sanity check: if the sponsor is configured with an expected
  // public address, verify the derived key maps to it. Fail loud at boot
  // rather than mint signatures from the wrong signer. The raw key is never
  // logged — only the derived + expected public addresses are compared.
  if (config.sponsor?.signerAddr) {
    const derived = privateKeyToAccount(config.sponsor.signerKey).address;
    if (derived.toLowerCase() !== config.sponsor.signerAddr.toLowerCase()) {
      throw new Error(
        `[aa-sponsor] CITRATE_AA_SPONSOR_SIGNER_KEY derives ${derived} but ` +
          `CITRATE_AA_SPONSOR_SIGNER_ADDR is ${config.sponsor.signerAddr}`,
      );
    }
  }

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

    // POST /aa/register-wallet ─────────────────────────────────
    // RADAR handoff T-2: after the factory deploy lands, register
    // the wallet with CitratePaymaster so sponsorship stops
    // reverting NotARegisteredCitrateWallet. Auth + userId gate are
    // identical to /aa/enroll-validator; the wallet address is
    // DERIVED from the authenticated userId (never taken from the
    // body), so a caller can only ever register their own wallet.
    if (ctx.method === 'POST' && ctx.path === '/aa/register-wallet') {
      const account = await resolveAccount(provider, ctx);
      if (!account) {
        respondJson(ctx, 401, { error: 'unauthorized', reason: 'access token required' });
        return;
      }
      const body = await readJsonBody(ctx);
      const userId = body ? (stringField(body, 'userId') as Hex | null) : null;
      if (!userId || !userId.startsWith('0x') || userId.length !== 66) {
        respondJson(ctx, 400, {
          error: 'invalid_request',
          reason: 'userId must be a 0x-prefixed 32-byte hex string',
        });
        return;
      }
      if (account !== userId) {
        respondJson(ctx, 403, {
          error: 'forbidden',
          reason: 'userId in body must match the authenticated subject',
        });
        return;
      }
      if (!config.paymaster || !config.registrarKey) {
        respondJson(ctx, 503, {
          error: 'registrar_unconfigured',
          reason: 'authority has no paymaster registrar configured',
        });
        return;
      }
      const wallet = predictWalletAddress(config.factory, config.kernelImpl, userId);
      try {
        const result = await registerWalletIfNeeded(
          {
            rpcUrl,
            chainId: config.chainId,
            paymaster: config.paymaster,
            registrarKey: config.registrarKey,
          },
          wallet,
        );
        respondJson(ctx, 200, {
          userId,
          wallet,
          paymaster: config.paymaster,
          status: result.status,
          ...(result.status === 'registered' ? { txHash: result.txHash } : {}),
        });
      } catch (err) {
        if (err instanceof WalletNotDeployedError) {
          respondJson(ctx, 409, {
            error: 'wallet_not_deployed',
            reason: err.message,
          });
          return;
        }
        respondJson(ctx, 502, {
          error: 'register_failed',
          reason: (err as Error).message,
        });
      }
      return;
    }

    // POST /aa/sponsor ─────────────────────────────────────────
    // WS-6 (Wave-2 Track G): sign a CitratePaymaster sponsorship digest so a
    // member's UserOp can be gas-sponsored. AUTH: a shared SERVICE TOKEN — the
    // caller is a trusted machine (core-membership), NOT an end user. The
    // caller supplies `sender` (the member smart-wallet address) in the body;
    // we treat the token as fully authorizing sponsorship of that account. The
    // trust boundary: anyone holding CITRATE_AA_SPONSOR_SERVICE_TOKEN can mint
    // a sponsorship signature for any sender, bounded by the paymaster's own
    // per-account caps (firstOpCap / hasUsedFirstOp / daily caps) and the SHORT
    // signed window this route enforces (<= 15 min). Keep the token
    // machine-to-machine only; never expose it to browsers.
    if (ctx.method === 'POST' && ctx.path === '/aa/sponsor') {
      const sponsor = config.sponsor;
      if (!sponsor) {
        respondJson(ctx, 503, {
          error: 'sponsor_unconfigured',
          reason: 'authority has no paymaster sponsor signer configured',
        });
        return;
      }
      if (!serviceTokenOk(ctx, sponsor.serviceToken)) {
        respondJson(ctx, 401, {
          error: 'unauthorized',
          reason: 'valid service token required',
        });
        return;
      }
      const body = await readJsonBody(ctx);
      const rawSender = body ? stringField(body, 'sender') : null;
      if (!rawSender || !/^0x[a-fA-F0-9]{40}$/.test(rawSender)) {
        respondJson(ctx, 400, {
          error: 'invalid_request',
          reason: 'sender must be a 20-byte 0x-prefixed address',
        });
        return;
      }
      // Normalize to a checksummed address (case-insensitive → same 20 bytes,
      // so the digest is unchanged); tolerates lowercase input from callers.
      const sender: Address = getAddress(rawSender);
      // Category: default to first-op (the deploy + first sponsored action).
      let category = SponsorCategory.FirstOp as number;
      if (body && body.category !== undefined) {
        const c = numberField(body, 'category');
        if (c === null || (c !== 0 && c !== 1 && c !== 2)) {
          respondJson(ctx, 400, {
            error: 'invalid_request',
            reason: 'category must be 0 (standard), 1 (recovery), or 2 (first-op)',
          });
          return;
        }
        category = c;
      }
      // TTL: default from config, clamped to [60, 900] inside computeSponsorWindow.
      let ttlSeconds = sponsor.defaultTtlSeconds;
      if (body && body.ttlSeconds !== undefined) {
        const t = numberField(body, 'ttlSeconds');
        if (t === null) {
          respondJson(ctx, 400, {
            error: 'invalid_request',
            reason: 'ttlSeconds must be a positive number',
          });
          return;
        }
        ttlSeconds = t;
      }
      try {
        const nowSeconds = BigInt(Math.floor(Date.now() / 1000));
        const window = computeSponsorWindow(nowSeconds, ttlSeconds);
        const s = await buildSponsorship({
          chainId: config.chainId,
          paymaster: sponsor.paymaster,
          account: sender,
          category,
          validUntil: window.validUntil,
          validAfter: window.validAfter,
          sponsorSignerHex: sponsor.signerKey,
        });
        respondJson(ctx, 200, {
          paymaster: sponsor.paymaster,
          account: sender,
          chainId: config.chainId.toString(),
          category: s.category,
          validUntil: s.validUntil.toString(),
          validAfter: s.validAfter.toString(),
          signature: s.signature,
          digest: s.digest,
        });
      } catch (err) {
        respondJson(ctx, 500, {
          error: 'sponsor_sign_failed',
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

/**
 * Constant-time service-token check for POST /aa/sponsor. Reads the token
 * from `Authorization: Bearer <token>` or the `X-Citrate-Service-Token`
 * header and compares it against the configured secret without leaking
 * length or content via timing. Mirrors the alf/admin route posture.
 */
function serviceTokenOk(ctx: Ctx, expected: string): boolean {
  if (!expected) return false;
  const presented = presentedServiceToken(ctx);
  if (presented === undefined) return false;
  const a = Buffer.from(presented, 'utf8');
  const b = Buffer.from(expected, 'utf8');
  if (a.length !== b.length) {
    // Equal-length compare against self so timing does not reveal length.
    timingSafeEqual(b, b);
    return false;
  }
  return timingSafeEqual(a, b);
}

function presentedServiceToken(ctx: Ctx): string | undefined {
  const auth = ctx.headers.authorization;
  if (typeof auth === 'string') {
    const m = /^Bearer\s+(.+)$/i.exec(auth.trim());
    if (m) return m[1].trim();
  }
  const h = ctx.headers['x-citrate-service-token'];
  if (typeof h === 'string' && h.length > 0) return h.trim();
  return undefined;
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
