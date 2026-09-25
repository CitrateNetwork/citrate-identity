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
import {
  createPublicClient,
  decodeFunctionData,
  getAddress,
  http,
  isAddress,
  keccak256,
  sha256,
  type Address,
  type Hex,
} from 'viem';

import { type AaConfig } from './config.js';
import { buildPermit } from './permit.js';
import { registerWalletIfNeeded, WalletNotDeployedError } from './register-wallet.js';
import { predictWalletAddress } from './predict.js';
import { accountIdToAaUserId } from './wallet-claims.js';
import { guardianInstallModuleCall } from './install-data.js';
import { getGuardianStore } from './guardians.js';
import { getWalletRegistry } from '../identity-registry.js';
import { getUserStore, getWebAuthnStore } from '../auth/stores.js';
import { InMemoryRateLimiter, type RateLimiter } from '../auth/rate-limit.js';

/**
 * PBA-L3a-004: longest permit lifetime the authority signs. One hour (the
 * access-token TTL) plus 60 s of client clock skew: the shipped wallet extension
 * asks for now+3600. A permit is a bearer credential for the victim's wallet
 * address, so it must never be "effectively permanent".
 */
export const MAX_PERMIT_TTL_SEC = 3600 + 60;

/**
 * PBA-L3a-004: the Citrate-owned clients that legitimately request deploy
 * permits (radar's passport mint, the wallet extension, the native/desktop
 * apps). A token minted for any other RP cannot obtain one.
 */
export const AA_PERMIT_CLIENT_IDS: ReadonlySet<string> = new Set([
  'citrate-radar',
  'citrate-wallet-extension',
  'citrate-gui-native',
  'citrate-core',
]);

/** Permits per user per hour (a leaked token cannot mint an unbounded supply). */
export const PERMITS_PER_USER_PER_HOUR = 5;

const KERNEL_INITIALIZE_ABI = [
  {
    type: 'function',
    name: 'initialize',
    inputs: [
      { name: 'rootValidator', type: 'bytes21' },
      { name: 'hook', type: 'address' },
      { name: 'validatorData', type: 'bytes' },
      { name: 'hookData', type: 'bytes' },
      { name: 'initConfig', type: 'bytes[]' },
    ],
    outputs: [],
    stateMutability: 'payable',
  },
] as const;

const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000';

export type RootValidator =
  | { kind: 'ecdsa'; validator: Address; owner: Address; initConfig: readonly Hex[] }
  | { kind: 'webauthn'; validator: Address; credentialIdHash: Hex; initConfig: readonly Hex[] };

/**
 * Decode `initData` as Kernel `initialize(...)` and classify its root validator
 * by the strict install-data lengths the contracts enforce (ECDSA 21 bytes =
 * owner|source, WebAuthn 97 bytes = credIdHash|x|y|uv). Anything else → null.
 * A non-zero hook is refused (a hook runs on every operation).
 */
export function parseKernelInitData(initData: Hex): RootValidator | null {
  let decoded;
  try {
    decoded = decodeFunctionData({ abi: KERNEL_INITIALIZE_ABI, data: initData });
  } catch {
    return null;
  }
  const [rootValidator, hook, validatorData, hookData, initConfig] = decoded.args;
  if (rootValidator.length !== 44 || !rootValidator.toLowerCase().startsWith('0x01')) return null;
  if (hook.toLowerCase() !== ZERO_ADDRESS || hookData !== '0x') return null;
  const validator = getAddress(`0x${rootValidator.slice(4)}`);
  const vd = validatorData.slice(2);
  if (vd.length === 21 * 2) {
    return { kind: 'ecdsa', validator, owner: getAddress(`0x${vd.slice(0, 40)}`), initConfig };
  }
  if (vd.length === 97 * 2) {
    return { kind: 'webauthn', validator, credentialIdHash: `0x${vd.slice(0, 64)}` as Hex, initConfig };
  }
  return null;
}

type Ctx = Parameters<Parameters<Provider['use']>[0]>[0];
type Next = Parameters<Parameters<Provider['use']>[0]>[1];

interface AaRouteOptions {
  config: AaConfig;
  /** Authority's chain JSON-RPC URL. Used for /aa/validators reads. */
  rpcUrl: string;
  /**
   * GuardianRecoveryModule address (same value the guardian routes serve). The
   * ONLY initConfig entry a permit may carry is this module installed with the
   * caller's own stored nomination.
   */
  recoveryModule?: Address;
  /** Permit issuance budget (tests). Defaults to a per-process limiter. */
  permitLimiter?: RateLimiter;
}

/**
 * Mount /aa/* on the provider's koa app. Idempotent — calling twice
 * registers the routes twice (callers should mount once at boot).
 */
export function mountAaRoutes(provider: Provider, options: AaRouteOptions): void {
  const { config, rpcUrl } = options;
  const permitLimiter = options.permitLimiter ?? new InMemoryRateLimiter();

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
      const caller = await resolveCaller(provider, ctx);
      if (!caller) {
        respondJson(ctx, 401, { error: 'unauthorized', reason: 'access token required' });
        return;
      }
      const account = caller.userId;
      // PBA-L3a-004: only first-party permit clients.
      if (!AA_PERMIT_CLIENT_IDS.has(caller.clientId)) {
        respondJson(ctx, 403, {
          error: 'client_not_permitted',
          reason: 'this client may not request wallet deploy permits',
        });
        return;
      }
      if (!config.ecdsaValidator && !config.webauthnValidator) {
        respondJson(ctx, 503, {
          error: 'aa_validators_unconfigured',
          reason: 'set CITRATE_AA_ECDSA_VALIDATOR / CITRATE_AA_WEBAUTHN_VALIDATOR to sign deploy permits',
        });
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
      const expiresAt = BigInt(Math.floor(expiresAtNum));
      const nowSec = BigInt(Math.floor(Date.now() / 1000));
      if (expiresAt <= nowSec) {
        respondJson(ctx, 400, {
          error: 'invalid_request',
          reason: 'expiresAt must be in the future',
        });
        return;
      }
      // PBA-L3a-004: no long-lived permits.
      if (expiresAt > nowSec + BigInt(MAX_PERMIT_TTL_SEC)) {
        respondJson(ctx, 400, {
          error: 'invalid_request',
          reason: `expiresAt may be at most ${MAX_PERMIT_TTL_SEC}s in the future`,
        });
        return;
      }
      // PBA-L3a-004: initData must install the CALLER's own root validator.
      const root = parseKernelInitData(initData);
      if (!root) {
        respondJson(ctx, 400, {
          error: 'invalid_request',
          reason: 'initData must be a Kernel initialize() with an ECDSA or WebAuthn root validator and no hook',
        });
        return;
      }
      const ownership = await checkRootValidatorOwnership(root, caller.accountId, config, options.recoveryModule);
      if (ownership !== true) {
        respondJson(ctx, 403, { error: 'validator_not_owned', reason: ownership });
        return;
      }
      if (!(await permitLimiter.hit(`aa-permit:${userId.toLowerCase()}`, PERMITS_PER_USER_PER_HOUR, 60 * 60 * 1000))) {
        respondJson(ctx, 429, { error: 'too_many_requests', reason: 'permit budget for this wallet is spent; retry later' });
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
 * PBA-L3a-004: the bearer token's subject, its AA userId and the client it was
 * minted for (permits are restricted to {@link AA_PERMIT_CLIENT_IDS}).
 */
async function resolveCaller(
  provider: Provider,
  ctx: Ctx,
): Promise<{ accountId: string; userId: Hex; clientId: string } | null> {
  const auth = ctx.headers.authorization;
  if (typeof auth !== 'string') return null;
  const m = /^Bearer\s+(.+)$/i.exec(auth.trim());
  if (!m) return null;
  try {
    const token = await provider.AccessToken.find(m[1].trim());
    if (!token || token.isExpired) return null;
    const acct = token.accountId;
    const clientId = token.clientId;
    if (typeof acct !== 'string' || typeof clientId !== 'string') return null;
    const userId = accountIdToAaUserId(acct);
    return userId ? { accountId: acct, userId, clientId } : null;
  } catch {
    return null;
  }
}

/**
 * PBA-L3a-004: is the root validator the caller's own?
 *   - validator module must be the configured canonical one for its kind;
 *   - ECDSA owner ∈ { the SIWE address the caller signed in with, the caller's
 *     bound primary wallet, the caller's registry-proven wallets };
 *   - WebAuthn credentialIdHash = keccak256 or sha256 of one of the caller's
 *     registered passkey credential ids;
 *   - initConfig: empty, or exactly the guardian-module install for the
 *     caller's own stored nomination.
 * Returns true, or the refusal reason.
 */
export async function checkRootValidatorOwnership(
  root: RootValidator,
  accountId: string,
  config: AaConfig,
  recoveryModule?: Address,
): Promise<true | string> {
  const expected = root.kind === 'ecdsa' ? config.ecdsaValidator : config.webauthnValidator;
  if (!expected || getAddress(expected) !== root.validator) {
    return `root validator ${root.validator} is not the canonical ${root.kind} validator`;
  }
  if (root.kind === 'ecdsa') {
    const owners = new Set<string>();
    if (isAddress(accountId)) owners.add(getAddress(accountId));
    try {
      const rec = await getUserStore().findById(accountId);
      if (rec?.primaryWallet) owners.add(getAddress(rec.primaryWallet));
    } catch {
      // not a UUID-keyed user
    }
    for (const w of await getWalletRegistry().list(accountId)) owners.add(getAddress(w.address));
    if (!owners.has(root.owner)) return 'the ECDSA owner is not a wallet this account has proven';
  } else {
    const creds = await getWebAuthnStore().listByUserId(accountId);
    const mine = creds.some((c) => {
      const id = new Uint8Array(c.credentialId);
      return keccak256(id) === root.credentialIdHash.toLowerCase() || sha256(id) === root.credentialIdHash.toLowerCase();
    });
    if (!mine) return 'the WebAuthn credential is not one of this account\'s passkeys';
  }
  if (root.initConfig.length > 0) {
    const nomination = recoveryModule ? await getGuardianStore().get(accountId) : undefined;
    const allowed =
      recoveryModule && nomination
        ? guardianInstallModuleCall({ recoveryModule, threshold: nomination.threshold, guardians: nomination.guardians as Address[] }).toLowerCase()
        : undefined;
    if (!allowed || root.initConfig.length !== 1 || root.initConfig[0]!.toLowerCase() !== allowed) {
      return 'initConfig may only install the guardian module with this account\'s own nomination';
    }
  }
  return true;
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
