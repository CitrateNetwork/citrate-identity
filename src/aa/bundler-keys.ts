/**
 * `bk_` bundler API-key minting — auth.citrate.ai self-serve surface
 * (EW-S1 WP-4 slice B, sprint item 12).
 *
 * The `citrate-bundler` gate validates a presented key with
 * `sismember('bundler:apikeys', sha256(key))` — only the SHA-256 hash is
 * ever stored, never the plaintext. This module mints into that SAME Redis
 * set so a key minted here is honoured by the gate.
 *
 * ⚠ CONTRACT: the set name, key prefix, key entropy, and hash MUST stay in
 * lockstep with `citrate-bundler/gate/src/apikeys.ts`. If you change one,
 * change both.
 *
 * Because a `bk_` key authorizes submitting UserOps the paymaster sponsors
 * gas for, minting is admin-gated (see {@link authorizeBundlerKeyMint}) and
 * fails closed when unconfigured.
 */
import { createHash, randomBytes } from 'node:crypto';

/** Redis set the bundler gate reads (must match citrate-bundler). */
export const BUNDLER_API_KEY_SET = 'bundler:apikeys';
const KEY_PREFIX = 'bk_';

/** SHA-256 hex of the full key string (matches the gate's `hashApiKey`). */
export function hashBundlerApiKey(key: string): string {
  return createHash('sha256').update(key, 'utf8').digest('hex');
}

/** Shape check identical to the gate's `looksLikeApiKey`. */
export function looksLikeBundlerApiKey(key: string): boolean {
  return key.startsWith(KEY_PREFIX) && /^bk_[A-Za-z0-9_-]{32,}$/.test(key);
}

/** The minimal Redis surface minting needs — `sadd` only (ioredis satisfies it). */
export interface BundlerKeyRedis {
  sadd(key: string, ...members: string[]): Promise<number>;
}

/**
 * Mint a fresh `bk_` key and register its SHA-256 in the gate's set.
 * Returns the PLAINTEXT once — only the hash is persisted, so a Redis dump
 * cannot be replayed as a credential.
 */
export async function mintBundlerApiKey(redis: BundlerKeyRedis): Promise<string> {
  const key = KEY_PREFIX + randomBytes(32).toString('base64url');
  await redis.sadd(BUNDLER_API_KEY_SET, hashBundlerApiKey(key));
  return key;
}

/** Parse `BUNDLER_KEY_ADMIN_SUBS` (comma-separated operator subjects). */
export function parseAdminSubs(raw: string | undefined): string[] {
  return (raw ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

/** Authorization outcome for a mint attempt (pure — unit-tested). */
export type MintAuthz =
  | { ok: true }
  | { ok: false; status: 401 | 403 | 503; error: string };

/**
 * Decide whether a mint may proceed. Fail-closed ordering:
 *  - not configured (no bundler Redis / no admin allowlist) → 503
 *  - no authenticated subject (no live interaction/session)  → 401
 *  - authenticated but not on the admin allowlist            → 403
 */
export function authorizeBundlerKeyMint(args: {
  configured: boolean;
  accountId: string | null;
  adminSubs: string[];
}): MintAuthz {
  if (!args.configured) {
    return { ok: false, status: 503, error: 'bundler key minting not configured' };
  }
  if (!args.accountId) {
    return { ok: false, status: 401, error: 'sign in first' };
  }
  if (!args.adminSubs.includes(args.accountId)) {
    return { ok: false, status: 403, error: 'not authorized to mint bundler keys' };
  }
  return { ok: true };
}
