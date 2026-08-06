/**
 * Single-use, subject-bound hand-off nonce store (item 2 of the 2026-08-06 backend
 * work order; spec: IDENTITY_ACCOUNT_HANDOFF_2026-08-06.md §3a).
 *
 * WHY THIS EXISTS. `/kyc/start` and `/account` resolve the acting user from the
 * BROWSER's auth.citrate.ai session cookie. The desktop app (Citrate Core) holds
 * its own OIDC session and cannot present it to a system-browser navigation, so a
 * member whose browser is signed into a DIFFERENT account silently gets that other
 * account's verification surface — a compliance-path identity misbinding.
 *
 * The fix is an AUTHENTICATED hand-off: the app proves who it is with the access
 * token it already holds (`POST /kyc/handoff`), the server mints a short-lived
 * nonce BOUND to that token's `sub`, and the consuming page (`?handoff=<nonce>`)
 * resolves the subject from the nonce and ignores the cookie.
 *
 * This is deliberately NOT the SIWE {@link NonceStore}: that store only records a
 * nonce's EXISTENCE (value `1`) and cannot carry the bound subject. It reuses the
 * SAME Redis infrastructure (one shared client, distinct `handoff:` key namespace)
 * so there is no new infrastructure — exactly as the hand-off spec requires. The
 * one-time guarantee is the atomic GETDEL, identical in spirit to the SIWE store's
 * consume: whichever instance's GETDEL removes the key wins; every replay (or a
 * racing instance) finds it gone.
 */
import { randomBytes } from 'node:crypto';
import type { RedisLike } from './redis.js';

/** A hand-off nonce carries the OIDC subject (accountId) it was minted for. */
export interface HandoffStore {
  /** Mint a fresh single-use nonce bound to `sub`. Returns the nonce value. */
  issue(sub: string): Promise<string>;
  /**
   * Consume a nonce exactly once, returning the `sub` it was bound to, or `null`
   * if it is unknown, already used, or expired. The same nonce never yields its
   * subject twice.
   */
  consume(nonce: string): Promise<string | null>;
}

/** Default nonce lifetime — 5 minutes, matching the SIWE nonce TTL (spec §3a). */
const DEFAULT_TTL_MS = 5 * 60 * 1000;
/** Key prefix, namespaced away from `nonce:` (SIWE) and other authority keys. */
const HANDOFF_PREFIX = 'handoff:';

/** 32 bytes of URL-safe randomness — the nonce is an unguessable capability. */
function freshNonce(): string {
  return randomBytes(32).toString('base64url');
}

/**
 * Redis-backed store (prod / HA). `issue` writes `handoff:<nonce> = sub` with a
 * TTL and `NX` (never clobber a live nonce); `consume` is an atomic GETDEL so the
 * read-and-delete is one server-side step and a replay can never re-read a
 * consumed nonce. GETDEL is present on Redis ≥ 6.2 and ioredis-mock — the shared
 * client already relies on it for the SIWE store, so no Lua fallback is needed.
 */
export class RedisHandoffStore implements HandoffStore {
  constructor(
    private readonly redis: RedisLike,
    private readonly ttlMs: number = DEFAULT_TTL_MS,
  ) {}

  async issue(sub: string): Promise<string> {
    const nonce = freshNonce();
    await this.redis.set(HANDOFF_PREFIX + nonce, sub, 'PX', this.ttlMs, 'NX');
    return nonce;
  }

  async consume(nonce: string): Promise<string | null> {
    if (!nonce) return null;
    return this.redis.getdel(HANDOFF_PREFIX + nonce);
  }
}

/**
 * In-memory store (dev / single-instance / tests). Same one-time + TTL contract as
 * {@link RedisHandoffStore}; the entry is deleted on first read regardless of
 * expiry, so a replay is `null` even within the TTL window. Not shared across
 * instances — prod always wires the Redis store via {@link createHandoffStore}.
 */
export class InMemoryHandoffStore implements HandoffStore {
  private readonly map = new Map<string, { sub: string; expiresAt: number }>();

  constructor(private readonly ttlMs: number = DEFAULT_TTL_MS) {}

  async issue(sub: string): Promise<string> {
    const nonce = freshNonce();
    this.map.set(nonce, { sub, expiresAt: Date.now() + this.ttlMs });
    return nonce;
  }

  async consume(nonce: string): Promise<string | null> {
    const entry = this.map.get(nonce);
    if (!entry) return null;
    // One-time: delete on first read, whether or not it has expired.
    this.map.delete(nonce);
    return entry.expiresAt > Date.now() ? entry.sub : null;
  }
}

/** Build the store the server uses: Redis when a client is wired, else in-memory. */
export function createHandoffStore(redis?: RedisLike): HandoffStore {
  return redis ? new RedisHandoffStore(redis) : new InMemoryHandoffStore();
}
