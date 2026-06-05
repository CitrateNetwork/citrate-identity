/**
 * Redis-backed single-use SIWE nonce store (HA / multi-instance).
 *
 * Backs the EXISTING {@link NonceStore} seam (siwe.ts) with Redis so a nonce
 * issued by one authority instance is consumable EXACTLY ONCE across every
 * instance — the replay defence has to hold cluster-wide, not just per-process.
 * Selected by `REDIS_URL` (see {@link initNonceStoreFromEnv}); when unset the
 * in-memory {@link InMemoryNonceStore} is used unchanged (dev).
 *
 *   issue   → SET nonce:<v> 1 PX <ttl> NX   (one writer wins; short TTL)
 *   consume → atomic GETDEL nonce:<v>        (read-and-delete in ONE round trip)
 *
 * `consume` MUST be atomic: if two instances race to consume the same nonce, at
 * most one may win. A naive GET-then-DEL has a TOCTOU window where both read "1"
 * before either deletes. `GETDEL` (Redis ≥ 6.2) closes that window in a single
 * command. For older Redis we fall back to a tiny Lua script that does the same
 * check-and-delete atomically; either way the delete is what makes a nonce
 * one-time across instances.
 */
import { generateNonce } from 'siwe';
import type { NonceStore } from './siwe.js';
import type { RedisLike } from './redis.js';

/** Key prefix for nonce entries so they're namespaced from other authority keys. */
const NONCE_PREFIX = 'nonce:';

/**
 * Atomic check-and-delete: returns 1 and deletes the key iff it exists, else 0.
 * Registered via `defineCommand` as `nonceConsume` so the GET+DEL happen in one
 * server-side step even on a Redis without `GETDEL`. We prefer the native
 * `GETDEL` when available and only use this as the portable fallback.
 */
const CONSUME_LUA = `
local v = redis.call('GET', KEYS[1])
if v then
  redis.call('DEL', KEYS[1])
  return 1
end
return 0
`;

declare module './redis.js' {
  interface RedisLike {
    /** Registered Lua fallback for atomic one-time consume (see CONSUME_LUA). */
    nonceConsume?(key: string): Promise<number>;
  }
}

export class RedisNonceStore implements NonceStore {
  private readonly ttlMs: number;
  private readonly hasGetDel: boolean;

  /**
   * @param redis a shared {@link RedisLike} (ioredis / ioredis-mock).
   * @param ttlMs nonce lifetime; defaults to 5 minutes to match
   *   {@link InMemoryNonceStore}.
   */
  constructor(
    private readonly redis: RedisLike,
    ttlMs: number = 5 * 60 * 1000,
  ) {
    this.ttlMs = ttlMs;
    // Prefer native GETDEL (Redis ≥ 6.2 and ioredis-mock both have it); register
    // the Lua fallback once so a pre-6.2 server still gets an atomic consume.
    this.hasGetDel = typeof redis.getdel === 'function';
    if (!this.hasGetDel && typeof redis.nonceConsume !== 'function') {
      redis.defineCommand('nonceConsume', {
        numberOfKeys: 1,
        lua: CONSUME_LUA,
      });
    }
  }

  /**
   * Issue a fresh nonce and register it with a short TTL. `NX` makes the write a
   * no-op if (astronomically unlikely) the random value already exists, so we
   * never silently overwrite a live nonce. The TTL is set in the same command
   * (PX) so there is no window where a nonce exists without an expiry.
   */
  async issue(): Promise<string> {
    const nonce = generateNonce();
    await this.redis.set(NONCE_PREFIX + nonce, '1', 'PX', this.ttlMs, 'NX');
    return nonce;
  }

  /**
   * Consume a nonce exactly once. The atomic delete is what enforces one-time
   * use across instances: whichever instance's GETDEL/Lua removes the key gets
   * `true`; every later attempt (replay, or a racing instance) finds it gone and
   * gets `false`. An unknown OR already-expired nonce is also absent → `false`.
   */
  async consume(nonce: string): Promise<boolean> {
    const key = NONCE_PREFIX + nonce;
    if (this.hasGetDel) {
      const prev = await this.redis.getdel(key);
      return prev !== null;
    }
    const consumed = await this.redis.nonceConsume!(key);
    return consumed === 1;
  }
}
