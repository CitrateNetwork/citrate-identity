import { describe, expect, it } from 'vitest';
import RedisMock from 'ioredis-mock';
import { RedisNonceStore } from '../src/nonce-redis.js';
import type { RedisLike } from '../src/redis.js';

/**
 * RedisNonceStore (HA): the SIWE single-use nonce store backed by Redis so a
 * nonce issued by one authority instance is consumable EXACTLY ONCE across every
 * instance. Runs against `ioredis-mock` (in-process Redis) so it is fully offline
 * and shares data across "instances" exactly like a real shared Redis.
 *
 *   gtm-spine: replay defence must hold cluster-wide, not just per-process.
 */

/** A fresh mock Redis client typed as the narrow surface the store consumes. */
function freshRedis(): RedisLike {
  return new RedisMock() as unknown as RedisLike;
}

describe('RedisNonceStore (single-use across instances)', () => {
  it('issue → consume succeeds exactly once; a replay FAILS', async () => {
    const store = new RedisNonceStore(freshRedis());
    const nonce = await store.issue();
    expect(typeof nonce).toBe('string');
    expect(nonce.length).toBeGreaterThan(0);

    // First consume wins.
    expect(await store.consume(nonce)).toBe(true);
    // Replay of the same value is rejected (one-time).
    expect(await store.consume(nonce)).toBe(false);
  });

  it('consuming an unknown nonce FAILS (never issued)', async () => {
    const store = new RedisNonceStore(freshRedis());
    expect(await store.consume('never-issued-nonce')).toBe(false);
  });

  it('an expired nonce FAILS to consume (TTL elapsed)', async () => {
    // 1ms TTL → the key self-expires before we consume it.
    const store = new RedisNonceStore(freshRedis(), 1);
    const nonce = await store.issue();
    await new Promise((r) => setTimeout(r, 20));
    expect(await store.consume(nonce)).toBe(false);
  });

  it('CROSS-INSTANCE: a second store on the SAME redis consumes a nonce issued by the first — exactly once', async () => {
    // Two SEPARATE mock clients = two authority instances sharing one Redis.
    const instanceA = freshRedis();
    const instanceB = freshRedis();
    const storeA = new RedisNonceStore(instanceA);
    const storeB = new RedisNonceStore(instanceB);

    // Instance A issues the nonce...
    const nonce = await storeA.issue();
    // ...instance B (a different process) consumes it — proving the nonce is
    // shared, not process-local.
    expect(await storeB.consume(nonce)).toBe(true);
    // And neither instance can consume it again (one-time, cluster-wide).
    expect(await storeA.consume(nonce)).toBe(false);
    expect(await storeB.consume(nonce)).toBe(false);
  });

  it('CROSS-INSTANCE race: two instances consuming the same nonce — at most one wins', async () => {
    const a = freshRedis();
    const b = freshRedis();
    const storeA = new RedisNonceStore(a);
    const storeB = new RedisNonceStore(b);
    const nonce = await storeA.issue();

    // Both instances attempt to consume "simultaneously". GETDEL is atomic, so
    // exactly one observes the value and deletes it; the other sees it gone.
    const [r1, r2] = await Promise.all([
      storeA.consume(nonce),
      storeB.consume(nonce),
    ]);
    expect([r1, r2].filter(Boolean)).toHaveLength(1);
  });

  it('Lua fallback path: works when the client lacks GETDEL', async () => {
    // Simulate a pre-6.2 Redis by hiding getdel; the store must register and use
    // the atomic check-and-delete Lua script instead, with identical semantics.
    const redis = freshRedis() as unknown as Record<string, unknown>;
    Object.defineProperty(redis, 'getdel', { value: undefined });
    const store = new RedisNonceStore(redis as unknown as RedisLike);
    const nonce = await store.issue();
    expect(await store.consume(nonce)).toBe(true);
    expect(await store.consume(nonce)).toBe(false);
  });
});
