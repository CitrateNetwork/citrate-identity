/**
 * FWA-C6-02 regression — Google OAuth state/nonce/verifier must be sharable
 * across instances and single-use, not pinned to one process's memory.
 *
 * The production authority runs MULTIPLE instances behind a load balancer
 * (the exact posture REDIS_URL is mandated for). A `/auth/google/start` served
 * by instance A and its `/auth/google/callback` landing on instance B must
 * resolve the SAME pending state, and the single-use / replay guarantee must
 * hold cluster-wide — mirroring the SIWE RedisNonceStore.
 *
 * These tests exercise the {@link RedisStateStore} class directly with two
 * ioredis-mock clients that share the same in-process keyspace (= two instances
 * sharing one Redis), plus the {@link InMemoryStateStore} for the dev fallback.
 *
 * RED on pre-fix code: state lived in a per-mount in-process Map, so a key
 * written by one instance was invisible to a second instance → cross-instance
 * resolve failed and replay was only bounded per-process.
 */
import { describe, expect, it } from 'vitest';
import RedisMock from 'ioredis-mock';

import {
  InMemoryStateStore,
  RedisStateStore,
} from '../../src/auth/google-routes.js';
import type { RedisLike } from '../../src/redis.js';

const VALUE = {
  interactionUid: 'int-1',
  codeVerifier: 'verifier-1',
  nonce: 'nonce-1',
} as const;

/**
 * Two RedisStateStores over the SAME in-memory ioredis-mock keyspace model two
 * authority instances sharing one Redis. ioredis-mock shares state across
 * instances constructed in the same process (default db).
 */
function twoInstances(): { a: RedisStateStore; b: RedisStateStore } {
  return {
    a: new RedisStateStore(new RedisMock() as unknown as RedisLike),
    b: new RedisStateStore(new RedisMock() as unknown as RedisLike),
  };
}

describe('FWA-C6-02: RedisStateStore is shared + single-use across instances', () => {
  it('a state PUT on instance A is TAKEable on instance B (cross-instance)', async () => {
    const { a, b } = twoInstances();
    await a.put('state-xyz', VALUE);

    const got = await b.take('state-xyz');
    expect(got).toBeDefined();
    expect(got!.interactionUid).toBe('int-1');
    expect(got!.codeVerifier).toBe('verifier-1');
    expect(got!.nonce).toBe('nonce-1');
  });

  it('take consumes exactly once — a replay on either instance gets undefined', async () => {
    const { a, b } = twoInstances();
    await a.put('state-replay', VALUE);

    const first = await b.take('state-replay');
    expect(first).toBeDefined();

    // Replayed callback (same state), even routed to the other instance → gone.
    const second = await a.take('state-replay');
    expect(second).toBeUndefined();
  });

  it('put uses NX so a live state is never silently overwritten', async () => {
    const redis = new RedisMock() as unknown as RedisLike;
    const store = new RedisStateStore(redis);
    await store.put('state-nx', VALUE);
    await store.put('state-nx', { ...VALUE, nonce: 'attacker-nonce' });

    const got = await store.take('state-nx');
    // The original (first) write must win; the second NX write was a no-op.
    expect(got!.nonce).toBe('nonce-1');
  });

  it('an unknown/expired state is absent → fail-closed undefined', async () => {
    const { a } = twoInstances();
    expect(await a.take('never-issued')).toBeUndefined();
  });

  it('malformed stored JSON is treated as absent (fail-closed)', async () => {
    const redis = new RedisMock() as unknown as RedisLike;
    await redis.set('google_state:bad', 'not-json{', 'PX', 600000, 'NX');
    const store = new RedisStateStore(redis);
    expect(await store.take('bad')).toBeUndefined();
  });

  it('namespaces keys under google_state: so they do not collide with nonces', async () => {
    const redis = new RedisMock() as unknown as RedisLike;
    const store = new RedisStateStore(redis);
    await store.put('k', VALUE);
    expect(await redis.get('google_state:k')).not.toBeNull();
    expect(await redis.get('k')).toBeNull();
  });
});

describe('FWA-C6-02: InMemoryStateStore dev fallback is single-use + TTL', () => {
  it('put then take returns the value exactly once', async () => {
    const store = new InMemoryStateStore();
    await store.put('s', VALUE);
    const first = await store.take('s');
    expect(first?.nonce).toBe('nonce-1');
    expect(await store.take('s')).toBeUndefined(); // single-use
  });

  it('an unknown state is undefined (fail-closed)', async () => {
    const store = new InMemoryStateStore();
    expect(await store.take('nope')).toBeUndefined();
  });
});
