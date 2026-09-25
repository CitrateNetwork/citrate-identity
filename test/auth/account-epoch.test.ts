/** PBA-L3a-008: the account revocation epoch (both backends + helpers). */
import { afterEach, describe, expect, it } from 'vitest';
import RedisMock from 'ioredis-mock';
import {
  EPOCH_TTL_SEC,
  InMemoryAccountEpochStore,
  RedisAccountEpochStore,
  getAccountEpochStore,
  initAccountEpochStore,
  isRevokedByEpoch,
  setAccountEpochStore,
  tokenAuthSec,
  type AccountEpochStore,
} from '../../src/auth/account-epoch.js';
import type { RedisLike } from '../../src/redis.js';

const backends: Array<[string, () => AccountEpochStore]> = [
  ['in-memory', () => new InMemoryAccountEpochStore()],
  ['redis', () => new RedisAccountEpochStore(new RedisMock() as unknown as RedisLike)],
];

afterEach(() => setAccountEpochStore(new InMemoryAccountEpochStore()));

for (const [name, make] of backends) {
  describe(`${name} account epoch`, () => {
    it('is undefined until bumped, then returns the stamp', async () => {
      const s = make();
      expect(await s.get('a')).toBeUndefined();
      expect(await s.bump('a', 1000)).toBe(1000);
      expect(await s.get('a')).toBe(1000);
      expect(await s.get('b')).toBeUndefined();
    });
    it('never moves backwards', async () => {
      const s = make();
      await s.bump('a', 2000);
      expect(await s.bump('a', 1500)).toBe(2000);
      expect(await s.get('a')).toBe(2000);
    });
    it('defaults the stamp to now (seconds)', async () => {
      const s = make();
      const before = Math.floor(Date.now() / 1000);
      const v = await s.bump('a');
      expect(v).toBeGreaterThanOrEqual(before);
      expect(v).toBeLessThanOrEqual(before + 1);
    });
  });
}

describe('redis epoch keys expire', () => {
  it('sets a TTL covering the longest credential lifetime', async () => {
    const r = new RedisMock() as unknown as RedisLike & { ttl(k: string): Promise<number> };
    await new RedisAccountEpochStore(r).bump('a', 5);
    const ttl = await r.ttl('acct-epoch:a');
    expect(ttl).toBeGreaterThan(EPOCH_TTL_SEC - 5);
    expect(ttl).toBeLessThanOrEqual(EPOCH_TTL_SEC);
    expect(EPOCH_TTL_SEC).toBeGreaterThanOrEqual(14 * 24 * 60 * 60);
  });
  it('a corrupt stored value reads as unset', async () => {
    const r = new RedisMock() as unknown as RedisLike;
    await r.set('acct-epoch:a', 'garbage');
    expect(await new RedisAccountEpochStore(r).get('a')).toBeUndefined();
  });
});

describe('isRevokedByEpoch / tokenAuthSec', () => {
  it('strictly-earlier credentials are revoked; same-second and later survive; no epoch → never', async () => {
    const s = new InMemoryAccountEpochStore();
    setAccountEpochStore(s);
    expect(getAccountEpochStore()).toBe(s);
    expect(await isRevokedByEpoch('a', 5)).toBe(false);
    expect(await isRevokedByEpoch('a', undefined)).toBe(false);
    await s.bump('a', 100);
    expect(await isRevokedByEpoch('a', 99)).toBe(true);
    expect(await isRevokedByEpoch('a', 100)).toBe(false);
    expect(await isRevokedByEpoch('a', 101)).toBe(false);
    expect(await isRevokedByEpoch('a', undefined)).toBe(true);
    expect(await isRevokedByEpoch('a', Number.NaN)).toBe(true);
    expect(await isRevokedByEpoch('other', 1)).toBe(false);
  });
  it('prefers iiat (survives refresh rotation) over iat', () => {
    expect(tokenAuthSec({ iiat: 10, iat: 50 })).toBe(10);
    expect(tokenAuthSec({ iat: 50 })).toBe(50);
    expect(tokenAuthSec({ iat: '50' })).toBeUndefined();
    expect(tokenAuthSec(undefined)).toBeUndefined();
  });
});

describe('initAccountEpochStore (called by createProvider with options.redis)', () => {
  it('installs the Redis-backed store (multi-instance) when a client is given, else leaves the current one', () => {
    const mem = new InMemoryAccountEpochStore();
    setAccountEpochStore(mem);
    expect(initAccountEpochStore()).toBe(mem);
    expect(initAccountEpochStore(new RedisMock() as unknown as RedisLike)).toBeInstanceOf(RedisAccountEpochStore);
    expect(getAccountEpochStore()).toBeInstanceOf(RedisAccountEpochStore);
  });
});
