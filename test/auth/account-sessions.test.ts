/** The per-account Session/Grant index behind "Sign out of all sessions". */
import { afterEach, describe, expect, it } from 'vitest';
import RedisMock from 'ioredis-mock';
import {
  InMemoryAccountSessionIndex,
  RedisAccountSessionIndex,
  getAccountSessionIndex,
  initAccountSessionIndex,
  setAccountSessionIndex,
  type AccountSessionIndex,
} from '../../src/auth/account-sessions.js';
import { EPOCH_TTL_SEC } from '../../src/auth/account-epoch.js';
import type { RedisLike } from '../../src/redis.js';

const backends: Array<[string, () => AccountSessionIndex]> = [
  ['in-memory', () => new InMemoryAccountSessionIndex()],
  ['redis', () => new RedisAccountSessionIndex(new RedisMock() as unknown as RedisLike)],
];

afterEach(() => setAccountSessionIndex(new InMemoryAccountSessionIndex()));

for (const [name, make] of backends) {
  describe(`${name} account session index`, () => {
    it('returns what was added for the account, once', async () => {
      const idx = make();
      await idx.add(`acct-a-${name}`, 'Session', 's1');
      await idx.add(`acct-a-${name}`, 'Grant', 'g1');
      await idx.add(`acct-a-${name}`, 'Session', 's1');
      await idx.add(`acct-b-${name}`, 'Session', 's2');
      const drained = await idx.drain(`acct-a-${name}`);
      expect(drained).toHaveLength(2);
      expect(drained).toEqual(
        expect.arrayContaining([
          { kind: 'Session', id: 's1' },
          { kind: 'Grant', id: 'g1' },
        ]),
      );
      expect(await idx.drain(`acct-a-${name}`)).toEqual([]);
      expect(await idx.drain(`acct-b-${name}`)).toEqual([{ kind: 'Session', id: 's2' }]);
    });

    it('keeps ids that contain a colon intact', async () => {
      const idx = make();
      await idx.add(`acct-colon-${name}`, 'Grant', 'a:b:c');
      expect(await idx.drain(`acct-colon-${name}`)).toEqual([{ kind: 'Grant', id: 'a:b:c' }]);
    });
  });
}

describe('redis account session index', () => {
  it('expires the account key after the longest credential lifetime', async () => {
    const redis = new RedisMock() as unknown as RedisLike & { pttl(k: string): Promise<number> };
    await new RedisAccountSessionIndex(redis).add('acct-ttl', 'Session', 's1');
    const ttl = await redis.pttl('acct-sessions:acct-ttl');
    expect(ttl).toBeGreaterThan(EPOCH_TTL_SEC * 1000 - 5000);
    expect(ttl).toBeLessThanOrEqual(EPOCH_TTL_SEC * 1000);
  });

  it('ignores members it did not write', async () => {
    const redis = new RedisMock() as unknown as RedisLike;
    // ioredis-mock shares one keyspace across instances: use a key of our own.
    await redis.sadd('acct-sessions:foreign', 'AccessToken:x', 'garbage', 'Session:');
    await redis.sadd('acct-sessions:foreign', 'Session:ok');
    expect(await new RedisAccountSessionIndex(redis).drain('foreign')).toEqual([{ kind: 'Session', id: 'ok' }]);
  });

  it('is installed when a Redis client is wired, else the current index stays', () => {
    const before = getAccountSessionIndex();
    expect(initAccountSessionIndex(undefined)).toBe(before);
    expect(initAccountSessionIndex(new RedisMock() as unknown as RedisLike)).toBeInstanceOf(
      RedisAccountSessionIndex,
    );
  });
});
