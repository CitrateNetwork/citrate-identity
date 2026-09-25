/**
 * PBA-L3a-002 / PBA-L3a-011: the login rate limiter. Both backends honour the
 * same budget semantics; clientIp never trusts client-supplied XFF entries.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import RedisMock from 'ioredis-mock';
import {
  clientIp,
  InMemoryRateLimiter,
  RedisRateLimiter,
  createRateLimiter,
  type RateLimiter,
} from '../../src/auth/rate-limit.js';
import type { RedisLike } from '../../src/redis.js';

afterEach(() => vi.useRealTimers());

const backends: Array<[string, () => RateLimiter]> = [
  ['in-memory', () => new InMemoryRateLimiter()],
  ['redis', () => new RedisRateLimiter(new RedisMock() as unknown as RedisLike)],
];

for (const [name, make] of backends) {
  describe(`${name} rate limiter`, () => {
    it('allows exactly `limit` hits per key per window, then refuses', async () => {
      const l = make();
      const got: boolean[] = [];
      for (let i = 0; i < 5; i++) got.push(await l.hit('k', 3, 60_000));
      expect(got).toEqual([true, true, true, false, false]);
    });
    it('keys are independent', async () => {
      const l = make();
      expect(await l.hit('a', 1, 60_000)).toBe(true);
      expect(await l.hit('a', 1, 60_000)).toBe(false);
      expect(await l.hit('b', 1, 60_000)).toBe(true);
    });
    it('a limit of 0 refuses the first hit', async () => {
      expect(await make().hit('z', 0, 60_000)).toBe(false);
    });
  });
}

describe('in-memory window reset', () => {
  it('a new window starts after windowMs', async () => {
    vi.useFakeTimers();
    const l = new InMemoryRateLimiter();
    expect(await l.hit('k', 1, 1000)).toBe(true);
    expect(await l.hit('k', 1, 1000)).toBe(false);
    vi.advanceTimersByTime(999);
    expect(await l.hit('k', 1, 1000)).toBe(false);
    vi.advanceTimersByTime(1);
    expect(await l.hit('k', 1, 1000)).toBe(true);
  });
  it('pruning expired windows never resets a live one', async () => {
    vi.useFakeTimers();
    const l = new InMemoryRateLimiter();
    expect(await l.hit('live', 1, 10_000_000)).toBe(true);
    for (let i = 0; i < 2100; i++) await l.hit(`tmp${i}`, 5, 1);
    vi.advanceTimersByTime(5);
    for (let i = 0; i < 2100; i++) await l.hit(`tmp2${i}`, 5, 1);
    expect(await l.hit('live', 1, 10_000_000)).toBe(false);
    // Expired windows were actually dropped (memory stays bounded).
    expect(l.size).toBeLessThanOrEqual(2101); // round 1 (2100 expired) pruned; live + round 2 remain
  });
});

describe('redis window expiry', () => {
  it('sets a TTL on the first hit only', async () => {
    const r = new RedisMock() as unknown as RedisLike & { pttl(k: string): Promise<number> };
    const l = new RedisRateLimiter(r);
    await l.hit('k', 5, 60_000);
    const ttl1 = await r.pttl('ratelimit:k');
    expect(ttl1).toBeGreaterThan(0);
    expect(ttl1).toBeLessThanOrEqual(60_000);
    await l.hit('k', 5, 120_000);
    expect(await r.pttl('ratelimit:k')).toBeLessThanOrEqual(60_000);
  });
  it('createRateLimiter picks the backend from the redis option', () => {
    expect(createRateLimiter()).toBeInstanceOf(InMemoryRateLimiter);
    expect(createRateLimiter(new RedisMock() as unknown as RedisLike)).toBeInstanceOf(RedisRateLimiter);
  });
});

describe('clientIp', () => {
  const req = (xff: string | string[] | undefined, remote = '10.0.0.9') =>
    ({ headers: xff === undefined ? {} : { 'x-forwarded-for': xff }, socket: { remoteAddress: remote } }) as never;
  it('behind the proxy: the RIGHTMOST XFF entry (what the proxy saw), never a spoofed left one', () => {
    expect(clientIp(req('6.6.6.6, 1.2.3.4'), true)).toBe('1.2.3.4');
    expect(clientIp(req(' 1.2.3.4 '), true)).toBe('1.2.3.4');
    expect(clientIp(req(['6.6.6.6', '1.2.3.4']), true)).toBe('1.2.3.4');
    expect(clientIp(req('1.2.3.4, '), true)).toBe('1.2.3.4');
  });
  it('without a trusted proxy XFF is ignored', () => {
    expect(clientIp(req('6.6.6.6'), false)).toBe('10.0.0.9');
  });
  it('a request with no socket yields "unknown" rather than throwing', () => {
    expect(clientIp({ headers: {} } as never, false)).toBe('unknown');
  });
  it('falls back to the socket peer when XFF is absent or empty', () => {
    expect(clientIp(req(undefined), true)).toBe('10.0.0.9');
    expect(clientIp(req(' , '), true)).toBe('10.0.0.9');
  });
});
