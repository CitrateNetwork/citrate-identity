/**
 * Fixed-window rate limiter for the login surfaces (PBA-L3a-002 / PBA-L3a-011).
 *
 * The email-code store caps guesses PER CODE and sends PER EMAIL; nothing capped
 * how fast one client could hit the login and code-verification endpoints. This
 * adds per-IP and per-account budgets in front of them.
 *
 * Two backends behind one interface:
 *   - {@link RedisRateLimiter}: shared across instances (prod runs Redis; see
 *     assertProductionConfig), one atomic INCR + PEXPIRE via Lua.
 *   - {@link InMemoryRateLimiter}: per process (dev/test).
 */
import type { IncomingMessage } from 'node:http';
import type { RedisLike } from '../redis.js';

export interface RateLimiter {
  /** Count one hit on `key`; true when it is within `limit` for the current window. */
  hit(key: string, limit: number, windowMs: number): Promise<boolean>;
}

export class InMemoryRateLimiter implements RateLimiter {
  private readonly windows = new Map<string, { count: number; resetAt: number }>();
  private hits = 0;

  async hit(key: string, limit: number, windowMs: number): Promise<boolean> {
    const now = Date.now();
    if (++this.hits % 1024 === 0) this.prune(now);
    const w = this.windows.get(key);
    if (!w || now >= w.resetAt) {
      this.windows.set(key, { count: 1, resetAt: now + windowMs });
      return 1 <= limit;
    }
    w.count += 1;
    return w.count <= limit;
  }

  /** Live window count (observability; bounded by pruning). */
  get size(): number {
    return this.windows.size;
  }

  private prune(now: number): void {
    for (const [k, w] of this.windows) if (now >= w.resetAt) this.windows.delete(k);
  }
}

const HIT_LUA = `
local n = redis.call('INCR', KEYS[1])
if n == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end
return n
`;

declare module '../redis.js' {
  interface RedisLike {
    /** Registered Lua: atomic INCR + first-hit PEXPIRE (see HIT_LUA). */
    rateLimitHit?(key: string, windowMs: number): Promise<number>;
  }
}

export class RedisRateLimiter implements RateLimiter {
  constructor(private readonly redis: RedisLike) {
    if (typeof redis.rateLimitHit !== 'function') {
      redis.defineCommand('rateLimitHit', { numberOfKeys: 1, lua: HIT_LUA });
    }
  }

  async hit(key: string, limit: number, windowMs: number): Promise<boolean> {
    const n = await this.redis.rateLimitHit!(`ratelimit:${key}`, windowMs);
    return Number(n) <= limit;
  }
}

export function createRateLimiter(redis?: RedisLike): RateLimiter {
  return redis ? new RedisRateLimiter(redis) : new InMemoryRateLimiter();
}

/**
 * The client's IP. Behind the TLS proxy (`provider.proxy = true`) the proxy
 * APPENDS the peer address to X-Forwarded-For, so the RIGHTMOST entry is the one
 * the proxy saw; everything left of it is client-supplied and spoofable. Without
 * a trusted proxy, the socket peer.
 */
export function clientIp(req: IncomingMessage, trustProxy: boolean): string {
  if (trustProxy) {
    const raw = req.headers['x-forwarded-for'];
    const xff = Array.isArray(raw) ? raw.join(',') : raw;
    if (typeof xff === 'string') {
      const parts = xff.split(',').map((p) => p.trim()).filter((p) => p.length > 0);
      const last = parts[parts.length - 1];
      if (last) return last;
    }
  }
  return req.socket?.remoteAddress ?? 'unknown';
}

/** Per-window budgets for the password/email-code login surface. */
export const LOGIN_WINDOW_MS = 15 * 60 * 1000;
export const LOGIN_LIMITS = {
  /** POST /auth/password/verify: code guesses. */
  verifyPerIp: 30,
  /**
   * Per (account, source IP). Charged BEFORE the account-wide budget and
   * short-circuiting, so one source runs out here and cannot exhaust the
   * account-wide budget (no single-source lockout of the victim).
   */
  verifyPerAccountIp: 5,
  /** Account-wide: bounds distributed guessing. Tradeoff: ≥3 sources can still lock it (issue: DEFERRED). */
  verifyPerAccount: 15,
  /** POST /auth/password/login: password guesses. */
  loginPerIp: 30,
  loginPerAccountIp: 4,
  loginPerAccount: 10,
  /** Code issuance (register, or login falling back to verify-first). */
  issuePerIp: 20,
} as const;
