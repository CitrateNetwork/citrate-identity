/**
 * Per-account "credentials valid from" epoch (PBA-L3a-008).
 *
 * Neither the panva adapter nor Redis indexes grants/sessions by account, so an
 * account-wide revocation ("log out everywhere", or a password reset) is done by
 * stamping the account with the second it happened. Anything authenticated
 * BEFORE that second is refused:
 *   - refresh-token grants and /userinfo, via `findAccount` (panva passes the
 *     token; its initial issued-at `iiat`, or `iat`, is compared);
 *   - browser sessions, via {@link mountSessionEpochGuard}, which destroys a
 *     `_session` whose `loginTs` predates the epoch before panva reads it.
 *
 * Second granularity matches panva's `iat` / `loginTs`. A session or token from
 * the SAME second as the bump survives (the reset's own new session is created
 * in that second); earlier ones do not.
 *
 * Redis-backed in production (shared across instances; prod requires REDIS_URL),
 * in-memory otherwise. Keys expire after the longest credential lifetime.
 */
import type Provider from 'oidc-provider';
import type { RedisLike } from '../redis.js';

/** Longest-lived credential the epoch must outlive (refresh tokens: 14 days) + margin. */
export const EPOCH_TTL_SEC = 30 * 24 * 60 * 60;

export interface AccountEpochStore {
  /** Unix seconds from which credentials are valid, or undefined. */
  get(accountId: string): Promise<number | undefined>;
  /** Stamp the account: everything authenticated before `atSec` is revoked. */
  bump(accountId: string, atSec?: number): Promise<number>;
}

const nowSec = (): number => Math.floor(Date.now() / 1000);

export class InMemoryAccountEpochStore implements AccountEpochStore {
  private readonly epochs = new Map<string, number>();
  async get(accountId: string): Promise<number | undefined> {
    return this.epochs.get(accountId);
  }
  async bump(accountId: string, atSec: number = nowSec()): Promise<number> {
    const prev = this.epochs.get(accountId) ?? 0;
    const next = Math.max(prev, atSec);
    this.epochs.set(accountId, next);
    return next;
  }
}

export class RedisAccountEpochStore implements AccountEpochStore {
  constructor(private readonly redis: RedisLike) {}
  private key(accountId: string): string {
    return `acct-epoch:${accountId}`;
  }
  async get(accountId: string): Promise<number | undefined> {
    const v = await this.redis.get(this.key(accountId));
    const n = v === null ? NaN : Number(v);
    return Number.isFinite(n) ? n : undefined;
  }
  async bump(accountId: string, atSec: number = nowSec()): Promise<number> {
    const prev = (await this.get(accountId)) ?? 0;
    const next = Math.max(prev, atSec);
    await this.redis.set(this.key(accountId), String(next), 'EX', EPOCH_TTL_SEC);
    return next;
  }
}

let store: AccountEpochStore = new InMemoryAccountEpochStore();

export function getAccountEpochStore(): AccountEpochStore {
  return store;
}

export function setAccountEpochStore(s: AccountEpochStore): void {
  store = s;
}

/** Install the shared Redis store when a client is wired (production), else keep the current one. */
export function initAccountEpochStore(redis?: RedisLike): AccountEpochStore {
  if (redis) setAccountEpochStore(new RedisAccountEpochStore(redis));
  return store;
}

/** True when a credential authenticated at `authSec` predates the account epoch. */
export async function isRevokedByEpoch(accountId: string, authSec: number | undefined): Promise<boolean> {
  const epoch = await store.get(accountId);
  if (epoch === undefined) return false;
  if (authSec === undefined || !Number.isFinite(authSec)) return true;
  return authSec < epoch;
}

/** The authentication second a panva token carries (`iiat` survives refresh rotation). */
export function tokenAuthSec(token: { iiat?: unknown; iat?: unknown } | undefined): number | undefined {
  if (!token) return undefined;
  const v = typeof token.iiat === 'number' ? token.iiat : token.iat;
  return typeof v === 'number' ? v : undefined;
}

/**
 * Destroy a browser session that predates its account's epoch, BEFORE panva
 * loads it, so /auth, /session/end and the session-authorised custom routes all
 * see an anonymous browser and require a fresh sign-in.
 */
export function mountSessionEpochGuard(provider: Provider): void {
  provider.use(async (ctx, next) => {
    const cookie = ctx.req.headers.cookie;
    if (typeof cookie === 'string' && /(?:^|;\s*)_session=/.test(cookie)) {
      try {
        const session = (await provider.Session.get(ctx)) as {
          accountId?: string;
          loginTs?: number;
          destroy(): Promise<void>;
        };
        if (session.accountId && (await isRevokedByEpoch(session.accountId, session.loginTs))) {
          await session.destroy();
        }
      } catch {
        // A session lookup failure leaves panva to handle the cookie as usual.
      }
    }
    return next();
  });
}
