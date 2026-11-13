/**
 * "Sign out of all sessions": find and end every browser session and grant of
 * an account.
 *
 * Neither panva's adapters nor Redis index Sessions or Grants by account, so
 * this module keeps that index itself. panva emits `session.saved` and
 * `grant.saved` with the saved model on every write; {@link trackAccountSessions}
 * records `<Model>:<id>` under the account. {@link endAllAccountSessions} then:
 *   1. stamps the account epoch (account-epoch.ts), which refuses anything the
 *      index cannot reach: records written before the index existed, or a
 *      write whose index update was lost;
 *   2. destroys every indexed Session record;
 *   3. revokes every indexed Grant: its access tokens, refresh tokens and
 *      unredeemed codes (revokeByGrantId), then the Grant record;
 *   4. publishes a `logout` on the session bus so RPs listening on
 *      /sessions/events drop their local session.
 *
 * Index entries for records that already expired are harmless: finding them
 * returns nothing. The index key expires after the longest record lifetime.
 *
 * Redis-backed in production (shared across instances), in-memory otherwise.
 */
import type Provider from 'oidc-provider';
import type { RedisLike } from '../redis.js';
import { EPOCH_TTL_SEC, getAccountEpochStore } from './account-epoch.js';
import { getSessionBus } from '../session-bus.js';

export type IndexedKind = 'Session' | 'Grant';

export interface AccountSessionIndex {
  add(accountId: string, kind: IndexedKind, id: string): Promise<void>;
  /** Every indexed record of the account, then forget them. */
  drain(accountId: string): Promise<Array<{ kind: IndexedKind; id: string }>>;
}

function parseMember(member: string): { kind: IndexedKind; id: string } | undefined {
  const i = member.indexOf(':');
  if (i === -1) return undefined;
  const kind = member.slice(0, i);
  const id = member.slice(i + 1);
  if ((kind !== 'Session' && kind !== 'Grant') || !id) return undefined;
  return { kind, id };
}

export class InMemoryAccountSessionIndex implements AccountSessionIndex {
  private readonly members = new Map<string, Set<string>>();
  async add(accountId: string, kind: IndexedKind, id: string): Promise<void> {
    let set = this.members.get(accountId);
    if (!set) {
      set = new Set();
      this.members.set(accountId, set);
    }
    set.add(`${kind}:${id}`);
  }
  async drain(accountId: string): Promise<Array<{ kind: IndexedKind; id: string }>> {
    const set = this.members.get(accountId) ?? new Set<string>();
    this.members.delete(accountId);
    return [...set].map(parseMember).filter((m): m is { kind: IndexedKind; id: string } => !!m);
  }
}

export class RedisAccountSessionIndex implements AccountSessionIndex {
  constructor(private readonly redis: RedisLike) {}
  private key(accountId: string): string {
    return `acct-sessions:${accountId}`;
  }
  async add(accountId: string, kind: IndexedKind, id: string): Promise<void> {
    const key = this.key(accountId);
    await this.redis.sadd(key, `${kind}:${id}`);
    await this.redis.pexpire(key, EPOCH_TTL_SEC * 1000);
  }
  async drain(accountId: string): Promise<Array<{ kind: IndexedKind; id: string }>> {
    const key = this.key(accountId);
    const members = await this.redis.smembers(key);
    await this.redis.del(key);
    return members.map(parseMember).filter((m): m is { kind: IndexedKind; id: string } => !!m);
  }
}

let index: AccountSessionIndex = new InMemoryAccountSessionIndex();

export function getAccountSessionIndex(): AccountSessionIndex {
  return index;
}

export function setAccountSessionIndex(i: AccountSessionIndex): void {
  index = i;
}

/** Install the shared Redis index when a client is wired (production), else keep the current one. */
export function initAccountSessionIndex(redis?: RedisLike): AccountSessionIndex {
  if (redis) setAccountSessionIndex(new RedisAccountSessionIndex(redis));
  return index;
}

interface SavedModel {
  accountId?: unknown;
  jti?: unknown;
}

/** Record every saved Session and Grant under its account. */
export function trackAccountSessions(provider: Provider): void {
  const record = (kind: IndexedKind) => (model: SavedModel) => {
    if (typeof model?.accountId !== 'string' || !model.accountId) return;
    if (typeof model.jti !== 'string' || !model.jti) return;
    getAccountSessionIndex()
      .add(model.accountId, kind, model.jti)
      .catch((err: unknown) => {
        // The account epoch still refuses this record on a sign-out-all.
        // eslint-disable-next-line no-console
        console.error(`[citrate-identity] account session index write failed: ${String(err)}`);
      });
  };
  provider.on('session.saved', record('Session'));
  provider.on('grant.saved', record('Grant'));
}

/** Revoke one grant: every token and code minted under it, then the grant record. */
export async function revokeGrant(provider: Provider, grantId: string): Promise<void> {
  await Promise.all([
    provider.AccessToken.revokeByGrantId(grantId),
    provider.RefreshToken.revokeByGrantId(grantId),
    provider.AuthorizationCode.revokeByGrantId(grantId),
    provider.DeviceCode.revokeByGrantId(grantId),
  ]);
  const grant = await provider.Grant.find(grantId);
  if (grant) await grant.destroy();
}

export interface EndAllResult {
  sessions: number;
  grants: number;
}

/** End every browser session and grant of `accountId` (see module doc). */
export async function endAllAccountSessions(
  provider: Provider,
  accountId: string,
  opts: { publish?: boolean } = {},
): Promise<EndAllResult> {
  await getAccountEpochStore().bump(accountId);
  const result: EndAllResult = { sessions: 0, grants: 0 };
  for (const { kind, id } of await getAccountSessionIndex().drain(accountId)) {
    if (kind === 'Session') {
      const session = await provider.Session.find(id);
      if (session && session.accountId === accountId) {
        for (const auth of Object.values(session.authorizations ?? {})) {
          if (auth?.grantId) {
            await revokeGrant(provider, auth.grantId);
            result.grants += 1;
          }
        }
        await session.destroy();
        result.sessions += 1;
      }
    } else {
      const grant = await provider.Grant.find(id);
      if (grant && grant.accountId === accountId) {
        await revokeGrant(provider, id);
        result.grants += 1;
      }
    }
  }
  if (opts.publish !== false) getSessionBus().publish(accountId, { type: 'logout', at: Date.now() });
  return result;
}
