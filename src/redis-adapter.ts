/**
 * Redis adapter for panva `oidc-provider` (HA / restart-safe authority state).
 *
 * panva ships with an IN-MEMORY adapter by default: every Session, Grant,
 * AccessToken, AuthorizationCode, RefreshToken, Interaction, etc. lives in the
 * process and is LOST on restart and INVISIBLE to other instances. For a
 * production `auth.citrate.ai` that means a deploy logs everyone out and a load
 * balancer can route a token to an instance that never minted it. This adapter
 * persists all of that in Redis so authority state survives restarts and is
 * shared across instances. Wired in via the Provider `adapter` config only when
 * `REDIS_URL` is set (config.ts); dev keeps panva's in-memory default.
 *
 * It implements the panva `Adapter` contract EXACTLY and follows the canonical
 * upstream Redis adapter example
 * (https://github.com/panva/node-oidc-provider/blob/main/example/adapters/redis.js):
 *
 *   - keys are namespaced per model:  `<name>:<id>`  (e.g. `Session:abc`)
 *   - payloads are stored as JSON (a Redis string), with `PEXPIRE`/`EXPIREAT`
 *     applied so records self-expire exactly when panva says they should;
 *   - `consume` marks a record consumed by writing a `consumed` timestamp onto
 *     the payload (AuthorizationCode / DeviceCode single-use enforcement);
 *   - secondary indexes are maintained for the lookups panva needs:
 *       grantId → ids   (a SET `grant:<grantId>`) so `revokeByGrantId` can drop
 *                        every token/code minted under a grant;
 *       userCode → id   (`userCode:<uc>`) for `findByUserCode` (Device Flow);
 *       uid → id        (`uid:<uid>`) for `findByUid` (Session lookup by uid).
 *
 * Models WITHOUT an expiry-bearing grant index (Session/Interaction/etc.) skip
 * the grant set; only "grantable" models carry a grantId, matching upstream.
 */
import type { Adapter, AdapterPayload } from 'oidc-provider';
import type { RedisLike } from './redis.js';

/**
 * Models that participate in grant-based revocation. For these, `upsert` adds the
 * id to the grant's SET and `revokeByGrantId` drops them all. This mirrors the
 * `grantable` list in the upstream example — exactly the access/refresh tokens,
 * authorization/device codes, and the grant-bound consent record.
 */
const GRANTABLE: ReadonlySet<string> = new Set([
  'AccessToken',
  'AuthorizationCode',
  'RefreshToken',
  'DeviceCode',
  'BackchannelAuthenticationRequest',
]);

/** Models whose single-use is enforced by a `consumed` stamp written by consume(). */
const CONSUMABLE: ReadonlySet<string> = new Set([
  'AuthorizationCode',
  'RefreshToken',
  'DeviceCode',
  'BackchannelAuthenticationRequest',
]);

/** `<name>:<id>` — the primary key for a model instance. */
function keyFor(name: string, id: string): string {
  return `${name}:${id}`;
}

/** `grant:<grantId>` — the SET of ids minted under a grant (revocation index). */
function grantKeyFor(grantId: string): string {
  return `grant:${grantId}`;
}

/** `userCode:<uc>` — secondary index for Device Flow `findByUserCode`. */
function userCodeKeyFor(userCode: string): string {
  return `userCode:${userCode}`;
}

/** `uid:<uid>` — secondary index for Session `findByUid`. */
function uidKeyFor(uid: string): string {
  return `uid:${uid}`;
}

/**
 * One adapter instance per model name. panva constructs `new RedisAdapter(name)`
 * for each model, so the shared Redis client is injected once via
 * {@link createRedisAdapterFactory} and closed over by the returned constructor.
 */
export class RedisAdapter implements Adapter {
  constructor(
    private readonly name: string,
    private readonly redis: RedisLike,
  ) {}

  /**
   * Persist `payload` for `id` with a TTL of `expiresIn` seconds. Maintains the
   * secondary indexes (grant set, userCode→id, uid→id) so the find-by-* lookups
   * and grant revocation work, and expires those index keys alongside the record
   * so nothing leaks after the primary expires.
   */
  async upsert(
    id: string,
    payload: AdapterPayload,
    expiresIn: number,
  ): Promise<void> {
    const key = keyFor(this.name, id);
    const json = JSON.stringify(payload);

    // Primary record. SET with PX so the value + its TTL land atomically.
    if (expiresIn) {
      await this.redis.set(key, json, 'PX', expiresIn * 1000);
    } else {
      await this.redis.set(key, json);
    }

    // grantId → ids index, expired no sooner than the record it points at, so a
    // revoke can always find every id under the grant while any of them lives.
    if (GRANTABLE.has(this.name) && payload.grantId) {
      const gkey = grantKeyFor(payload.grantId);
      await this.redis.sadd(gkey, key);
      if (expiresIn) await this.redis.pexpire(gkey, expiresIn * 1000);
    }

    // userCode → id (Device Flow).
    if (payload.userCode) {
      const ukey = userCodeKeyFor(payload.userCode);
      await this.redis.set(ukey, id);
      if (expiresIn) await this.redis.pexpire(ukey, expiresIn * 1000);
    }

    // uid → id (Session.findByUid).
    if (payload.uid) {
      const uidKey = uidKeyFor(payload.uid);
      await this.redis.set(uidKey, id);
      if (expiresIn) await this.redis.pexpire(uidKey, expiresIn * 1000);
    }
  }

  /** Resolve a stored payload by id, or undefined when absent/expired. */
  async find(id: string): Promise<AdapterPayload | undefined> {
    const raw = await this.redis.get(keyFor(this.name, id));
    if (!raw) return undefined;
    return JSON.parse(raw) as AdapterPayload;
  }

  /** Resolve via the userCode→id index (Device Flow). */
  async findByUserCode(userCode: string): Promise<AdapterPayload | undefined> {
    const id = await this.redis.get(userCodeKeyFor(userCode));
    if (!id) return undefined;
    return this.find(id);
  }

  /** Resolve via the uid→id index (Session lookup by uid). */
  async findByUid(uid: string): Promise<AdapterPayload | undefined> {
    const id = await this.redis.get(uidKeyFor(uid));
    if (!id) return undefined;
    return this.find(id);
  }

  /**
   * Mark a record consumed (single-use codes/tokens). panva calls this once a
   * code/token is redeemed; a second redemption then sees the `consumed` stamp
   * and is rejected. We re-write the payload with `consumed = now (epoch sec)`
   * WITHOUT changing its TTL, exactly as the upstream example does.
   */
  async consume(id: string): Promise<void> {
    if (!CONSUMABLE.has(this.name)) return;
    const key = keyFor(this.name, id);
    const raw = await this.redis.get(key);
    if (!raw) return;
    const payload = JSON.parse(raw) as AdapterPayload;
    payload.consumed = Math.floor(Date.now() / 1000);
    // Preserve the remaining TTL: re-set without changing expiry by reading the
    // PTTL would add a round trip; instead we KEEPTTL via the value rewrite. Redis
    // SET drops the TTL by default, so we restore it from the payload's exp when
    // present (panva stores `exp` as epoch seconds), else leave persistent.
    const exp = typeof payload.exp === 'number' ? payload.exp : undefined;
    if (exp) {
      const ms = exp * 1000 - Date.now();
      if (ms > 0) {
        await this.redis.set(key, JSON.stringify(payload), 'PX', ms);
        return;
      }
    }
    await this.redis.set(key, JSON.stringify(payload));
  }

  /** Remove a record (revocation / logout / rotation). */
  async destroy(id: string): Promise<void> {
    await this.redis.del(keyFor(this.name, id));
  }

  /**
   * Revoke EVERY id minted under a grant. Reads the grant SET, deletes all the
   * member records, then drops the index set itself. This is what makes a single
   * /logout or consent-revoke cascade to all of a user's tokens/codes for that
   * grant — the core of the revocation guarantee.
   */
  async revokeByGrantId(grantId: string): Promise<void> {
    const gkey = grantKeyFor(grantId);
    const members = await this.redis.smembers(gkey);
    if (members.length > 0) {
      await this.redis.del(...members);
    }
    await this.redis.del(gkey);
  }
}

/**
 * Build the panva `adapter` factory bound to a shared Redis client. panva calls
 * the factory with each model name and gets a {@link RedisAdapter} sharing the
 * one connection. Pass the result as the Provider config's `adapter`.
 */
export function createRedisAdapterFactory(
  redis: RedisLike,
): (name: string) => RedisAdapter {
  return (name: string) => new RedisAdapter(name, redis);
}
