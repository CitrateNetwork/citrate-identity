/**
 * Shared Redis client wiring for the Citrate OIDC authority (HA / restart-safe).
 *
 * Production-grade `auth.citrate.ai` runs MULTIPLE instances behind a load
 * balancer, and any instance can be restarted at any time. Three pieces of
 * authority state must therefore NOT live in a single process's memory:
 *
 *   1. SIWE nonces        — a nonce issued by instance A must be consumable
 *                            exactly once across ALL instances (replay defence).
 *   2. Session-bus events  — a logout published on instance A must reach the SSE
 *                            subscribers attached to instance B (logout cascade).
 *   3. oidc-provider state — sessions, grants, tokens, interactions, codes must
 *                            survive a restart and be visible to every instance,
 *                            instead of panva's default in-memory adapter.
 *
 * All three are backed by ONE Redis connection (reused) when `REDIS_URL` is set.
 * This mirrors the `DATABASE_URL` → {@link PgKycStore} selection in kyc.ts: set
 * the env var and the persistent/HA path lights up; leave it unset in dev and the
 * existing in-memory behaviour is unchanged. {@link assertProductionConfig}
 * fail-closes production when `REDIS_URL` is missing, exactly like `DATABASE_URL`.
 *
 * `ioredis` is imported lazily (only when `REDIS_URL` is configured) so dev/test
 * paths that use the in-memory stores never pull the driver in — the same lazy
 * posture kyc.ts uses for `pg`.
 */
import type { Redis as IORedis } from 'ioredis';

/**
 * The narrow Redis surface the authority's stores/adapter consume. `ioredis`
 * (and the `ioredis-mock` used in offline tests) satisfy this, so the same code
 * runs against a real Redis and against the in-process mock with no branching.
 *
 * Only the commands actually used are declared — `set`/`get`/`getdel`/`del`/
 * `expireat`/`pexpire`/`smembers`/`sadd`/`exists` for the adapter + nonce store,
 * `publish`/`subscribe`/`on` + `duplicate` for pub/sub, `quit` for shutdown, and
 * `defineCommand` so we can register the atomic consume Lua script.
 */
export interface RedisLike {
  set(
    key: string,
    value: string,
    ...args: Array<string | number>
  ): Promise<unknown>;
  get(key: string): Promise<string | null>;
  getdel(key: string): Promise<string | null>;
  del(...keys: string[]): Promise<number>;
  exists(...keys: string[]): Promise<number>;
  expireat(key: string, timestampSeconds: number): Promise<number>;
  pexpire(key: string, milliseconds: number): Promise<number>;
  smembers(key: string): Promise<string[]>;
  sadd(key: string, ...members: string[]): Promise<number>;
  publish(channel: string, message: string): Promise<number>;
  subscribe(...channels: string[]): Promise<unknown>;
  on(event: string, listener: (...args: unknown[]) => void): unknown;
  duplicate(): RedisLike;
  quit(): Promise<unknown>;
  /** Register a named Lua script as a callable method (atomic operations). */
  defineCommand(
    name: string,
    definition: { numberOfKeys: number; lua: string },
  ): void;
}

/**
 * Create a single shared `ioredis` connection from a connection string. The
 * driver is imported here (not at module load) so it is only required when a
 * `REDIS_URL` is actually configured — dev/test that use the in-memory stores
 * never touch `ioredis`. Mirrors `PgKycStore.connect` / `initKycStoreFromEnv`.
 *
 * `maxRetriesPerRequest: null` + `enableReadyCheck` keep the publisher resilient
 * across brief Redis blips rather than failing fast and dropping a logout event.
 */
export async function createRedis(url: string): Promise<RedisLike> {
  const { Redis } = await import('ioredis');
  const client = new Redis(url, {
    // Don't bound retries on a single request — for an HA authority a transient
    // Redis hiccup should queue, not error the whole login/logout path.
    maxRetriesPerRequest: null,
    lazyConnect: false,
  });
  return client as unknown as RedisLike;
}

export type { IORedis };
