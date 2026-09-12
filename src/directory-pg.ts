/**
 * Postgres-backed self-published bindings directory (citrate-core#61).
 *
 * Mirrors `wallet-registry-pg.ts`: `CREATE TABLE IF NOT EXISTS` at boot (this repo
 * has no migrations directory), a small `PgLike` seam so tests stay off a real
 * driver, and `InMemoryDirectoryStore`'s behaviour reproduced exactly — including
 * the last-writer-by-`bound_at` upsert whose strict-advance rule is what stops a
 * replayed publish from un-revoking a tombstoned handle.
 *
 * One row per `(platform, handle_key)` (composite PK). A revoke sets `revoked` and
 * leaves the row (and its `bound_at`) in place, so a re-publish must present a
 * strictly newer `bound_at` to bring it back.
 */

import type {
  BindingRecord,
  DirectoryPlatform,
  DirectoryStore,
  LookupHit,
  SearchHit,
  UpsertOutcome,
} from './directory.js';
import { getAddress } from 'ethers';

/** The slice of `pg.Pool` this store needs (keeps tests off a real driver). */
export interface PgLike {
  query(text: string, values?: unknown[]): Promise<{ rows: Array<Record<string, unknown>> }>;
}

const TABLE_EXISTS_SQL = `
  SELECT 1 FROM information_schema.tables
   WHERE table_schema = 'public' AND table_name = 'directory_bindings'`;

const CREATE_TABLE_SQL = `
  CREATE TABLE IF NOT EXISTS directory_bindings (
    platform     TEXT        NOT NULL,
    handle_key   TEXT        NOT NULL,
    handle       TEXT        NOT NULL,
    address      TEXT        NOT NULL,
    display_name TEXT,
    bound_at     BIGINT      NOT NULL,
    revoked      BOOLEAN     NOT NULL DEFAULT FALSE,
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (platform, handle_key)
  )`;

/** Prefix search + live-lookup index. Postgres uses it for `handle_key LIKE 'p%'`. */
const CREATE_INDEX_SQL = `
  CREATE INDEX IF NOT EXISTS directory_bindings_live_idx
    ON directory_bindings (platform, handle_key) WHERE NOT revoked`;

export class PgDirectoryStore implements DirectoryStore {
  constructor(private readonly pool: PgLike) {}

  static async connect(databaseUrl: string): Promise<PgDirectoryStore> {
    const { Pool } = await import('pg');
    const pool = new Pool({ connectionString: databaseUrl });
    const store = new PgDirectoryStore(pool as unknown as PgLike);
    await store.ensureSchema();
    return store;
  }

  async ensureSchema(): Promise<void> {
    const probe = await this.pool.query(TABLE_EXISTS_SQL);
    if (probe.rows.length === 0) {
      await this.pool.query(CREATE_TABLE_SQL);
    }
    await this.pool.query(CREATE_INDEX_SQL);
  }

  async upsert(rec: BindingRecord): Promise<UpsertOutcome> {
    const address = rec.address.toLowerCase();
    const cur = await this.pool.query(
      'SELECT handle, address, display_name, bound_at, revoked FROM directory_bindings WHERE platform = $1 AND handle_key = $2',
      [rec.platform, rec.handleKey],
    );
    if (cur.rows.length === 0) {
      await this.pool.query(
        `INSERT INTO directory_bindings (platform, handle_key, handle, address, display_name, bound_at, revoked, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, FALSE, now())
         ON CONFLICT (platform, handle_key) DO NOTHING`,
        [rec.platform, rec.handleKey, rec.handle, address, rec.displayName ?? null, rec.boundAt],
      );
      // A concurrent insert could have beaten us to the PK; re-run through the
      // update path so the newer bound_at still wins deterministically.
      const race = await this.pool.query(
        'SELECT bound_at FROM directory_bindings WHERE platform = $1 AND handle_key = $2',
        [rec.platform, rec.handleKey],
      );
      if (race.rows.length === 0) return 'stored';
      if (Number(race.rows[0]!.bound_at) === rec.boundAt) return 'stored';
      // fall through to the comparison below using the raced row
      return this.applyAdvance(rec, address, {
        handle: String(race.rows[0]!.handle ?? rec.handle),
        address: String(race.rows[0]!.address ?? address),
        displayName: race.rows[0]!.display_name == null ? undefined : String(race.rows[0]!.display_name),
        boundAt: Number(race.rows[0]!.bound_at),
        revoked: Boolean(race.rows[0]!.revoked),
      });
    }
    const row = cur.rows[0]!;
    return this.applyAdvance(rec, address, {
      handle: String(row.handle),
      address: String(row.address),
      displayName: row.display_name == null ? undefined : String(row.display_name),
      boundAt: Number(row.bound_at),
      revoked: Boolean(row.revoked),
    });
  }

  /** Shared last-writer decision against an already-read current row. */
  private async applyAdvance(
    rec: BindingRecord,
    address: string,
    cur: { handle: string; address: string; displayName?: string; boundAt: number; revoked: boolean },
  ): Promise<UpsertOutcome> {
    if (rec.boundAt > cur.boundAt) {
      await this.pool.query(
        `UPDATE directory_bindings
            SET handle = $3, address = $4, display_name = $5, bound_at = $6, revoked = FALSE, updated_at = now()
          WHERE platform = $1 AND handle_key = $2`,
        [rec.platform, rec.handleKey, rec.handle, address, rec.displayName ?? null, rec.boundAt],
      );
      return 'stored';
    }
    const identical =
      !cur.revoked &&
      rec.boundAt === cur.boundAt &&
      cur.address === address &&
      cur.handle === rec.handle &&
      (cur.displayName ?? undefined) === (rec.displayName ?? undefined);
    return identical ? 'unchanged' : 'stale';
  }

  async revoke(platform: DirectoryPlatform, handleKey: string, address: string): Promise<boolean> {
    const res = await this.pool.query(
      `UPDATE directory_bindings
          SET revoked = TRUE, updated_at = now()
        WHERE platform = $1 AND handle_key = $2 AND address = $3 AND NOT revoked
        RETURNING platform`,
      [platform, handleKey, address.toLowerCase()],
    );
    return res.rows.length > 0;
  }

  async lookup(platform: DirectoryPlatform, handleKey: string): Promise<LookupHit | null> {
    const res = await this.pool.query(
      'SELECT address, bound_at FROM directory_bindings WHERE platform = $1 AND handle_key = $2 AND NOT revoked',
      [platform, handleKey],
    );
    if (res.rows.length === 0) return null;
    return { address: String(res.rows[0]!.address), boundAt: Number(res.rows[0]!.bound_at) };
  }

  async search(platform: DirectoryPlatform, prefix: string, limit: number): Promise<SearchHit[]> {
    // `prefix` is a normalized handle key ([a-z0-9_.]) — escape LIKE metacharacters
    // so `_` and `%` are matched literally, never as wildcards. Backslash is
    // Postgres's default LIKE escape character, so no explicit ESCAPE clause is
    // needed (and omitting it keeps the statement portable).
    const escaped = prefix.replace(/([\\%_])/g, '\\$1');
    const res = await this.pool.query(
      `SELECT handle, address, display_name FROM directory_bindings
        WHERE platform = $1 AND NOT revoked AND handle_key LIKE $2
        ORDER BY handle_key ASC
        LIMIT $3`,
      [platform, `${escaped}%`, limit],
    );
    return res.rows.map((r) => ({
      handle: String(r.handle),
      address: getAddress(String(r.address)),
      ...(r.display_name == null ? {} : { displayName: String(r.display_name) }),
    }));
  }
}

/**
 * Install the directory store for this environment: Postgres when `DATABASE_URL`
 * is set (production), otherwise leave the in-memory default in place (dev/test).
 * `assertProductionConfig` already refuses to boot in production without
 * `DATABASE_URL`, so the in-memory fallback is genuinely dev-only.
 */
export async function initDirectoryStoreFromEnv(
  env: NodeJS.ProcessEnv,
  setStore: (s: DirectoryStore) => void,
): Promise<void> {
  const url = (env.DATABASE_URL ?? '').trim();
  if (!url) {
    // eslint-disable-next-line no-console
    console.warn(
      '[directory] DATABASE_URL unset — using the IN-MEMORY directory store. ' +
        'Self-published bindings will NOT survive a restart.',
    );
    return;
  }
  setStore(await PgDirectoryStore.connect(url));
}
