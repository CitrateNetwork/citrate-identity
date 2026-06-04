/**
 * Postgres-backed KYC claim store (TD-2).
 *
 * Discharges the Wave-2 debt-blocker TD-2: the KYC claim store was an in-memory
 * Map (data loss on restart; no sharing across instances). This backs the EXISTING
 * {@link KycStore} seam with a real database row — a drop-in swap, exactly as the
 * interface was designed for (see kyc.ts). It is selected by `initKycStoreFromEnv`
 * whenever `DATABASE_URL` is set.
 *
 * DATA-CONTROLLER BOUNDARY (ADR-2026-06-03, enforced here):
 * The table stores ONLY the claim record — status + dates + an opaque vendor_ref —
 * and has NO PII columns. The KYC vendor (CLEAR / Sumsub) remains the PII data
 * controller. The schema is closed: there is nowhere to put a name/SSN/document.
 * The `verified_at`/`expires_at` instants are stored as epoch-millisecond bigints
 * (the {@link KycClaim} ISO-8601 strings are converted at this boundary and back),
 * so the row is compact and the pure helpers `effectiveVerified`/`isExpired` stay
 * unchanged — they keep operating on the ISO strings of a reconstructed claim.
 *
 * All SQL is parameterized ($1, $2, …) — no string interpolation of caller input.
 *
 * SEAM: a single `pg.Pool` over `DATABASE_URL`. For multi-region / read-replica
 * topologies the pool config grows here; the interface does not change.
 */
import type { Pool, PoolClient, QueryResult } from 'pg';
import {
  type KycClaim,
  type KycStatus,
  type KycStore,
} from './kyc.js';

/**
 * The minimal `pg`-compatible surface this store needs. `pg.Pool` satisfies it,
 * and so does the Pool that `pg-mem` produces for offline tests — so the same
 * code runs against a real Postgres and against the in-process test database with
 * no branching.
 */
export interface PgLike {
  query(text: string, params?: unknown[]): Promise<QueryResult>;
  end?(): Promise<void>;
}

/** Normalize an address key so lookups are case-insensitive (mirrors kyc.ts). */
function key(address: string): string {
  return address.toLowerCase();
}

/** ISO-8601 string → epoch-ms bigint-as-number, or null when absent/unparseable. */
function isoToEpochMs(iso: string | undefined): number | null {
  if (!iso) return null;
  const ms = Date.parse(iso);
  return Number.isNaN(ms) ? null : ms;
}

/**
 * Epoch-ms (as returned by pg) → ISO-8601 string, or undefined when null. pg
 * returns `bigint` columns as strings by default; pg-mem returns them as numbers.
 * We accept both so the same row-mapper works in tests and in production.
 */
function epochMsToIso(value: unknown): string | undefined {
  if (value === null || value === undefined) return undefined;
  const ms = typeof value === 'string' ? Number(value) : (value as number);
  if (!Number.isFinite(ms)) return undefined;
  return new Date(ms).toISOString();
}

const VALID_STATUSES: readonly KycStatus[] = ['verified', 'pending', 'revoked'];
function asKycStatus(v: unknown): KycStatus {
  if (typeof v === 'string' && (VALID_STATUSES as readonly string[]).includes(v)) {
    return v as KycStatus;
  }
  // A row whose status is not one of the known values is data corruption, not an
  // expected branch — fail loudly rather than silently asserting a wrong status.
  throw new Error(`kyc_claims row has invalid status: ${String(v)}`);
}

/** The columns we select, in order, mapped back to a {@link KycClaim}. */
interface ClaimRow {
  status: unknown;
  verified_at: unknown;
  expires_at: unknown;
  vendor_ref: unknown;
}

function rowToClaim(row: ClaimRow): KycClaim {
  return {
    status: asKycStatus(row.status),
    verified_at: epochMsToIso(row.verified_at),
    expires_at: epochMsToIso(row.expires_at),
    vendor_ref: String(row.vendor_ref),
  };
}

/**
 * The idempotent schema. `kyc_claims` holds ONE row per wallet (address PRIMARY
 * KEY). NO PII columns — only status, the two lifecycle instants (epoch-ms
 * bigints), the opaque vendor_ref, and an updated_at bookkeeping stamp.
 */
const CREATE_TABLE_SQL = `
CREATE TABLE IF NOT EXISTS kyc_claims (
  address     text   PRIMARY KEY,
  status      text   NOT NULL,
  verified_at bigint,
  expires_at  bigint,
  vendor_ref  text   NOT NULL,
  updated_at  bigint NOT NULL
)`;

/**
 * Whether the table already exists. We gate the CREATE on this so `ensureSchema`
 * is idempotent on BOTH real Postgres and pg-mem: real PG handles
 * `CREATE TABLE IF NOT EXISTS` repeatedly fine, but pg-mem's planner does not
 * fully consume the AST of a second IF-NOT-EXISTS create once the table is
 * present (a known pg-mem limitation), so we simply skip the create when it
 * already exists. We probe `information_schema.tables` — standard, portable, and
 * injection-free (no caller input).
 */
const TABLE_EXISTS_SQL = `SELECT 1 AS present FROM information_schema.tables WHERE table_name = 'kyc_claims' LIMIT 1`;

export class PgKycStore implements KycStore {
  /**
   * @param pool a `pg.Pool` (or pg-mem equivalent). The store does NOT own the
   *   pool's lifecycle beyond {@link close}; callers that share a pool should not
   *   call close.
   */
  constructor(private readonly pool: PgLike) {}

  /**
   * Connect to `databaseUrl`, ensure the schema, and return a ready store. This
   * is the production entry point used by `initKycStoreFromEnv`. The `pg` driver
   * is imported here (not at module load) so it is only required when a database
   * is actually configured.
   */
  static async connect(databaseUrl: string): Promise<PgKycStore> {
    const { Pool } = await import('pg');
    const pool: Pool = new Pool({ connectionString: databaseUrl });
    const store = new PgKycStore(pool);
    await store.ensureSchema();
    return store;
  }

  /** CREATE TABLE IF NOT EXISTS — safe to run on every boot (idempotent). */
  async ensureSchema(): Promise<void> {
    const probe = await this.pool.query(TABLE_EXISTS_SQL);
    const exists = probe.rows.length > 0;
    if (!exists) {
      await this.pool.query(CREATE_TABLE_SQL);
    }
  }

  async get(address: string): Promise<KycClaim | undefined> {
    const res = await this.pool.query(
      'SELECT status, verified_at, expires_at, vendor_ref FROM kyc_claims WHERE address = $1',
      [key(address)],
    );
    const row = res.rows[0] as ClaimRow | undefined;
    if (!row) return undefined;
    return rowToClaim(row);
  }

  async set(address: string, claim: KycClaim): Promise<void> {
    await this.pool.query(
      `INSERT INTO kyc_claims (address, status, verified_at, expires_at, vendor_ref, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT (address) DO UPDATE SET
         status      = EXCLUDED.status,
         verified_at = EXCLUDED.verified_at,
         expires_at  = EXCLUDED.expires_at,
         vendor_ref  = EXCLUDED.vendor_ref,
         updated_at  = EXCLUDED.updated_at`,
      [
        key(address),
        claim.status,
        isoToEpochMs(claim.verified_at),
        isoToEpochMs(claim.expires_at),
        claim.vendor_ref,
        Date.now(),
      ],
    );
  }

  /**
   * Mark a wallet revoked. Mirrors {@link InMemoryKycStore.revoke} semantics
   * EXACTLY: preserve the existing vendor_ref/verified_at (so the revoked record
   * stays reconcilable with the vendor), force status='revoked', and CLEAR the
   * expiry (the record is dead now). Idempotent — revoking an unknown wallet
   * still leaves a `revoked` row with vendor_ref='revoked'.
   *
   * Done in a single statement that reads the existing row (if any) via a LEFT
   * JOIN-free correlated upsert: we compute the carry-over values in SQL so there
   * is no read-modify-write race between two revokes.
   */
  async revoke(address: string): Promise<void> {
    await this.pool.query(
      `INSERT INTO kyc_claims (address, status, verified_at, expires_at, vendor_ref, updated_at)
       VALUES ($1, 'revoked', NULL, NULL, 'revoked', $2)
       ON CONFLICT (address) DO UPDATE SET
         status      = 'revoked',
         expires_at  = NULL,
         vendor_ref  = COALESCE(kyc_claims.vendor_ref, 'revoked'),
         updated_at  = EXCLUDED.updated_at`,
      [key(address), Date.now()],
    );
  }

  /** Close the underlying pool (process shutdown / tests). */
  async close(): Promise<void> {
    await this.pool.end?.();
  }
}

// Re-export the pg types we touch so a consumer can type a custom pool without a
// direct `pg` import. (Unused at runtime; kept for the public surface.)
export type { Pool, PoolClient };
