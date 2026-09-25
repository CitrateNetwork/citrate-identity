/**
 * Test Postgres: a REAL server when IDENTITY_TEST_PG_URL is set (the R2 lane runs
 * the concurrency proofs against a local Postgres 17), else pg-mem. Each call
 * returns an isolated pool; `reset(tables)` drops tables so reruns start clean.
 */
import { newDb } from 'pg-mem';
import pg from 'pg';

export interface TestPg {
  pool: { query(text: string, params?: unknown[]): Promise<{ rows: unknown[] }> };
  real: boolean;
  reset(tables: string[]): Promise<void>;
  close(): Promise<void>;
}

export const REAL_PG_URL = process.env.IDENTITY_TEST_PG_URL?.trim() || undefined;

export function testPg(): TestPg {
  if (REAL_PG_URL) {
    const pool = new pg.Pool({ connectionString: REAL_PG_URL, max: 20 });
    return {
      pool,
      real: true,
      async reset(tables) {
        for (const t of tables) await pool.query(`DROP TABLE IF EXISTS ${t}`);
      },
      close: () => pool.end(),
    };
  }
  // pg-mem cannot DROP + re-CREATE a table with a primary key (the pkey index
  // name survives), so "reset" swaps in a brand-new in-memory database.
  const fresh = () => new (newDb().adapters.createPg().Pool)();
  let inner = fresh();
  return {
    pool: { query: (text, params) => inner.query(text, params) },
    real: false,
    async reset() {
      inner = fresh();
    },
    close: async () => {},
  };
}
