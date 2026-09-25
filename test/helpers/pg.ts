/**
 * Test Postgres: a REAL server when IDENTITY_TEST_PG_URL is set (the R2 lane runs
 * the concurrency proofs against a local Postgres 17), else pg-mem. Each call
 * returns an isolated pool; `reset(tables)` drops tables so reruns start clean.
 */
import { newDb } from 'pg-mem';
import pg from 'pg';
import { randomBytes } from 'node:crypto';

export interface TestPg {
  pool: { query(text: string, params?: unknown[]): Promise<{ rows: unknown[] }> };
  real: boolean;
  reset(tables: string[]): Promise<void>;
  close(): Promise<void>;
}

export const REAL_PG_URL = process.env.IDENTITY_TEST_PG_URL?.trim() || undefined;

export function testPg(): TestPg {
  if (REAL_PG_URL) {
    // A private schema per instance: vitest runs files in parallel, and two files
    // dropping/creating the same table in `public` would race each other.
    const schema = `t_${process.pid}_${randomBytes(4).toString('hex')}`;
    const pool = new pg.Pool({ connectionString: REAL_PG_URL, max: 20, options: `-c search_path=${schema}` });
    let created = false;
    return {
      pool,
      real: true,
      async reset(tables) {
        if (!created) {
          await pool.query(`CREATE SCHEMA IF NOT EXISTS ${schema}`);
          created = true;
        }
        for (const t of tables) await pool.query(`DROP TABLE IF EXISTS ${t}`);
      },
      async close() {
        if (created) await pool.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
        await pool.end();
      },
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
