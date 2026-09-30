/**
 * `setCanonical` against a REAL Postgres (opt-in: set TEST_DATABASE_URL).
 *
 * WHY THIS EXISTS
 *
 * The FakePg in wallet-registry-pg.test.ts no-ops DDL and flips every row at
 * once, so it cannot model how Postgres checks a plain unique index: row by
 * row as an UPDATE runs, not at the end of the statement. That gap let a
 * live bug ship. On 2026-09-30 (sub 5e79ed53) the in-app payout-wallet switch
 * failed three times with
 *   duplicate key value violates unique constraint "linked_wallets_one_canonical_per_sub"
 * because the single clear-and-set UPDATE reached the new row before it had
 * cleared the old canonical row.
 *
 * The trigger is heap order. The old canonical row was itself UPDATEd
 * (promoted) after the new row was inserted, so its live version sits later
 * in the table. This test replays exactly that sequence.
 *
 * Run: TEST_DATABASE_URL=postgres://postgres:x@127.0.0.1:55432/postgres npx vitest run test/wallet-set-canonical-real-pg.test.ts
 */

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { PgWalletRegistry, type PgLike } from '../src/wallet-registry-pg.js';

const URL = process.env.TEST_DATABASE_URL;
const SUB = '5e79ed53-89bc-463b-a6da-3c1c82c1362b';
const OLD = '0x' + '33'.repeat(20);
const NEW = '0x' + 'f1'.repeat(20);

describe.skipIf(!URL)('setCanonical on real Postgres', () => {
  // `pg` is a runtime dependency; imported lazily so the suite costs nothing when skipped.
  let pool: { query: PgLike['query']; end(): Promise<void> };

  beforeAll(async () => {
    const { Pool } = await import('pg');
    pool = new Pool({ connectionString: URL }) as unknown as typeof pool;
    await pool.query('DROP TABLE IF EXISTS linked_wallets');
  });

  afterAll(async () => {
    await pool.query('DROP TABLE IF EXISTS linked_wallets');
    await pool.end();
  });

  it('migrates a legacy partial unique index and then switches canonical in the order that used to fail', async () => {
    // The deployed-before-the-fix shape: plain partial unique index.
    await pool.query(`CREATE TABLE linked_wallets (
      seq BIGSERIAL PRIMARY KEY, sub TEXT NOT NULL, address TEXT NOT NULL,
      linked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      is_canonical BOOLEAN NOT NULL DEFAULT FALSE,
      CONSTRAINT linked_wallets_address_key UNIQUE (address))`);
    await pool.query(
      'CREATE UNIQUE INDEX linked_wallets_one_canonical_per_sub ON linked_wallets (sub) WHERE is_canonical',
    );

    const reg = new PgWalletRegistry(pool);
    await reg.ensureSchema();
    await reg.ensureSchema(); // idempotent

    await reg.link(SUB, OLD);
    await reg.link(SUB, NEW);
    // Promote OLD after NEW exists, so OLD's live row version sits later in the heap.
    await reg.setCanonical(SUB, OLD);
    expect(await reg.canonicalFor(SUB)).toBe(OLD);

    // The production failure: this threw "duplicate key value" under the unique index.
    await reg.setCanonical(SUB, NEW);
    expect(await reg.canonicalFor(SUB)).toBe(NEW);

    // The one-canonical rule still holds at statement end.
    await expect(
      pool.query('UPDATE linked_wallets SET is_canonical = TRUE WHERE sub = $1', [SUB]),
    ).rejects.toThrow(/linked_wallets_one_canonical_per_sub/);
  });
});
