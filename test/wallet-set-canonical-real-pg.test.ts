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

const ALT = '0x' + 'ab'.repeat(20);

describe.skipIf(!URL)('setCanonical on real Postgres', () => {
  // `pg` is a runtime dependency; imported lazily so the suite costs nothing when skipped.
  let pool: { query: PgLike['query']; end(): Promise<void> };
  let reg: PgWalletRegistry;

  const canonicalRows = async () =>
    (await pool.query('SELECT address FROM linked_wallets WHERE sub = $1 AND is_canonical', [SUB])).rows.map(
      (r) => String(r.address),
    );
  const primaryWallet = async () =>
    String((await pool.query('SELECT primary_wallet FROM users WHERE id = $1::uuid', [SUB])).rows[0]!.primary_wallet);

  beforeAll(async () => {
    const { Pool } = await import('pg');
    pool = new Pool({ connectionString: URL, max: 12 }) as unknown as typeof pool;
    await pool.query('DROP TABLE IF EXISTS linked_wallets');
    await pool.query('DROP TABLE IF EXISTS users');
    // The slice of the user store's table that setCanonical mirrors into.
    await pool.query(
      'CREATE TABLE users (id UUID PRIMARY KEY, primary_wallet TEXT, updated_at TIMESTAMPTZ NOT NULL DEFAULT now())',
    );
    await pool.query('INSERT INTO users (id) VALUES ($1)', [SUB]);
    // The deployed-before-the-fix shape: plain partial unique index.
    await pool.query(`CREATE TABLE linked_wallets (
      seq BIGSERIAL PRIMARY KEY, sub TEXT NOT NULL, address TEXT NOT NULL,
      linked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      is_canonical BOOLEAN NOT NULL DEFAULT FALSE,
      CONSTRAINT linked_wallets_address_key UNIQUE (address))`);
    await pool.query(
      'CREATE UNIQUE INDEX linked_wallets_one_canonical_per_sub ON linked_wallets (sub) WHERE is_canonical',
    );
    reg = new PgWalletRegistry(pool);
    await reg.ensureSchema();
    await reg.ensureSchema(); // idempotent
  });

  afterAll(async () => {
    await pool.query('DROP TABLE IF EXISTS linked_wallets');
    await pool.query('DROP TABLE IF EXISTS users');
    await pool.end();
  });

  it('switches canonical in the order that used to fail (red on the old schema)', async () => {
    await reg.link(SUB, OLD);
    await reg.link(SUB, NEW);
    // Promote OLD after NEW exists, so OLD's live row version sits later in the heap.
    await reg.setCanonical(SUB, OLD);
    expect(await reg.canonicalFor(SUB)).toBe(OLD);

    // The production failure: this threw "duplicate key value" under the unique index.
    await reg.setCanonical(SUB, NEW);
    expect(await reg.canonicalFor(SUB)).toBe(NEW);
    expect(await canonicalRows()).toEqual([NEW]);

    // The one-canonical rule still holds at statement end.
    await expect(
      pool.query('UPDATE linked_wallets SET is_canonical = TRUE WHERE sub = $1', [SUB]),
    ).rejects.toThrow(/linked_wallets_one_canonical_per_sub/);
  });

  it('moves users.primary_wallet in the SAME statement: if that write fails, the switch rolls back', async () => {
    await reg.setCanonical(SUB, OLD);
    expect(await primaryWallet()).toBe(OLD);

    // Make the users write fail, then attempt a switch.
    await pool.query(`CREATE FUNCTION refuse() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN RAISE EXCEPTION 'users write refused'; END $$`);
    await pool.query('CREATE TRIGGER refuse BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION refuse()');
    await expect(reg.setCanonical(SUB, NEW)).rejects.toThrow(/users write refused/);
    await pool.query('DROP TRIGGER refuse ON users');
    await pool.query('DROP FUNCTION refuse()');

    // Neither half landed: the claim and the registry still agree on OLD.
    expect(await canonicalRows()).toEqual([OLD]);
    expect(await primaryWallet()).toBe(OLD);

    await reg.setCanonical(SUB, NEW);
    expect(await canonicalRows()).toEqual([NEW]);
    expect(await primaryWallet()).toBe(NEW);
  });

  it('concurrent switches never leave zero or two canonicals, and the claim matches the winner', async () => {
    await reg.link(SUB, ALT);
    const targets = [OLD, NEW, ALT];
    const results = await Promise.allSettled(
      Array.from({ length: 40 }, (_, i) => reg.setCanonical(SUB, targets[i % targets.length]!)),
    );
    expect(results.filter((r) => r.status === 'rejected')).toEqual([]);

    const rows = await canonicalRows();
    expect(rows).toHaveLength(1);
    expect(targets).toContain(rows[0]);
    expect(await primaryWallet()).toBe(rows[0]);
    expect(await reg.canonicalFor(SUB)).toBe(rows[0]);
  });
});
