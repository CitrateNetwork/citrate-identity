import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { newDb, type IMemoryDb } from 'pg-mem';
import { PgKycStore } from '../src/kyc-pg.js';
import { effectiveVerified, type KycClaim } from '../src/kyc.js';

/**
 * TD-2 — KYC claim store backed by a database (PgKycStore).
 *
 * Runs the REAL PgKycStore against a `pg-mem` in-process Postgres so the SQL
 * (CREATE TABLE, parameterized upsert/select, revoke) executes fully offline — no
 * external database, no network. pg-mem exposes a `pg`-compatible Pool via
 * `createPg()`, which is exactly the surface PgKycStore consumes.
 *
 *   gtm-spine/TECH_DEBT.md → TD-2
 *   adrs/ADR-2026-06-03-kyc-flow.md (no-PII claim-record boundary)
 */

/** A wallet address (mixed-case to exercise case-insensitive keying). */
const ADDR = '0xAbCdEf0123456789AbCdEf0123456789AbCdEf01';

/** Build a fresh pg-mem database + a Pool over it. */
function freshDb(): { db: IMemoryDb; makePool: () => InstanceType<ReturnType<IMemoryDb['adapters']['createPg']>['Pool']> } {
  const db = newDb();
  const pg = db.adapters.createPg();
  return { db, makePool: () => new pg.Pool() };
}

describe('PgKycStore against pg-mem (TD-2)', () => {
  let ctx: ReturnType<typeof freshDb>;

  beforeEach(() => {
    ctx = freshDb();
  });

  afterEach(async () => {
    // Pools are created per-test on a per-test db; nothing global to reset.
  });

  it('ensureSchema is idempotent (safe to run twice)', async () => {
    const store = new PgKycStore(ctx.makePool());
    await store.ensureSchema();
    // Running it again must not throw (CREATE TABLE IF NOT EXISTS).
    await expect(store.ensureSchema()).resolves.toBeUndefined();
  });

  it('set → get round-trips the exact KycClaim semantics', async () => {
    const store = new PgKycStore(ctx.makePool());
    await store.ensureSchema();

    const verified_at = '2026-06-04T00:00:00.000Z';
    const expires_at = '2027-06-04T00:00:00.000Z';
    const claim: KycClaim = {
      status: 'verified',
      verified_at,
      expires_at,
      vendor_ref: 'clear:applicant-abc123',
    };
    await store.set(ADDR, claim);

    const got = await store.get(ADDR);
    expect(got).toEqual(claim);
    // The pure helper still operates on the reconstructed ISO strings.
    expect(effectiveVerified(got, new Date('2026-12-01T00:00:00.000Z'))).toBe(true);
  });

  it('keys are case-insensitive (set mixed-case → get lower-case)', async () => {
    const store = new PgKycStore(ctx.makePool());
    await store.ensureSchema();
    await store.set(ADDR, { status: 'verified', vendor_ref: 'r' });
    const got = await store.get(ADDR.toLowerCase());
    expect(got?.status).toBe('verified');
  });

  it('a wallet that never did KYC returns undefined', async () => {
    const store = new PgKycStore(ctx.makePool());
    await store.ensureSchema();
    expect(await store.get(ADDR)).toBeUndefined();
  });

  it('set upserts (second set overwrites the row, not a duplicate)', async () => {
    const store = new PgKycStore(ctx.makePool());
    await store.ensureSchema();
    await store.set(ADDR, { status: 'pending', vendor_ref: 'r1' });
    await store.set(ADDR, {
      status: 'verified',
      verified_at: '2026-06-04T00:00:00.000Z',
      vendor_ref: 'r2',
    });
    const got = await store.get(ADDR);
    expect(got?.status).toBe('verified');
    expect(got?.vendor_ref).toBe('r2');
  });

  it('revoke → get reflects revoked, preserves vendor_ref/verified_at, clears expiry', async () => {
    const store = new PgKycStore(ctx.makePool());
    await store.ensureSchema();
    await store.set(ADDR, {
      status: 'verified',
      verified_at: '2026-01-01T00:00:00.000Z',
      expires_at: '2027-01-01T00:00:00.000Z',
      vendor_ref: 'clear:xyz',
    });

    await store.revoke(ADDR);

    const got = await store.get(ADDR);
    expect(got?.status).toBe('revoked');
    expect(got?.vendor_ref).toBe('clear:xyz');
    expect(got?.verified_at).toBe('2026-01-01T00:00:00.000Z');
    expect(got?.expires_at).toBeUndefined();
    expect(effectiveVerified(got)).toBe(false);
  });

  it('revoke is idempotent for an unknown wallet (leaves a revoked record)', async () => {
    const store = new PgKycStore(ctx.makePool());
    await store.ensureSchema();
    await store.revoke(ADDR);
    const got = await store.get(ADDR);
    expect(got?.status).toBe('revoked');
    expect(got?.vendor_ref).toBe('revoked');
    // Revoking again must not throw and keeps it revoked.
    await expect(store.revoke(ADDR)).resolves.toBeUndefined();
    expect((await store.get(ADDR))?.status).toBe('revoked');
  });

  it('an expired verified claim reports effectiveVerified=false', async () => {
    const store = new PgKycStore(ctx.makePool());
    await store.ensureSchema();
    await store.set(ADDR, {
      status: 'verified',
      verified_at: new Date(Date.now() - 400 * 24 * 60 * 60 * 1000).toISOString(),
      expires_at: new Date(Date.now() - 60_000).toISOString(),
      vendor_ref: 'clear:expired',
    });
    const got = await store.get(ADDR);
    expect(got?.status).toBe('verified'); // stored status is still verified
    expect(effectiveVerified(got)).toBe(false); // but it is past expiry
  });

  it('PERSISTS across a NEW store instance on the SAME db ("survives reconnect")', async () => {
    // First store writes a claim, then "disconnects" (we just drop the instance).
    const first = new PgKycStore(ctx.makePool());
    await first.ensureSchema();
    await first.set(ADDR, {
      status: 'verified',
      verified_at: '2026-06-04T00:00:00.000Z',
      expires_at: '2027-06-04T00:00:00.000Z',
      vendor_ref: 'clear:persist',
    });

    // A brand-new store instance over a fresh Pool on the SAME underlying db —
    // simulating a process restart / a second instance. The row must still be
    // there (this is the whole point of TD-2: survive restart + multi-instance).
    const second = new PgKycStore(ctx.makePool());
    await second.ensureSchema(); // idempotent; table already exists
    const got = await second.get(ADDR);
    expect(got).toEqual({
      status: 'verified',
      verified_at: '2026-06-04T00:00:00.000Z',
      expires_at: '2027-06-04T00:00:00.000Z',
      vendor_ref: 'clear:persist',
    });
  });

  it('the kyc_claims table has NO PII columns — only the claim-record columns', async () => {
    const store = new PgKycStore(ctx.makePool());
    await store.ensureSchema();

    // Introspect the actual columns pg-mem created from the DDL.
    const pool = ctx.makePool();
    const res = await pool.query(
      `SELECT column_name FROM information_schema.columns WHERE table_name = 'kyc_claims'`,
    );
    const columns = new Set(
      (res.rows as Array<{ column_name: string }>).map((r) => r.column_name),
    );
    // Exactly the claim-record columns — and nothing else.
    expect(columns).toEqual(
      new Set([
        'address',
        'status',
        'verified_at',
        'expires_at',
        'vendor_ref',
        'updated_at',
      ]),
    );
    // Belt-and-suspenders: none of the obvious PII column names exist.
    for (const pii of ['name', 'full_name', 'ssn', 'dob', 'document', 'document_image', 'email', 'address_line1']) {
      expect(columns.has(pii)).toBe(false);
    }
  });
});
