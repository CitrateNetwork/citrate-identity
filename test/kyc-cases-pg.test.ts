import { describe, expect, it, beforeEach } from 'vitest';
import { newDb, type IMemoryDb } from 'pg-mem';
import { randomBytes } from 'node:crypto';
import { KycCaseStore } from '../src/kyc-cases-pg.js';
import { newDek, openField, sealField, unwrapDek, wrapDek } from '../src/kyc-crypto.js';

/**
 * VERI-S1-WP2/WP4 — encrypted case store against pg-mem (offline, no network).
 * Exercises the real SQL and the three-tier retention/destruction semantics.
 */
function freshDb(): { db: IMemoryDb; makePool: () => InstanceType<ReturnType<IMemoryDb['adapters']['createPg']>['Pool']> } {
  const db = newDb();
  const pg = db.adapters.createPg();
  return { db, makePool: () => new pg.Pool() };
}

describe('KycCaseStore (VERI-S1)', () => {
  let ctx: ReturnType<typeof freshDb>;
  const master = randomBytes(32);

  beforeEach(() => {
    ctx = freshDb();
  });

  async function store(): Promise<KycCaseStore> {
    const s = new KycCaseStore(ctx.makePool());
    await s.ensureSchema();
    return s;
  }

  it('ensureSchema is idempotent', async () => {
    const s = await store();
    await expect(s.ensureSchema()).resolves.toBeUndefined();
  });

  it('createCase → getCase round-trips, latest-for-user works', async () => {
    const s = await store();
    const dek = newDek();
    const c = await s.createCase('sub-123', wrapDek(dek, master));
    expect(c.status).toBe('created');
    expect(c.legalHold).toBe(false);
    const got = await s.getCase(c.caseId);
    expect(got?.caseId).toBe(c.caseId);
    expect(await (await store()).getLatestCaseForUser('nobody')).toBeUndefined();
    expect((await s.getLatestCaseForUser('sub-123'))?.caseId).toBe(c.caseId);
  });

  it('END-TO-END server-blind: identity is recoverable only via master → DEK', async () => {
    const s = await store();
    const dek = newDek();
    const c = await s.createCase('sub-x', wrapDek(dek, master));
    const identity = JSON.stringify({ name: 'Ada Lovelace', dob: '1815-12-10', doc: 'A1234567' });
    await s.setIdentityCiphertext(c.caseId, sealField(identity, dek));

    const row = await s.getCase(c.caseId);
    // The stored row carries NO plaintext — only ciphertext + wrapped DEK.
    expect(row?.identityCt).toBeDefined();
    expect(row?.identityCt).not.toContain('Ada');
    expect(row?.wrappedDek).not.toContain('Ada');

    // Recovery requires the master (to unwrap the DEK) then the DEK (to open).
    const recoveredDek = unwrapDek(row!.wrappedDek, master);
    expect(openField(row!.identityCt!, recoveredDek)).toBe(identity);
    // Wrong master → cannot even unwrap.
    expect(() => unwrapDek(row!.wrappedDek, randomBytes(32))).toThrow();
  });

  it('setDecision drives status + lifecycle fields', async () => {
    const s = await store();
    const c = await s.createCase('sub-d', wrapDek(newDek(), master));
    const verifiedAt = Date.now();
    await s.setDecision(c.caseId, {
      decision: 'verified',
      screeningResult: 'clear',
      verifiedAt,
      expiresAt: verifiedAt + 365 * 864e5,
      retentionUntil: verifiedAt + 365 * 864e5,
    });
    const got = await s.getCase(c.caseId);
    expect(got?.status).toBe('verified');
    expect(got?.decision).toBe('verified');
    expect(got?.screeningResult).toBe('clear');
    expect(got?.verifiedAt).toBe(verifiedAt);
  });

  it('destroyDueBiometrics wipes only due Tier-2 evidence, idempotently', async () => {
    const s = await store();
    const dek = newDek();
    const c = await s.createCase('sub-b', wrapDek(dek, master));
    const now = Date.now();
    // Tier-2 biometric, due for destruction now:
    await s.addEvidence({ caseId: c.caseId, kind: 'liveness', tier: 2, ciphertext: sealField('face', dek), destroyAfter: now - 1 });
    // Tier-2 not yet due:
    await s.addEvidence({ caseId: c.caseId, kind: 'selfie', tier: 2, ciphertext: sealField('face2', dek), destroyAfter: now + 1e6 });
    // Tier-3 convenience (never auto-destroyed by this job):
    await s.addEvidence({ caseId: c.caseId, kind: 'other', tier: 3, ciphertext: sealField('meta', dek) });

    const destroyed = await s.destroyDueBiometrics(now);
    expect(destroyed).toBe(1);
    const ev = await s.listEvidence(c.caseId);
    const due = ev.find((e) => e.kind === 'liveness');
    expect(due?.ciphertext).toBeUndefined(); // wiped
    expect(due?.destroyedAt).toBeDefined();
    expect(ev.find((e) => e.kind === 'selfie')?.ciphertext).toBeDefined(); // not yet due
    expect(ev.find((e) => e.kind === 'other')?.ciphertext).toBeDefined(); // tier-3 untouched
    // Idempotent: running again destroys nothing new.
    expect(await s.destroyDueBiometrics(now)).toBe(0);
  });

  it('deleteCase hard-deletes without a legal hold', async () => {
    const s = await store();
    const c = await s.createCase('sub-del', wrapDek(newDek(), master));
    await s.addEvidence({ caseId: c.caseId, kind: 'document', tier: 3, ciphertext: 'x' });
    expect(await s.deleteCase(c.caseId)).toBe('deleted');
    expect(await s.getCase(c.caseId)).toBeUndefined();
    expect(await s.listEvidence(c.caseId)).toHaveLength(0);
    expect(await s.deleteCase('case_missing')).toBe('absent');
  });

  it('deleteCase TOMBSTONES (not hard-delete) under a legal hold', async () => {
    const s = await store();
    const dek = newDek();
    const c = await s.createCase('sub-hold', wrapDek(dek, master));
    await s.setIdentityCiphertext(c.caseId, sealField('pii', dek));
    await s.addEvidence({ caseId: c.caseId, kind: 'document', tier: 3, ciphertext: sealField('doc', dek) });
    await s.setLegalHold(c.caseId, true);

    expect(await s.deleteCase(c.caseId)).toBe('tombstoned');
    const row = await s.getCase(c.caseId);
    expect(row).toBeDefined(); // row preserved for the hold
    expect(row?.tombstonedAt).toBeDefined();
    expect(row?.identityCt).toBeUndefined(); // PII wiped
    expect((await s.listEvidence(c.caseId))[0]?.ciphertext).toBeUndefined(); // evidence wiped
    // A tombstoned case is not returned as the user's latest.
    expect(await s.getLatestCaseForUser('sub-hold')).toBeUndefined();
  });
});
