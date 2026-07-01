import { describe, expect, it, beforeEach } from 'vitest';
import { newDb, type IMemoryDb } from 'pg-mem';
import { randomBytes } from 'node:crypto';
import { KycCaseStore } from '../src/kyc-cases-pg.js';
import { runRetentionSweep } from '../src/kyc-retention.js';
import { newDek, sealField, wrapDek } from '../src/kyc-crypto.js';

/** VERI-S1-WP4 — retention/destruction sweep. */
function freshStore() {
  const db: IMemoryDb = newDb();
  const pg = db.adapters.createPg();
  return new KycCaseStore(new pg.Pool());
}

describe('runRetentionSweep (VERI-S1-WP4)', () => {
  const master = randomBytes(32);
  let store: KycCaseStore;
  beforeEach(async () => {
    store = freshStore();
    await store.ensureSchema();
  });

  it('destroys due biometrics AND purges expired non-held cases', async () => {
    const now = Date.now();
    const dek = newDek();

    // Case A: retention expired, no hold → purged.
    const a = await store.createCase('sub-a', wrapDek(dek, master));
    await store.setDecision(a.caseId, { decision: 'verified', verifiedAt: now - 1e9, expiresAt: now - 1, retentionUntil: now - 1 });
    await store.addEvidence({ caseId: a.caseId, kind: 'liveness', tier: 2, ciphertext: sealField('face', dek), destroyAfter: now - 1 });

    // Case B: retention in the future → kept; its tier-2 due now → wiped.
    const b = await store.createCase('sub-b', wrapDek(dek, master));
    await store.setDecision(b.caseId, { decision: 'verified', verifiedAt: now, expiresAt: now + 1e9, retentionUntil: now + 1e9 });
    await store.addEvidence({ caseId: b.caseId, kind: 'liveness', tier: 2, ciphertext: sealField('face', dek), destroyAfter: now - 1 });

    // Case C: retention expired BUT legal hold → kept.
    const c = await store.createCase('sub-c', wrapDek(dek, master));
    await store.setDecision(c.caseId, { decision: 'verified', retentionUntil: now - 1 });
    await store.setLegalHold(c.caseId, true);

    const res = await runRetentionSweep(store, now);
    expect(res.casesPurged).toBe(1); // only A
    // Sweep destroys biometrics FIRST, then purges: both A's and B's due tier-2
    // are wiped before A is deleted wholesale.
    expect(res.biometricsDestroyed).toBe(2);

    expect(await store.getCase(a.caseId)).toBeUndefined(); // purged
    expect(await store.getCase(b.caseId)).toBeDefined(); // kept
    expect((await store.listEvidence(b.caseId))[0]?.ciphertext).toBeUndefined(); // biometric wiped
    expect(await store.getCase(c.caseId)).toBeDefined(); // legal hold kept
  });

  it('is idempotent (a second pass changes nothing)', async () => {
    const now = Date.now();
    const a = await store.createCase('sub-x', wrapDek(newDek(), master));
    await store.setDecision(a.caseId, { decision: 'verified', retentionUntil: now - 1 });
    await runRetentionSweep(store, now);
    const res2 = await runRetentionSweep(store, now);
    expect(res2.casesPurged).toBe(0);
    expect(res2.biometricsDestroyed).toBe(0);
  });
});
