import { describe, expect, it, beforeEach } from 'vitest';
import { newDb } from 'pg-mem';
import { randomBytes } from 'node:crypto';
import { KycCaseStore } from '../src/kyc-cases-pg.js';
import { KycAuditLog } from '../src/kyc-audit-pg.js';
import { newDek, sealField, unwrapDek, wrapDek } from '../src/kyc-crypto.js';
import { adjudicateCase, approveUnlock, deleteUser, dsarExport, listCases, requestUnlock } from '../src/admin-kyc-actions.js';
import { InhouseKycProvider } from '../src/kyc-providers/inhouse.js';

/** VERI-S4 — admin/compliance actions + audit. */
describe('admin KYC actions (VERI-S4)', () => {
  const master = randomBytes(32);
  let store: KycCaseStore;
  let audit: KycAuditLog;
  const getDek = async (id: string) => { const c = await store.getCase(id); return c ? unwrapDek(c.wrappedDek, master) : null; };

  beforeEach(async () => {
    const db = newDb();
    const pg = db.adapters.createPg();
    store = new KycCaseStore(new pg.Pool());
    audit = new KycAuditLog(new pg.Pool());
    await store.ensureSchema();
    await audit.ensureSchema();
  });

  async function seedCase(sub: string, name = 'Ada Lovelace') {
    const dek = newDek();
    const c = await store.createCase(sub, wrapDek(dek, master));
    await store.setIdentityCiphertext(c.caseId, sealField(JSON.stringify({ name, dob: '1815-12-10' }), dek));
    await store.setDecision(c.caseId, { decision: 'needs-review', retentionUntil: Date.now() + 864e5 });
    return c.caseId;
  }

  it('adjudicateCase(verified) records the decision + emits a webhook the provider accepts', async () => {
    const caseId = await seedCase('sub-adj');
    const r = await adjudicateCase(store, audit, { actor: 'admin-1', caseId, decision: 'verified', reason: 'manual review OK', webhookSecret: 'wh' });
    expect(r.ok).toBe(true);
    expect((await store.getCase(caseId))?.status).toBe('verified');
    // audited
    expect((await audit.list({ caseId }))[0].action).toBe('case.adjudicate');
    // the emitted webhook flows through the unchanged /kyc/webhook path
    const provider = new InhouseKycProvider({ mode: 'sandbox', store, masterKey: master, sessionSecret: 's', webhookSecret: 'wh', captureBaseUrl: 'https://x/verify' });
    if (r.ok) expect(provider.verifyWebhook(r.signedWebhook.headers, r.signedWebhook.body)).toBe(true);
  });

  it('DUAL CONTROL: unlock requires a second, distinct admin; decrypts once; audits the access not the PII', async () => {
    const caseId = await seedCase('sub-unlock');
    const req = await requestUnlock(store, audit, { actor: 'admin-A', caseId, reason: 'subpoena 2026-123' });
    expect(req.ok).toBe(true);
    const unlockId = req.ok ? req.unlockId : '';

    // Same admin cannot approve their own request.
    const self = await approveUnlock(store, audit, { approver: 'admin-A', unlockId, getDek });
    expect(self.ok).toBe(false);
    if (!self.ok) expect(self.error).toMatch(/dual_control/);

    // A different admin can — and gets the decrypted identity ONCE.
    const ok = await approveUnlock(store, audit, { approver: 'admin-B', unlockId, getDek });
    expect(ok.ok).toBe(true);
    if (ok.ok) expect((ok.identity as { name: string }).name).toBe('Ada Lovelace');

    // Single-use: a second approval fails.
    expect((await approveUnlock(store, audit, { approver: 'admin-C', unlockId, getDek })).ok).toBe(false);

    // The audit logged the access, NOT the plaintext.
    const dec = (await audit.list({ caseId })).find((a) => a.action === 'unlock.decrypt');
    expect(dec?.detail?.requestedBy).toBe('admin-A');
    expect(dec?.detail?.approvedBy).toBe('admin-B');
    expect(JSON.stringify(dec)).not.toContain('Ada'); // no PII in the audit
  });

  it('deleteUser hard-deletes without a hold, tombstones under one; both audited', async () => {
    const a = await seedCase('sub-del');
    const del = await deleteUser(store, audit, { actor: 'admin-1', sub: 'sub-del' });
    expect(del.cases[0].mode).toBe('deleted');
    expect(await store.getCase(a)).toBeUndefined();

    const b = await seedCase('sub-hold');
    await store.setLegalHold(b, true);
    const held = await deleteUser(store, audit, { actor: 'admin-1', sub: 'sub-hold' });
    expect(held.cases[0].mode).toBe('tombstoned');
    expect(await store.getCase(b)).toBeDefined(); // preserved under hold
    expect((await audit.list()).some((x) => x.action === 'user.delete')).toBe(true);
  });

  it('dsarExport returns the decrypted identity + evidence metadata for the subject', async () => {
    await seedCase('sub-dsar', 'Grace Hopper');
    const exp = await dsarExport(store, audit, { actor: 'admin-1', sub: 'sub-dsar', getDek });
    expect(exp.cases).toHaveLength(1);
    expect(((exp.cases[0] as { identity: { name: string } }).identity).name).toBe('Grace Hopper');
    expect((await audit.list()).some((x) => x.action === 'dsar.export')).toBe(true);
  });

  it('listCases returns metadata only (no ciphertext), filterable by status', async () => {
    await seedCase('sub-1');
    const all = await listCases(store, undefined);
    expect(all.length).toBeGreaterThan(0);
    expect(JSON.stringify(all)).not.toMatch(/identityCt|wrappedDek/);
    expect(await listCases(store, 'verified')).toHaveLength(0);
  });

  it('every action leaves the audit chain intact', async () => {
    const caseId = await seedCase('sub-chain');
    await adjudicateCase(store, audit, { actor: 'a', caseId, decision: 'verified', reason: 'x', webhookSecret: 'wh' });
    await deleteUser(store, audit, { actor: 'a', sub: 'sub-chain' });
    const v = await audit.verifyChain();
    expect(v.ok).toBe(true);
  });
});
