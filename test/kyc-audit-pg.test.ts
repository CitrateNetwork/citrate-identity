import { describe, expect, it, beforeEach } from 'vitest';
import { newDb, type IMemoryDb } from 'pg-mem';
import { KycAuditLog } from '../src/kyc-audit-pg.js';

/** VERI-S4-WP5 — immutable, hash-chained audit log. */
describe('KycAuditLog (VERI-S4)', () => {
  let pool: InstanceType<ReturnType<IMemoryDb['adapters']['createPg']>['Pool']>;
  let log: KycAuditLog;

  beforeEach(async () => {
    const db = newDb();
    pool = new (db.adapters.createPg().Pool)();
    log = new KycAuditLog(pool);
    await log.ensureSchema();
  });

  it('appends a hash chain (each row links to the previous)', async () => {
    const a = await log.record({ actor: 'admin-1', action: 'case.view', caseId: 'c1' });
    const b = await log.record({ actor: 'admin-2', action: 'case.adjudicate', caseId: 'c1', detail: { decision: 'verified' } });
    expect(b.prevHash).toBe(a.hash);
    expect(b.hash).not.toBe(a.hash);
    const list = await log.list({ caseId: 'c1' });
    expect(list).toHaveLength(2);
  });

  it('verifyChain passes for an untampered log', async () => {
    for (let i = 0; i < 5; i++) await log.record({ actor: 'admin', action: 'case.view', caseId: 'c' + i });
    const v = await log.verifyChain();
    expect(v.ok).toBe(true);
    expect(v.count).toBe(5);
  });

  it('verifyChain DETECTS a tampered row (immutability guarantee)', async () => {
    await log.record({ actor: 'admin', action: 'unlock.decrypt', caseId: 'c1', detail: { reason: 'subpoena #1' } });
    const mid = await log.record({ actor: 'admin', action: 'user.delete', caseId: 'c1' });
    await log.record({ actor: 'admin', action: 'dsar.export', caseId: 'c1' });

    // Tamper: rewrite the middle row's actor directly in the DB (bypassing record()).
    await pool.query('UPDATE kyc_audit SET actor = $2 WHERE audit_id = $1', [mid.auditId, 'someone-else']);

    const v = await log.verifyChain();
    expect(v.ok).toBe(false);
    expect(v.brokenAt).toBe(mid.auditId);
  });

  it('list filters by case and is newest-first', async () => {
    await log.record({ actor: 'a', action: 'case.view', caseId: 'x' });
    await log.record({ actor: 'a', action: 'case.view', caseId: 'y' });
    const last = await log.record({ actor: 'a', action: 'case.view', caseId: 'x' });
    const xs = await log.list({ caseId: 'x' });
    expect(xs).toHaveLength(2);
    expect(xs[0].auditId).toBe(last.auditId); // newest first
    expect((await log.list()).length).toBe(3);
  });
});
