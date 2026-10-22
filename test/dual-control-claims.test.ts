/**
 * Dual-control (two distinct admins, single use) pinned at the enforcing step.
 *
 * `approveDsar` / `approveUnlock` pre-check the request (used? expired? same
 * admin?) and then CLAIM it with one conditional UPDATE. The pre-checks only pick
 * the error message; the claim is what holds under concurrency. These tests make
 * the claim observable on its own:
 *   - the store-level claim refuses the requesting admin, whatever the caller did;
 *   - concurrent DSAR approvals, with query latency so every caller passes the
 *     pre-check before any claim lands, export exactly once.
 * Postgres is pg-mem in-process; nothing leaves the test.
 */
import { randomBytes } from 'node:crypto';
import { beforeEach, describe, expect, it } from 'vitest';
import { newDb } from 'pg-mem';
import { KycCaseStore } from '../src/kyc-cases-pg.js';
import { KycAuditLog } from '../src/kyc-audit-pg.js';
import { newDek, sealField, unwrapDek, wrapDek } from '../src/kyc-crypto.js';
import * as actions from '../src/admin-kyc-actions.js';

type Pool = { query(t: string, p?: unknown[]): Promise<{ rows: unknown[] }> };

/** Delay every statement so concurrent callers interleave between the read and the claim. */
function withLatency(inner: Pool, ms = 3): Pool {
  return { query: async (t, p) => { await new Promise((r) => setTimeout(r, ms)); return inner.query(t, p); } };
}

const master = randomBytes(32);
let store: KycCaseStore;
let audit: KycAuditLog;
const getDek = async (id: string) => {
  const k = await store.getCase(id);
  return k ? unwrapDek(k.wrappedDek, master) : null;
};

beforeEach(async () => {
  const pg = newDb().adapters.createPg();
  store = new KycCaseStore(withLatency(new pg.Pool()) as never);
  audit = new KycAuditLog(new pg.Pool());
  await store.ensureSchema();
  await audit.ensureSchema();
});

async function seedCase(sub: string): Promise<string> {
  const dek = newDek();
  const c = await store.createCase(sub, wrapDek(dek, master));
  await store.setIdentityCiphertext(c.caseId, sealField(JSON.stringify({ name: 'Test Person' }), dek));
  return c.caseId;
}

describe('the atomic claim refuses the requesting admin', () => {
  it('DSAR: claimDsarRequest by the requester returns nothing; a second admin claims it', async () => {
    const req = await store.createDsarRequest('sub-claim', 'admin-A', 'ticket');
    expect(await store.claimDsarRequest(req.requestId, 'admin-A')).toBeUndefined();
    expect((await store.getDsarRequest(req.requestId))?.consumedAt).toBeUndefined();
    expect(await store.claimDsarRequest(req.requestId, 'admin-B')).toMatchObject({ requestId: req.requestId, sub: 'sub-claim' });
  });

  it('unlock: claimUnlockRequest by the requester returns nothing; a second admin claims it', async () => {
    const caseId = await seedCase('sub-claim-u');
    const req = await store.createUnlockRequest(caseId, 'admin-A', 'subpoena');
    expect(await store.claimUnlockRequest(req.unlockId, 'admin-A')).toBeUndefined();
    expect((await store.getUnlockRequest(req.unlockId))?.consumedAt).toBeUndefined();
    expect(await store.claimUnlockRequest(req.unlockId, 'admin-B')).toBe(caseId);
  });
});

describe('concurrent DSAR approvals export exactly once', () => {
  it('six interleaved approvals by the second admin: one export, five refusals', async () => {
    await seedCase('sub-race');
    const r = await actions.requestDsar(store, audit, { actor: 'admin-A', sub: 'sub-race', reason: 'race' });
    const results = await Promise.all(
      Array.from({ length: 6 }, () => actions.approveDsar(store, audit, { approver: 'admin-B', requestId: r.requestId, getDek })),
    );
    expect(results.filter((x) => x.ok)).toHaveLength(1);
    for (const x of results.filter((y) => !y.ok)) expect(x).toEqual({ ok: false, error: 'dsar_already_used' });
    expect((await audit.list()).filter((e) => e.action === 'dsar.export')).toHaveLength(1);
  });
});
