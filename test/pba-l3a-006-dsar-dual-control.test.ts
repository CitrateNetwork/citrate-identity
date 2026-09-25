/**
 * PBA-L3a-006 (MEDIUM) — GET /admin/kyc/dsar decrypted a subject's identity for a
 * SINGLE admin, sidestepping the two-distinct-admins rule the subpoena unlock
 * enforces; and as a GET it was readable cross-origin with the admin cookie.
 *
 * Fix under test: DSAR is a POST request/approve pair behind the admin CSRF guard,
 * approval needs a second, distinct admin, and approval is single-use under
 * concurrency (a variant fixed in the subpoena unlock too).
 */
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { randomBytes } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { privateKeyToAccount } from 'viem/accounts';
import type { Hex } from 'viem';
import { newDb } from 'pg-mem';
import { createProvider } from '../src/server.js';
import { setKycProvider } from '../src/kyc-providers/index.js';
import { InhouseKycProvider } from '../src/kyc-providers/inhouse.js';
import { KycCaseStore } from '../src/kyc-cases-pg.js';
import { KycAuditLog, setKycAuditLog } from '../src/kyc-audit-pg.js';
import { newDek, sealField, unwrapDek, wrapDek } from '../src/kyc-crypto.js';
import * as actions from '../src/admin-kyc-actions.js';
import { Jar, openConsole, sameOriginJson, siweLogin } from './helpers/admin-session.js';

const adminA = privateKeyToAccount(`0x${'d1'.repeat(32)}` as Hex);
const adminB = privateKeyToAccount(`0x${'d2'.repeat(32)}` as Hex);
let server: Server;
let baseUrl: string;
let store: KycCaseStore;
let audit: KycAuditLog;
const master = randomBytes(32);
const jarA = new Jar();
const jarB = new Jar();
let csrfA = '';
let csrfB = '';

beforeAll(async () => {
  const db = newDb();
  const pg = db.adapters.createPg();
  store = new KycCaseStore(new pg.Pool());
  audit = new KycAuditLog(new pg.Pool());
  await store.ensureSchema();
  await audit.ensureSchema();
  const probe = createServer();
  await new Promise<void>((r) => probe.listen(0, '127.0.0.1', r));
  const { port } = probe.address() as AddressInfo;
  probe.close();
  baseUrl = `http://127.0.0.1:${port}`;
  const oidc = await createProvider(baseUrl, { googleEnabled: false });
  setKycProvider(new InhouseKycProvider({ mode: 'sandbox', store, masterKey: master, sessionSecret: 's', webhookSecret: 'wh', captureBaseUrl: `${baseUrl}/verify` }));
  setKycAuditLog(audit);
  process.env.KYC_ADMIN_SUBS = `${adminA.address},${adminB.address}`;
  server = createServer(oidc.callback());
  await new Promise<void>((r) => server.listen(port, '127.0.0.1', r));
  await siweLogin(baseUrl, adminA, jarA);
  await siweLogin(baseUrl, adminB, jarB);
  csrfA = await openConsole(baseUrl, jarA);
  csrfB = await openConsole(baseUrl, jarB);
  const dek = newDek();
  const c = await store.createCase('sub-dsar', wrapDek(dek, master));
  await store.setIdentityCiphertext(c.caseId, sealField(JSON.stringify({ name: 'Grace Hopper' }), dek));
});
afterAll(async () => {
  setKycProvider(undefined);
  setKycAuditLog(undefined);
  delete process.env.KYC_ADMIN_SUBS;
  await new Promise<void>((r) => server.close(() => r()));
});

const post = (jar: Jar, csrf: string, path: string, body: unknown) =>
  fetch(`${baseUrl}${path}`, { method: 'POST', headers: sameOriginJson(baseUrl, jar, csrf), body: JSON.stringify(body) });

describe('PBA-L3a-006 DSAR export needs two admins', () => {
  it('the single-admin GET export is gone (no decrypted PII to one admin)', async () => {
    const r = await fetch(`${baseUrl}/admin/kyc/dsar?sub=sub-dsar`, { headers: { 'sec-fetch-site': 'same-origin', cookie: jarA.header() } });
    const text = await r.text();
    expect(r.status).not.toBe(200);
    expect(text).not.toContain('Grace Hopper');
  });

  it('request by A, self-approval by A is refused, approval by B exports once', async () => {
    const req = await post(jarA, csrfA, '/admin/kyc/dsar/request', { sub: 'sub-dsar', reason: 'DSAR ticket 42' });
    expect(req.status).toBe(200);
    const { requestId } = (await req.json()) as { requestId: string };
    expect(requestId).toMatch(/^dsar_/);

    const self = await post(jarA, csrfA, '/admin/kyc/dsar/approve', { requestId });
    expect(self.status).toBe(400);
    const selfBody = await self.text();
    expect(selfBody).not.toContain('Grace Hopper');
    expect(selfBody).toContain('dual_control_violation');
    const reqRow = (await audit.list()).find((e) => e.action === 'dsar.request');
    expect(reqRow?.detail).toMatchObject({ requestId, sub: 'sub-dsar', reason: 'DSAR ticket 42' });
    expect((await store.getDsarRequest(requestId))?.createdAt).toBeGreaterThan(0);

    const ok = await post(jarB, csrfB, '/admin/kyc/dsar/approve', { requestId });
    expect(ok.status).toBe(200);
    const body = (await ok.json()) as { cases: Array<{ identity: { name: string } }> };
    expect(body.cases[0]?.identity.name).toBe('Grace Hopper');

    const again = await post(jarB, csrfB, '/admin/kyc/dsar/approve', { requestId });
    expect(again.status).toBe(400);
    expect(((await again.json()) as { error: string }).error).toBe('dsar_already_used');
    const unknown = await post(jarB, csrfB, '/admin/kyc/dsar/approve', { requestId: 'dsar_nope' });
    expect(((await unknown.json()) as { error: string }).error).toBe('dsar_not_found');
    expect(await store.getDsarRequest('dsar_nope')).toBeUndefined();
    expect((await post(jarA, csrfA, '/admin/kyc/dsar/request', { sub: 'sub-dsar' })).status).toBe(400);
    expect((await post(jarB, csrfB, '/admin/kyc/dsar/approve', {})).status).toBe(400);

    const log = await audit.list();
    const exp = log.find((e) => e.action === 'dsar.export');
    expect(exp?.detail).toMatchObject({ requestedBy: adminA.address, approvedBy: adminB.address });
  });

  it('concurrent approvals of one request export exactly once', async () => {
    const req = await post(jarA, csrfA, '/admin/kyc/dsar/request', { sub: 'sub-dsar', reason: 'race' });
    const { requestId } = (await req.json()) as { requestId: string };
    const rs = await Promise.all(Array.from({ length: 6 }, () => post(jarB, csrfB, '/admin/kyc/dsar/approve', { requestId })));
    expect(rs.filter((r) => r.status === 200)).toHaveLength(1);
  });

  it('the subpoena unlock and delete still work over HTTP for two admins', async () => {
    const dek = newDek();
    const c = await store.createCase('sub-http-unlock', wrapDek(dek, master));
    await store.setIdentityCiphertext(c.caseId, sealField(JSON.stringify({ name: 'Katherine' }), dek));
    const rq = await post(jarA, csrfA, '/admin/kyc/unlock/request', { caseId: c.caseId, reason: 'subpoena 9' });
    expect(rq.status).toBe(200);
    const { unlockId } = (await rq.json()) as { unlockId: string };
    expect((await post(jarA, csrfA, '/admin/kyc/unlock/request', { caseId: c.caseId })).status).toBe(400);
    expect((await post(jarB, csrfB, '/admin/kyc/unlock/approve', {})).status).toBe(400);
    const ap = await post(jarB, csrfB, '/admin/kyc/unlock/approve', { unlockId });
    expect(ap.status).toBe(200);
    expect(((await ap.json()) as { identity: { name: string } }).identity.name).toBe('Katherine');
    const del = await post(jarA, csrfA, '/admin/kyc/delete', { sub: 'sub-http-unlock' });
    expect(del.status).toBe(200);
    expect(((await del.json()) as { ok: boolean }).ok).toBe(true);
  });

  it('the DSAR routes sit behind the admin CSRF guard', async () => {
    const r = await fetch(`${baseUrl}/admin/kyc/dsar/request`, {
      method: 'POST',
      headers: { 'content-type': 'text/plain', origin: 'https://evil.example', 'sec-fetch-site': 'cross-site', cookie: jarA.header() },
      body: JSON.stringify({ sub: 'sub-dsar', reason: 'x' }),
    });
    expect(r.status).toBe(403);
  });
});

describe('variant: subpoena unlock approval is single-use under concurrency', () => {
  it('concurrent approvals by the second admin decrypt exactly once', async () => {
    const dek = newDek();
    const c = await store.createCase('sub-unlock-race', wrapDek(dek, master));
    await store.setIdentityCiphertext(c.caseId, sealField(JSON.stringify({ name: 'Ada' }), dek));
    const getDek = async (id: string) => { const k = await store.getCase(id); return k ? unwrapDek(k.wrappedDek, master) : null; };
    const req = await actions.requestUnlock(store, audit, { actor: 'admin-A', caseId: c.caseId, reason: 'subpoena' });
    const unlockId = req.ok ? req.unlockId : '';
    const rs = await Promise.all(Array.from({ length: 6 }, () => actions.approveUnlock(store, audit, { approver: 'admin-B', unlockId, getDek })));
    expect(rs.filter((r) => r.ok)).toHaveLength(1);
    for (const r of rs.filter((x) => !x.ok)) expect(r).toEqual({ ok: false, error: 'unlock_already_used' });
  });
});

describe('PBA-L3a-006 with a single provisioned admin', () => {
  it('DSAR request/approve fail closed (409) like the subpoena unlock', async () => {
    const saved = process.env.KYC_ADMIN_SUBS;
    process.env.KYC_ADMIN_SUBS = adminA.address;
    try {
      for (const path of ['/admin/kyc/dsar/request', '/admin/kyc/dsar/approve', '/admin/kyc/unlock/request', '/admin/kyc/unlock/approve']) {
        const r = await post(jarA, csrfA, path, { sub: 'sub-dsar', reason: 'x', requestId: 'x', caseId: 'x', unlockId: 'x' });
        expect(r.status, path).toBe(409);
      }
      // a non-dual-control route is unaffected
      expect((await post(jarA, csrfA, '/admin/kyc/delete', { sub: 'nobody' })).status).toBe(200);
    } finally {
      process.env.KYC_ADMIN_SUBS = saved;
    }
  });
});
