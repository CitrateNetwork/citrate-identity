/**
 * VERI-S4 — admin route auth gate. The authorized action logic is covered by
 * admin-kyc-actions.test.ts (session-injecting is out of scope); here we prove the
 * routes are mounted and FAIL CLOSED to 403 without an admin session.
 */
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { newDb } from 'pg-mem';
import { randomBytes } from 'node:crypto';
import { createProvider } from '../src/server.js';
import { setKycProvider } from '../src/kyc-providers/index.js';
import { InhouseKycProvider } from '../src/kyc-providers/inhouse.js';
import { KycCaseStore } from '../src/kyc-cases-pg.js';
import { KycAuditLog, setKycAuditLog } from '../src/kyc-audit-pg.js';

let server: Server;
let baseUrl: string;

beforeAll(async () => {
  const db = newDb();
  const pg = db.adapters.createPg();
  const store = new KycCaseStore(new pg.Pool());
  const audit = new KycAuditLog(new pg.Pool());
  await store.ensureSchema();
  await audit.ensureSchema();

  const probe = createServer();
  await new Promise<void>((res) => probe.listen(0, '127.0.0.1', res));
  const { port } = probe.address() as AddressInfo;
  probe.close();
  baseUrl = `http://127.0.0.1:${port}`;
  const oidc = await createProvider(baseUrl, { googleEnabled: false });
  setKycProvider(new InhouseKycProvider({ mode: 'sandbox', store, masterKey: randomBytes(32), sessionSecret: 's', webhookSecret: 'wh', captureBaseUrl: `${baseUrl}/verify` }));
  setKycAuditLog(audit);
  process.env.KYC_ADMIN_SUBS = 'admin-sub-1';
  server = createServer(oidc.callback());
  await new Promise<void>((res) => server.listen(port, '127.0.0.1', res));
});
afterAll(async () => {
  setKycProvider(undefined);
  setKycAuditLog(undefined);
  delete process.env.KYC_ADMIN_SUBS;
  await new Promise<void>((res, rej) => server.close((e) => (e ? rej(e) : res())));
});

describe('/admin/kyc auth gate (VERI-S4)', () => {
  it('403s every route without an admin session', async () => {
    expect((await fetch(`${baseUrl}/admin/kyc/cases`, { redirect: 'manual' })).status).toBe(403);
    expect((await fetch(`${baseUrl}/admin/kyc/audit`, { redirect: 'manual' })).status).toBe(403);
    const del = await fetch(`${baseUrl}/admin/kyc/delete`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ sub: 'x' }), redirect: 'manual' });
    expect(del.status).toBe(403);
    const unlock = await fetch(`${baseUrl}/admin/kyc/unlock/approve`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ unlockId: 'x' }), redirect: 'manual' });
    expect(unlock.status).toBe(403);
  });
});
