/**
 * AUTHSPINE S1-WP4 — admin entitlement API (POST /admin/entitlements).
 */
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createProvider } from '../src/server.js';
import { EntitlementStore, _setEntitlementStoreForTests, type PgLike } from '../src/entitlements.js';

const SECRET = 'eadm_test_secret';
let server: Server;
let baseUrl: string;
let calls: { text: string; params?: unknown[] }[];

function recordingPool(): PgLike {
  calls = [];
  return {
    async query(text: string, params?: unknown[]) {
      calls.push({ text, params });
      return { rows: /^\s*SELECT/i.test(text) ? [] : [] };
    },
  };
}

async function post(body: unknown, secret?: string) {
  return fetch(`${baseUrl}/admin/entitlements`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      ...(secret ? { authorization: `Bearer ${secret}` } : {}),
    },
    body: JSON.stringify(body),
    redirect: 'manual',
  });
}

beforeAll(async () => {
  process.env.ENTITLEMENTS_ADMIN_SECRET = SECRET;
  _setEntitlementStoreForTests(new EntitlementStore(recordingPool()));
  const probe = createServer();
  await new Promise<void>((res) => probe.listen(0, '127.0.0.1', res));
  const { port } = probe.address() as AddressInfo;
  probe.close();
  baseUrl = `http://127.0.0.1:${port}`;
  const provider = await createProvider(baseUrl, { googleEnabled: false });
  server = createServer(provider.callback());
  await new Promise<void>((res) => server.listen(port, '127.0.0.1', res));
});
afterAll(async () => {
  delete process.env.ENTITLEMENTS_ADMIN_SECRET;
  await new Promise<void>((res, rej) => server.close((e) => (e ? rej(e) : res())));
});

describe('POST /admin/entitlements', () => {
  it('401s without the admin secret', async () => {
    const r = await post({ sub: 'u1', tier: 'confidential' });
    expect(r.status).toBe(401);
  });

  it('400s with no sub/email/wallet', async () => {
    const r = await post({ tier: 'confidential' }, SECRET);
    expect(r.status).toBe(400);
  });

  it('400s on an unknown tier', async () => {
    const r = await post({ sub: 'u1', tier: 'superadmin' }, SECRET);
    expect(r.status).toBe(400);
  });

  it('grants a higher tier + role and appends a roster row', async () => {
    calls = recordingPool() && calls; // reset recorder
    _setEntitlementStoreForTests(new EntitlementStore(recordingPool()));
    const r = await post(
      { email: 'partner@firm.com', tier: 'confidential', citrateRole: 'auditor', expiresAt: '2027-01-01T00:00:00Z' },
      SECRET,
    );
    expect(r.status).toBe(200);
    const body = (await r.json()) as { ok: boolean; granted: { tier: string; citrateRole?: string } };
    expect(body.ok).toBe(true);
    expect(body.granted.tier).toBe('confidential');
    const insert = calls.find((c) => /INSERT/i.test(c.text));
    expect(insert).toBeDefined();
    // params: [sub, email, wallet, tier, org_id, citrate_role, milestone, expires_at]
    expect(insert!.params).toEqual([null, 'partner@firm.com', null, 'confidential', null, 'auditor', null, '2027-01-01T00:00:00Z']);
  });
});
