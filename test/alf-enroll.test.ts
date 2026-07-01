/**
 * American Learning Federation enroll API (POST /alf/enroll).
 *
 * Least-privilege grant path: academic/orgId:alf, and ONLY for a live-verified
 * KYC principal.
 */
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createProvider } from '../src/server.js';
import { EntitlementStore, _setEntitlementStoreForTests, type PgLike } from '../src/entitlements.js';
import { InMemoryKycStore, setKycStore } from '../src/kyc.js';

const SECRET = 'alf_test_secret';
let server: Server;
let baseUrl: string;
let calls: { text: string; params?: unknown[] }[] = [];

function recordingPool(): PgLike {
  calls = [];
  return {
    async query(text: string, params?: unknown[]) {
      calls.push({ text, params });
      return { rows: [] };
    },
  };
}

async function post(body: unknown, secret?: string) {
  return fetch(`${baseUrl}/alf/enroll`, {
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
  process.env.ALF_ENROLL_SECRET = SECRET;
  _setEntitlementStoreForTests(new EntitlementStore(recordingPool()));
  const kyc = new InMemoryKycStore();
  // A live-verified principal, and a pending (not verified) one.
  kyc.set('sub-verified', { status: 'verified', verified_at: '2026-06-01T00:00:00Z', vendor_ref: 'sumsub:abc' });
  kyc.set('sub-pending', { status: 'pending', vendor_ref: 'sumsub:def' });
  setKycStore(kyc);

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
  delete process.env.ALF_ENROLL_SECRET;
  await new Promise<void>((res, rej) => server.close((e) => (e ? rej(e) : res())));
});

describe('POST /alf/enroll', () => {
  it('401s without the enroll secret', async () => {
    const r = await post({ sub: 'sub-verified' });
    expect(r.status).toBe(401);
  });

  it('400s with no sub', async () => {
    const r = await post({ email: 'x@y.com' }, SECRET);
    expect(r.status).toBe(400);
  });

  it('409s when the principal is not KYC-verified', async () => {
    const r = await post({ sub: 'sub-pending' }, SECRET);
    expect(r.status).toBe(409);
    const body = (await r.json()) as { error: string };
    expect(body.error).toBe('kyc_not_verified');
  });

  it('409s when the principal has no KYC claim at all', async () => {
    const r = await post({ sub: 'sub-unknown' }, SECRET);
    expect(r.status).toBe(409);
  });

  it('grants academic/orgId:alf for a verified principal', async () => {
    _setEntitlementStoreForTests(new EntitlementStore(recordingPool()));
    const r = await post({ sub: 'sub-verified', email: 'member@school.edu' }, SECRET);
    expect(r.status).toBe(200);
    const body = (await r.json()) as { granted: boolean; tier: string; orgId: string };
    expect(body).toEqual({ granted: true, tier: 'academic', orgId: 'alf' });
    const insert = calls.find((c) => /INSERT/i.test(c.text));
    expect(insert).toBeDefined();
    // params: [sub, email, wallet, tier, org_id, citrate_role, milestone, expires_at]
    expect(insert!.params).toEqual([
      'sub-verified',
      'member@school.edu',
      null,
      'academic',
      'alf',
      null,
      null,
      null,
    ]);
  });

  it('cannot be coerced into granting a higher tier', async () => {
    _setEntitlementStoreForTests(new EntitlementStore(recordingPool()));
    // Even if a caller tries to smuggle tier/role in the body, the endpoint
    // ignores it and grants exactly academic/alf.
    const r = await post(
      { sub: 'sub-verified', tier: 'confidential', citrateRole: 'auditor', orgId: 'evil' },
      SECRET,
    );
    expect(r.status).toBe(200);
    const insert = calls.find((c) => /INSERT/i.test(c.text));
    expect(insert!.params).toEqual([
      'sub-verified',
      null,
      null,
      'academic',
      'alf',
      null,
      null,
      null,
    ]);
  });
});
