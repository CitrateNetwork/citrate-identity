/**
 * Dataroom hand-off C.2 (/kyc/return) + C.3 (GET /kyc/status?sub=).
 */
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createProvider } from '../src/server.js';
import { getKycStore, setKycStore, InMemoryKycStore } from '../src/kyc.js';

const STATUS_SECRET = 'ksec_test_0xabc';
let server: Server;
let baseUrl: string;

beforeAll(async () => {
  setKycStore(new InMemoryKycStore());
  process.env.KYC_STATUS_SECRET = STATUS_SECRET;
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
  delete process.env.KYC_STATUS_SECRET;
  await new Promise<void>((res, rej) => server.close((e) => (e ? rej(e) : res())));
});

describe('GET /kyc/status?sub= (owner re-check, C.3)', () => {
  it('401s without the secret', async () => {
    const res = await fetch(`${baseUrl}/kyc/status?sub=u1`, { redirect: 'manual' });
    expect(res.status).toBe(401);
  });

  it('returns the live status for a sub with the secret', async () => {
    await getKycStore().set('u1', {
      status: 'verified',
      vendor_ref: 'app1',
      verified_at: '2026-06-18T00:00:00.000Z',
      expires_at: '2027-06-18T00:00:00.000Z',
    });
    const res = await fetch(`${baseUrl}/kyc/status?sub=u1`, {
      headers: { authorization: `Bearer ${STATUS_SECRET}` },
      redirect: 'manual',
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { sub: string; kyc_status: string };
    expect(body.sub).toBe('u1');
    expect(body.kyc_status).toBe('verified');
  });

  it("returns 'none' for an unknown sub", async () => {
    const res = await fetch(`${baseUrl}/kyc/status?sub=nobody`, {
      headers: { authorization: `Bearer ${STATUS_SECRET}` },
      redirect: 'manual',
    });
    expect(res.status).toBe(200);
    expect(((await res.json()) as { kyc_status: string }).kyc_status).toBe('none');
  });

  it('400s without a sub', async () => {
    const res = await fetch(`${baseUrl}/kyc/status`, {
      headers: { authorization: `Bearer ${STATUS_SECRET}` },
      redirect: 'manual',
    });
    expect(res.status).toBe(400);
  });
});

describe('GET /kyc/return (post-KYC landing, C.2)', () => {
  it('303s to the fallback dataroom origin when no return cookie is present', async () => {
    const res = await fetch(`${baseUrl}/kyc/return`, { redirect: 'manual' });
    expect(res.status).toBe(303);
    const loc = res.headers.get('location');
    // Default allowlist's primary origin.
    expect(loc).toBe('https://dataroom.citrate.ai');
  });
});
