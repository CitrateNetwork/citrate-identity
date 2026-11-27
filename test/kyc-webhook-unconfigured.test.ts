/**
 * The trusted KYC webhook (`POST /kyc/_set`, `/kyc/_revoke`) is disabled when no
 * webhook secret is configured: it answers 503 `kyc_webhook_unconfigured` for
 * any presented bearer and writes nothing. Driven through a provider built by
 * createProvider with no secret in options or the environment.
 */
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createProvider } from '../src/server.js';
import { InMemoryKycStore, setKycStore } from '../src/kyc.js';

const ADDRESS = '0x00000000000000000000000000000000000000c3';
let server: Server;
let baseUrl: string;
let saved: string | undefined;
const store = new InMemoryKycStore();

beforeAll(async () => {
  saved = process.env.KYC_WEBHOOK_SECRET;
  delete process.env.KYC_WEBHOOK_SECRET;
  setKycStore(store);
  const probe = createServer();
  await new Promise<void>((r) => probe.listen(0, '127.0.0.1', r));
  const { port } = probe.address() as AddressInfo;
  probe.close();
  baseUrl = `http://127.0.0.1:${port}`;
  const provider = await createProvider(baseUrl, { googleEnabled: false });
  server = createServer(provider.callback());
  await new Promise<void>((r) => server.listen(port, '127.0.0.1', r));
});

afterAll(async () => {
  await new Promise<void>((r) => server.close(() => r()));
  setKycStore(new InMemoryKycStore());
  if (saved === undefined) delete process.env.KYC_WEBHOOK_SECRET;
  else process.env.KYC_WEBHOOK_SECRET = saved;
});

async function post(path: string, bearer: string | null): Promise<Response> {
  const headers: Record<string, string> = { 'content-type': 'application/json' };
  if (bearer !== null) headers.authorization = `Bearer ${bearer}`;
  return fetch(`${baseUrl}${path}`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ address: ADDRESS, status: 'verified', vendor_ref: 'probe' }),
  });
}

describe('KYC webhook with no secret configured', () => {
  for (const bearer of ['anything', 'undefined', '']) {
    it(`/kyc/_set answers 503 for bearer ${JSON.stringify(bearer)} and writes nothing`, async () => {
      const res = await post('/kyc/_set', bearer);
      expect(res.status).toBe(503);
      expect(((await res.json()) as { error?: string }).error).toBe('kyc_webhook_unconfigured');
      expect(store.get(ADDRESS)).toBeUndefined();
    });
  }

  it('/kyc/_revoke answers 503 too', async () => {
    const res = await post('/kyc/_revoke', 'anything');
    expect(res.status).toBe(503);
  });
});
