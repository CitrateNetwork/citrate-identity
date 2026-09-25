/**
 * PBA-L3a-005 variant — POST /kyc/handoff mints a single-use nonce that opens
 * /kyc/start or /account AS the token's subject in whatever browser follows it.
 * Like wallet linking, that is a desktop-app action: a leaked token from any
 * other RP must not be able to open the victim's KYC / account surfaces in the
 * attacker's browser.
 */
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type Provider from 'oidc-provider';
import { createProvider } from '../src/server.js';
import * as handoffRoutes from '../src/kyc-handoff-routes.js';

let server: Server;
let baseUrl: string;
let provider: Provider;

beforeAll(async () => {
  const probe = createServer();
  await new Promise<void>((r) => probe.listen(0, '127.0.0.1', r));
  const { port } = probe.address() as AddressInfo;
  probe.close();
  baseUrl = `http://127.0.0.1:${port}`;
  provider = await createProvider(baseUrl, { googleEnabled: false });
  server = createServer(provider.callback());
  await new Promise<void>((r) => server.listen(port, '127.0.0.1', r));
});
afterAll(async () => { await new Promise<void>((r) => server.close(() => r())); });

async function token(clientId: string): Promise<string> {
  const client = await provider.Client.find(clientId);
  return new provider.AccessToken({ accountId: '0xvictim', client: client!, scope: 'openid' } as never).save();
}
const handoff = async (tok: string) =>
  fetch(`${baseUrl}/kyc/handoff`, { method: 'POST', headers: { authorization: `Bearer ${tok}`, 'content-type': 'application/json' }, body: '{}' });

describe('PBA-L3a-005 variant: /kyc/handoff is a desktop-app action', () => {
  it('a token from another RP cannot mint a hand-off', async () => {
    const r = await handoff(await token('citrate-explorer'));
    expect(r.status).toBe(403);
    expect(((await r.json()) as { error: string }).error).toBe('client_not_permitted');
  });
  it('the desktop app still can', async () => {
    const r = await handoff(await token('citrate-core'));
    expect(r.status).toBe(200);
    expect(((await r.json()) as { url: string }).url).toContain('/kyc/start?handoff=');
  });
  it('the permitted set is the desktop apps', () => {
    const ids = (handoffRoutes as { KYC_HANDOFF_CLIENT_IDS?: ReadonlySet<string> }).KYC_HANDOFF_CLIENT_IDS;
    expect([...(ids ?? [])].sort()).toEqual(['citrate-core', 'citrate-gui-native']);
  });
});
