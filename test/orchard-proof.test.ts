import { buildOrchardProofMessage, ORCHARD_CLIENTS } from '../src/orchard-clients.js';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { privateKeyToAccount } from 'viem/accounts';
import type { Hex } from 'viem';
import type Provider from 'oidc-provider';
import { createProvider } from '../src/server.js';
import { siweDomainFromIssuer } from '../src/config.js';
import { CITRATE_CHAIN_ID } from '../src/siwe.js';
import * as registry from '../src/identity-registry.js';

const { InMemoryWalletRegistry, setWalletRegistry, getWalletRegistry } = registry;
const victim = privateKeyToAccount(`0x${'a1'.repeat(32)}` as Hex);


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
beforeEach(() => setWalletRegistry(new InMemoryWalletRegistry()));

async function token(clientId: string, scope: string, accountId: string = victim.address): Promise<string> {
  const client = await provider.Client.find(clientId);
  return new provider.AccessToken({ accountId, client: client!, scope } as never).save();
}
const sub = () => victim.address;


async function proof(tok: string, mismatchClient = false) {
  const headers = {authorization: `Bearer ${tok}`, 'content-type': 'application/json'};
  const ch = await fetch(`${baseUrl}/identity/${sub()}/orchard-proof/challenge`, {method: 'POST', headers});
  if (!ch.ok) return {response: ch};
  const {nonce} = await ch.json() as {nonce: string};
  const message = buildOrchardProofMessage({authority: siweDomainFromIssuer(baseUrl), sub: sub(), address: victim.address, nonce, chainId: CITRATE_CHAIN_ID, clientId: mismatchClient ? 'citrate-orchard-smb' : 'citrate-orchard-web'});
  const body = JSON.stringify({address: victim.address, nonce, signature: await victim.signMessage({message})});
  const send = () => fetch(`${baseUrl}/identity/${sub()}/orchard-proof`, {method: 'POST', headers, body});
  return {response: await send(), send};
}
describe('Orchard read-only proof', () => {
  it('verifies a real EIP-191 signature without linking a wallet and prevents replay', async () => {
    const result = await proof(await token('citrate-orchard-web', 'openid wallet'));
    expect(result.response.status).toBe(200);
    expect(await result.response.json()).toMatchObject({verified: true, sub: sub(), client_id: 'citrate-orchard-web'});
    expect(await getWalletRegistry().list(sub())).toEqual([]);
    expect((await result.send!()).status).toBe(401);
  });
  it('rejects a signature prepared for another Orchard client', async () => {
    expect((await proof(await token('citrate-orchard-web', 'openid wallet'), true)).response.status).toBe(401);
  });
  it.each([['citrate-explorer','openid wallet'], ['citrate-orchard-web','openid profile']])('rejects wrong RP/scope %s %s', async (client, scope) => {
    expect((await proof(await token(client, scope))).response.status).toBe(403);
  });
  it('rejects cross-subject access', async () => {
    const tok = await token('citrate-orchard-web', 'openid wallet', 'other-user');
    expect((await proof(tok)).response.status).toBe(403);
  });
  it('does not grant Orchard wallet-link mutation access', async () => {
    const tok = await token('citrate-orchard-web','openid wallet');
    const response = await fetch(`${baseUrl}/identity/${sub()}/wallets/challenge`, {method:'POST', headers:{authorization:`Bearer ${tok}`}});
    expect(response.status).toBe(403);
  });
  it('registers exact callback origins with no refresh or broad scopes', async () => {
    for (const [id, origins] of Object.entries(ORCHARD_CLIENTS)) {
      const client = await provider.Client.find(id);
      expect(client?.redirectUris).toEqual(origins.map(origin => `${origin}/auth/callback`));
      expect(client?.applicationType).toBe(id === 'citrate-orchard-preview' ? 'native' : 'web');
      expect(client?.grantTypes).toEqual(['authorization_code']);
      expect(client?.scope).toBe('openid profile wallet');
    }
  });
});
