/**
 * PBA-L3a-005 (MEDIUM) — any client's access token could link a wallet the
 * attacker controls to the victim's identity and promote it to the canonical
 * (pay-to) address. The wallet's own EIP-191 proof was already required; what
 * was missing is WHICH token may drive it.
 *
 * Fix under test: the mutating registry routes (challenge, link, canonical,
 * unlink) require a token minted to a Citrate wallet client AND carrying the
 * `wallet` scope. Listing stays open to the subject's own token from any client.
 */
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

const { buildWalletLinkMessage, InMemoryWalletRegistry, setWalletRegistry, getWalletRegistry } = registry;
const victim = privateKeyToAccount(`0x${'a1'.repeat(32)}` as Hex);
const attackerWallet = privateKeyToAccount(`0x${'a2'.repeat(32)}` as Hex);

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

async function token(clientId: string, scope: string, accountId = victim.address): Promise<string> {
  const client = await provider.Client.find(clientId);
  return new provider.AccessToken({ accountId, client: client!, scope } as never).save();
}
const sub = () => victim.address;

async function linkWith(tok: string, wallet = attackerWallet): Promise<Response> {
  const ch = await fetch(`${baseUrl}/identity/${sub()}/wallets/challenge`, { method: 'POST', headers: { authorization: `Bearer ${tok}` } });
  if (ch.status !== 200) return ch;
  const { nonce } = (await ch.json()) as { nonce: string };
  const message = buildWalletLinkMessage({ authority: siweDomainFromIssuer(baseUrl), sub: sub(), address: wallet.address, nonce, chainId: CITRATE_CHAIN_ID });
  const signature = await wallet.signMessage({ message });
  return fetch(`${baseUrl}/identity/${sub()}/wallets`, {
    method: 'POST',
    headers: { authorization: `Bearer ${tok}`, 'content-type': 'application/json' },
    body: JSON.stringify({ address: wallet.address, signature, nonce }),
  });
}

describe('PBA-L3a-005 wallet linking is limited to wallet clients with the wallet scope', () => {
  it('a token from an unrelated RP (explorer) cannot link an attacker wallet', async () => {
    const r = await linkWith(await token('citrate-explorer', 'openid wallet'));
    expect(r.status).toBe(403);
    expect(((await r.json()) as { error: string }).error).toBe('client_not_permitted');
    expect(await getWalletRegistry().list(sub())).toHaveLength(0);
  });

  it('nor promote one to canonical, nor unlink the victim\'s wallet', async () => {
    await getWalletRegistry().link(sub(), victim.address);
    await getWalletRegistry().link(sub(), attackerWallet.address);
    const tok = await token('citrate-explorer', 'openid wallet');
    const canon = await fetch(`${baseUrl}/identity/${sub()}/wallets/${attackerWallet.address}/canonical`, { method: 'POST', headers: { authorization: `Bearer ${tok}` } });
    expect(canon.status).toBe(403);
    expect((await getWalletRegistry().canonicalFor(sub()))?.toLowerCase()).toBe(victim.address.toLowerCase());
    const del = await fetch(`${baseUrl}/identity/${sub()}/wallets/${victim.address}`, { method: 'DELETE', headers: { authorization: `Bearer ${tok}` } });
    expect(del.status).toBe(403);
    expect(await getWalletRegistry().list(sub())).toHaveLength(2);
  });

  it('a wallet client without the wallet scope is refused', async () => {
    const r = await linkWith(await token('citrate-core', 'openid profile'));
    expect(r.status).toBe(403);
    expect(((await r.json()) as { error: string }).error).toBe('insufficient_scope');
    // `wallet` must be a whole scope token, not a substring of another one.
    const r2 = await linkWith(await token('citrate-core', 'openid profile'), victim);
    expect(r2.status).toBe(403);
  });

  it('the desktop app (citrate-core, wallet scope) still links with a wallet proof', async () => {
    const r = await linkWith(await token('citrate-core', 'openid profile wallet'), victim);
    expect(r.status).toBe(201);
  });

  it('listing your own wallets stays available to any client', async () => {
    const r = await fetch(`${baseUrl}/identity/${sub()}/wallets`, { headers: { authorization: `Bearer ${await token('citrate-explorer', 'openid')}` } });
    expect(r.status).toBe(200);
    expect(await r.json()).toMatchObject({ sub: sub(), wallets: [] });
  });

  it('the permitted client set is exactly the Citrate wallet apps', () => {
    const ids = (registry as { WALLET_LINK_CLIENT_IDS?: ReadonlySet<string> }).WALLET_LINK_CLIENT_IDS;
    expect([...(ids ?? [])].sort()).toEqual(['citrate-core', 'citrate-gui-native', 'citrate-wallet-extension']);
  });
});
