/**
 * PBA-L3a-008 on the bearer-authenticated custom routes (#52).
 *
 * The account revocation epoch (password reset / sign out everywhere) already
 * refused pre-epoch refresh grants, /userinfo and browser sessions. The custom
 * routes that read an access token straight from the adapter did not check it,
 * so a token issued before the epoch kept working on them until it expired.
 *
 * Under test: every such route refuses a pre-epoch token with 401 and accepts a
 * token issued at or after the epoch (the OAuth relay has its own cases in
 * oauth-relay.test.ts).
 */
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { privateKeyToAccount } from 'viem/accounts';
import type { Address, Hex } from 'viem';
import type Provider from 'oidc-provider';
import { createProvider } from '../src/server.js';
import { mountAaRoutes } from '../src/aa/aa-routes.js';
import { mountGuardianRoutes } from '../src/aa/guardian-routes.js';
import { InMemoryHandoffStore } from '../src/handoff-store.js';
import {
  InMemoryAccountEpochStore,
  getAccountEpochStore,
  setAccountEpochStore,
} from '../src/auth/account-epoch.js';

const config = {
  factory: '0x00000000000000000000000000000000000000f1' as Address,
  kernelImpl: '0x00000000000000000000000000000000000000f2' as Address,
  chainId: 40204n,
  identitySignerKey: `0x${'5a'.repeat(32)}` as Hex,
  ecdsaValidator: '0x00000000000000000000000000000000000000e1' as Address,
  webauthnValidator: '0x00000000000000000000000000000000000000e2' as Address,
};

let server: Server;
let baseUrl: string;
let provider: Provider;

beforeAll(async () => {
  const probe = createServer();
  await new Promise<void>((r) => probe.listen(0, '127.0.0.1', r));
  const { port } = probe.address() as AddressInfo;
  probe.close();
  baseUrl = `http://127.0.0.1:${port}`;
  provider = await createProvider(baseUrl, { googleEnabled: false, handoffStore: new InMemoryHandoffStore() });
  mountAaRoutes(provider, { config, rpcUrl: 'http://127.0.0.1:9' });
  mountGuardianRoutes(provider);
  server = createServer(provider.callback());
  await new Promise<void>((r) => server.listen(port, '127.0.0.1', r));
});
afterAll(async () => {
  await new Promise<void>((r) => server.close(() => r()));
});
afterEach(() => setAccountEpochStore(new InMemoryAccountEpochStore()));

const nowSec = () => Math.floor(Date.now() / 1000);

/** A real access token in the authority's adapter, authenticated at `iat`. */
async function mint(accountId: string, iat?: number, clientId = 'citrate-core'): Promise<string> {
  const client = await provider.Client.find(clientId);
  if (!client) throw new Error(`client ${clientId} not registered`);
  const at = new provider.AccessToken({
    accountId,
    client,
    scope: 'openid wallet',
    ...(iat !== undefined ? { iat } : {}),
  } as never);
  return at.save();
}

/** Each route, with the status a valid token gets for the request sent. */
interface Case {
  name: string;
  okStatus: number;
  call(token: string, account: string): Promise<Response>;
}

const bearer = (token: string, json = false): Record<string, string> => ({
  authorization: `Bearer ${token}`,
  ...(json ? { 'content-type': 'application/json' } : {}),
});

const cases: Case[] = [
  {
    name: 'POST /kyc/handoff',
    okStatus: 200,
    call: (t) =>
      fetch(`${baseUrl}/kyc/handoff`, { method: 'POST', headers: bearer(t, true), body: JSON.stringify({ level: 'T3' }) }),
  },
  {
    name: 'GET /identity/:sub/wallets',
    okStatus: 200,
    call: (t, a) => fetch(`${baseUrl}/identity/${encodeURIComponent(a)}/wallets`, { headers: bearer(t) }),
  },
  {
    // resolveCaller: a valid caller reaches body validation.
    name: 'POST /aa/enroll-validator',
    okStatus: 400,
    call: (t) => fetch(`${baseUrl}/aa/enroll-validator`, { method: 'POST', headers: bearer(t, true), body: '{}' }),
  },
  {
    // resolveAccount: a valid caller reaches body validation.
    name: 'POST /aa/register-wallet',
    okStatus: 400,
    call: (t) => fetch(`${baseUrl}/aa/register-wallet`, { method: 'POST', headers: bearer(t, true), body: '{}' }),
  },
  {
    name: 'GET /aa/guardians',
    okStatus: 200,
    call: (t) => fetch(`${baseUrl}/aa/guardians`, { headers: bearer(t) }),
  },
];

describe('PBA-L3a-008: bearer routes honour the account epoch', () => {
  cases.forEach((c, i) => {
    const account = privateKeyToAccount(`0x${(i + 1).toString(16).padStart(2, '0').repeat(32)}` as Hex).address;

    it(`${c.name}: a token issued before the epoch is refused 401`, async () => {
      const old = await mint(account, nowSec() - 60);
      expect((await c.call(old, account)).status).toBe(c.okStatus); // works until the epoch
      await getAccountEpochStore().bump(account, nowSec());
      expect((await c.call(old, account)).status).toBe(401);
    });

    it(`${c.name}: a token issued after the epoch works`, async () => {
      await getAccountEpochStore().bump(account, nowSec() - 30);
      const fresh = await mint(account);
      expect((await c.call(fresh, account)).status).toBe(c.okStatus);
    });
  });
});
