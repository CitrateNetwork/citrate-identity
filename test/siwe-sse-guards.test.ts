/**
 * Interaction and session-stream guards pinned at their entry points:
 *   - POST /siwe/verify with an in-flight interaction refuses a cross-site
 *     request (the same-origin check that already guards /consent/approve);
 *   - mounting the SIWE routes with the direct token grant enabled refuses an
 *     audience that is not a registered first-party client;
 *   - GET /sessions/events caps concurrent streams and frees a slot on close.
 * Everything runs in-process on 127.0.0.1; no external service is contacted.
 */
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { EventEmitter } from 'node:events';
import { createHash, randomBytes } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { privateKeyToAccount } from 'viem/accounts';
import type { Hex } from 'viem';
import { SiweMessage } from 'siwe';
import type Provider from 'oidc-provider';
import { createProvider } from '../src/server.js';
import { CITRATE_CHAIN_ID } from '../src/siwe.js';
import { mountSiweRoutes } from '../src/siwe-routes.js';
import { mountLogoutRoutes } from '../src/logout-routes.js';
import { Jar } from './helpers/admin-session.js';

const REDIRECT = 'http://localhost:3001/auth/callback';
const b64u = (b: Buffer): string => b.toString('base64url');
const account = privateKeyToAccount(`0x${'c7'.repeat(32)}` as Hex);

describe('POST /siwe/verify with an active interaction', () => {
  let server: Server;
  let baseUrl: string;

  beforeAll(async () => {
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
  });

  async function startInteraction(jar: Jar): Promise<void> {
    const challenge = b64u(createHash('sha256').update(b64u(randomBytes(32))).digest());
    const a = await fetch(
      `${baseUrl}/auth?response_type=code&client_id=citrate-explorer&redirect_uri=${encodeURIComponent(REDIRECT)}` +
        `&scope=openid&code_challenge=${challenge}&code_challenge_method=S256&state=s`,
      { redirect: 'manual', headers: { cookie: jar.header() } },
    );
    jar.absorb(a);
    const loc = a.headers.get('location') ?? '';
    expect(loc).toContain('/interaction/');
    jar.absorb(await fetch(`${baseUrl}${new URL(loc, baseUrl).pathname}`, { headers: { cookie: jar.header() }, redirect: 'manual' }));
  }

  async function signedLogin(): Promise<{ message: string; signature: string }> {
    const { nonce } = (await (await fetch(`${baseUrl}/siwe/challenge`)).json()) as { nonce: string };
    const now = new Date();
    const message = new SiweMessage({
      domain: new URL(baseUrl).host,
      address: account.address,
      statement: 'Sign in to Citrate',
      uri: baseUrl,
      version: '1',
      chainId: CITRATE_CHAIN_ID,
      nonce,
      issuedAt: now.toISOString(),
      expirationTime: new Date(now.getTime() + 6e5).toISOString(),
    }).prepareMessage();
    return { message, signature: await account.signMessage({ message }) };
  }

  for (const [label, headers] of [
    ['Origin', { origin: 'https://other.example' }],
    ['Sec-Fetch-Site', { 'sec-fetch-site': 'cross-site' }],
  ] as const) {
    it(`a cross-site request (${label}) is refused and does not log the interaction in`, async () => {
      const jar = new Jar();
      await startInteraction(jar);
      const res = await fetch(`${baseUrl}/siwe/verify`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', cookie: jar.header(), ...headers },
        body: JSON.stringify(await signedLogin()),
        redirect: 'manual',
      });
      expect(res.status).toBe(403);
      expect(((await res.json()) as { reason?: string }).reason).toBe('cross_site_forbidden');
    });
  }

  it('the same request from the authority origin resumes the interaction (control)', async () => {
    const jar = new Jar();
    await startInteraction(jar);
    const res = await fetch(`${baseUrl}/siwe/verify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: jar.header(), origin: baseUrl },
      body: JSON.stringify(await signedLogin()),
      redirect: 'manual',
    });
    expect(res.status).toBe(200);
    expect(((await res.json()) as { redirectTo?: string }).redirectTo).toBeTruthy();
  });
});

describe('mountSiweRoutes: direct token grant needs a first-party audience', () => {
  const fakeProvider = { use: () => undefined } as unknown as Provider;
  const base = { expectedDomain: 'auth.example', issuer: 'https://auth.example', signingJwk: {} as never };

  it('refuses to mount with an unregistered audience', () => {
    expect(() =>
      mountSiweRoutes(fakeProvider, { ...base, allowDirectTokenGrant: true, audience: 'unregistered-client' }),
    ).toThrow(/first-party client/);
  });

  it('mounts with a registered first-party audience, or with the grant off (control)', () => {
    expect(() => mountSiweRoutes(fakeProvider, { ...base, allowDirectTokenGrant: true, audience: 'citrate-explorer' })).not.toThrow();
    expect(() => mountSiweRoutes(fakeProvider, { ...base, audience: 'unregistered-client' })).not.toThrow();
  });
});

describe('GET /sessions/events concurrent stream cap', () => {
  it('refuses a stream over the cap with 503 and frees the slot when a stream closes', async () => {
    let mw: ((ctx: unknown, next: () => Promise<void>) => Promise<void>) | null = null;
    const provider = {
      use: (fn: typeof mw) => { mw = fn; },
      AccessToken: { find: async (t: string) => (t === 'good' ? { accountId: 'sub-1' } : undefined) },
    } as unknown as Provider;
    mountLogoutRoutes(provider, { maxSseConnections: 1, sseHeartbeatMs: 60_000 });

    const open = async () => {
      const req = Object.assign(new EventEmitter(), { headers: { authorization: 'Bearer good' } });
      const out = { status: 0 };
      const ctx = {
        method: 'GET',
        path: '/sessions/events',
        req,
        res: { writeHead: (s: number) => { out.status = s; }, write: () => true, end: () => undefined },
      };
      await mw!(ctx, async () => undefined);
      return { status: out.status, close: () => req.emit('close') };
    };

    const first = await open();
    expect(first.status).toBe(200);
    const second = await open();
    expect(second.status).toBe(503);
    first.close();
    const third = await open();
    expect(third.status).toBe(200);
    third.close();
  });
});
