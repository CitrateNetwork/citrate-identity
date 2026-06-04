import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { createHash, randomBytes } from 'node:crypto';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { privateKeyToAccount } from 'viem/accounts';
import { type Hex } from 'viem';
import { SiweMessage } from 'siwe';
import { createProvider } from '../src/server.js';
import { CITRATE_CHAIN_ID } from '../src/siwe.js';
import {
  SessionBus,
  getSessionBus,
  setSessionBus,
  type SessionEvent,
} from '../src/session-bus.js';

/**
 * IDP-S2 / TD-5 (authority side) — logout + token revocation + session-bus cascade.
 *
 *   gtm-spine/features/IDP-S2-revocation-and-logout-cascade.feature
 *     Scenario: revocation invalidates a token immediately
 *     Scenario: logout in one app cascades to the others
 *
 * We drive the REAL Authorization-Code + PKCE + SIWE login (exactly like
 * explorer-rp.test.ts) to obtain a genuine access token, then:
 *   - POST /logout publishes a `logout` event on the bus for the right `sub`,
 *   - the SAME token is afterwards inactive (introspection → active:false; the
 *     userinfo endpoint 401s),
 *   - the SSE endpoint /sessions/events emits the event to a connected client,
 *   - /logout with no token fails closed (401).
 */

let server: Server;
let baseUrl: string;
let host: string;
let userinfoEndpoint: string;
let introspectionEndpoint: string;
const account = privateKeyToAccount(`0x${'d5'.repeat(32)}` as Hex);

const EXPLORER_REDIRECT = 'http://localhost:3001/auth/callback';

class CookieJar {
  private readonly jar = new Map<string, string>();
  absorb(res: Response): void {
    const setCookies =
      typeof (res.headers as Headers & { getSetCookie?: () => string[] })
        .getSetCookie === 'function'
        ? (res.headers as Headers & { getSetCookie: () => string[] }).getSetCookie()
        : [];
    for (const sc of setCookies) {
      const [pair] = sc.split(';');
      const eq = pair.indexOf('=');
      if (eq === -1) continue;
      const name = pair.slice(0, eq).trim();
      const value = pair.slice(eq + 1).trim();
      if (value === '' || value === 'undefined') this.jar.delete(name);
      else this.jar.set(name, value);
    }
  }
  header(): string {
    return Array.from(this.jar.entries())
      .map(([k, v]) => `${k}=${v}`)
      .join('; ');
  }
}

function base64url(buf: Buffer): string {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

beforeAll(async () => {
  const probe = createServer();
  await new Promise<void>((res) => probe.listen(0, '127.0.0.1', res));
  const { port } = probe.address() as AddressInfo;
  probe.close();

  baseUrl = `http://127.0.0.1:${port}`;
  host = `127.0.0.1:${port}`;
  const provider = await createProvider(baseUrl);
  server = createServer(provider.callback());
  await new Promise<void>((res) => server.listen(port, '127.0.0.1', res));

  const discovery = await fetch(`${baseUrl}/.well-known/openid-configuration`);
  const doc = (await discovery.json()) as {
    userinfo_endpoint: string;
    introspection_endpoint: string;
  };
  userinfoEndpoint = doc.userinfo_endpoint;
  introspectionEndpoint = doc.introspection_endpoint;
});

afterAll(async () => {
  await new Promise<void>((res, rej) =>
    server.close((err) => (err ? rej(err) : res())),
  );
});

afterEach(() => {
  // Fresh bus per test so published events don't leak across cases.
  setSessionBus(new SessionBus());
});

/** Drive the full Authorization-Code + PKCE + SIWE login → a real access token. */
async function loginForAccessToken(): Promise<string> {
  const jar = new CookieJar();
  const codeVerifier = base64url(randomBytes(32));
  const codeChallenge = base64url(createHash('sha256').update(codeVerifier).digest());
  const state = base64url(randomBytes(16));

  const authUrl =
    `${baseUrl}/auth?response_type=code&client_id=citrate-explorer` +
    `&redirect_uri=${encodeURIComponent(EXPLORER_REDIRECT)}` +
    `&scope=${encodeURIComponent('openid wallet')}` +
    `&code_challenge=${codeChallenge}&code_challenge_method=S256` +
    `&state=${state}`;
  const authRes = await fetch(authUrl, { redirect: 'manual' });
  jar.absorb(authRes);
  expect(authRes.status).toBe(303);
  const interactionLoc = authRes.headers.get('location')!;

  const interactionUrl = interactionLoc.startsWith('http')
    ? interactionLoc
    : `${baseUrl}${interactionLoc}`;
  const viewRes = await fetch(interactionUrl, {
    headers: { cookie: jar.header() },
    redirect: 'manual',
  });
  jar.absorb(viewRes);

  const challengeRes = await fetch(`${baseUrl}/siwe/challenge`, {
    headers: { cookie: jar.header() },
  });
  jar.absorb(challengeRes);
  const { nonce } = (await challengeRes.json()) as { nonce: string };

  const issuedAt = new Date();
  const expirationTime = new Date(issuedAt.getTime() + 10 * 60 * 1000);
  const siwe = new SiweMessage({
    domain: host,
    address: account.address,
    statement: 'Sign in to Citrate',
    uri: baseUrl,
    version: '1',
    chainId: CITRATE_CHAIN_ID,
    nonce,
    issuedAt: issuedAt.toISOString(),
    expirationTime: expirationTime.toISOString(),
  });
  const message = siwe.prepareMessage();
  const signature = await account.signMessage({ message });

  const verifyRes = await fetch(`${baseUrl}/siwe/verify`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie: jar.header() },
    body: JSON.stringify({ message, signature }),
  });
  jar.absorb(verifyRes);
  const verifyJson = (await verifyRes.json()) as { redirectTo?: string };

  let location = verifyJson.redirectTo!;
  let callbackLoc: string | undefined;
  for (let hop = 0; hop < 10; hop++) {
    const url = location.startsWith('http') ? location : `${baseUrl}${location}`;
    if (url.startsWith(EXPLORER_REDIRECT)) {
      callbackLoc = url;
      break;
    }
    const hopRes = await fetch(url, { headers: { cookie: jar.header() }, redirect: 'manual' });
    jar.absorb(hopRes);
    expect(hopRes.status).toBe(303);
    location = hopRes.headers.get('location')!;
  }
  const code = new URL(callbackLoc!).searchParams.get('code')!;

  const tokenRes = await fetch(`${baseUrl}/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      client_id: 'citrate-explorer',
      redirect_uri: EXPLORER_REDIRECT,
      code_verifier: codeVerifier,
    }).toString(),
  });
  expect(tokenRes.status).toBe(200);
  const tokenJson = (await tokenRes.json()) as { access_token?: string };
  expect(typeof tokenJson.access_token).toBe('string');
  return tokenJson.access_token!;
}

/** Ask the authority whether a token is active (public client introspection). */
async function introspect(token: string): Promise<{ active: boolean }> {
  const res = await fetch(introspectionEndpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ token, client_id: 'citrate-explorer' }).toString(),
  });
  expect(res.status).toBe(200);
  return (await res.json()) as { active: boolean };
}

async function logout(token: string | null): Promise<Response> {
  const headers: Record<string, string> = {};
  if (token !== null) headers.authorization = `Bearer ${token}`;
  return fetch(`${baseUrl}/logout`, { method: 'POST', headers });
}

describe('IDP-S2 — logout, revocation, and session-bus cascade (TD-5)', () => {
  it('POST /logout publishes a logout event on the session bus for the right sub', async () => {
    const token = await loginForAccessToken();

    const received: SessionEvent[] = [];
    const unsubscribe = getSessionBus().subscribe((e) => received.push(e));

    const res = await logout(token);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { ok: boolean; sub: string };
    expect(body.ok).toBe(true);
    expect(body.sub).toBe(account.address);

    unsubscribe();
    expect(received).toHaveLength(1);
    expect(received[0].type).toBe('logout');
    expect(received[0].sub).toBe(account.address);
    expect(typeof received[0].at).toBe('number');
  });

  it('after /logout the token is REVOKED (introspection inactive + userinfo 401)', async () => {
    const token = await loginForAccessToken();

    // Active before logout.
    expect((await introspect(token)).active).toBe(true);
    const before = await fetch(userinfoEndpoint, {
      headers: { authorization: `Bearer ${token}` },
    });
    expect(before.status).toBe(200);

    const res = await logout(token);
    expect(res.status).toBe(200);

    // Inactive after logout — the SAME token is now dead.
    expect((await introspect(token)).active).toBe(false);
    const after = await fetch(userinfoEndpoint, {
      headers: { authorization: `Bearer ${token}` },
    });
    expect(after.status).toBe(401);
  });

  it('GET /sessions/events (SSE) emits the logout event to a connected client', async () => {
    const token = await loginForAccessToken();

    // Open the SSE stream. We read the body as a stream and resolve when the
    // logout event frame arrives. An AbortController tears the connection down.
    const ac = new AbortController();
    const sseRes = await fetch(`${baseUrl}/sessions/events`, {
      headers: { accept: 'text/event-stream' },
      signal: ac.signal,
    });
    expect(sseRes.status).toBe(200);
    expect(sseRes.headers.get('content-type')).toContain('text/event-stream');

    const reader = sseRes.body!.getReader();
    const decoder = new TextDecoder();

    const eventArrived = (async (): Promise<string> => {
      let buffer = '';
      for (;;) {
        const { value, done } = await reader.read();
        if (done) return buffer;
        buffer += decoder.decode(value, { stream: true });
        if (buffer.includes('event: logout')) return buffer;
      }
    })();

    // Give the stream a tick to register its subscription, then log out.
    await new Promise((r) => setTimeout(r, 50));
    const res = await logout(token);
    expect(res.status).toBe(200);

    const frame = await Promise.race([
      eventArrived,
      new Promise<string>((_, rej) =>
        setTimeout(() => rej(new Error('SSE event did not arrive in time')), 3000),
      ),
    ]);

    expect(frame).toContain('event: logout');
    expect(frame).toContain('"type":"logout"');
    expect(frame).toContain(account.address);

    ac.abort();
    await reader.cancel().catch(() => {});
  });

  it('POST /logout with NO token fails closed (401) and publishes nothing', async () => {
    const received: SessionEvent[] = [];
    const unsubscribe = getSessionBus().subscribe((e) => received.push(e));

    const res = await logout(null);
    expect(res.status).toBe(401);

    unsubscribe();
    expect(received).toHaveLength(0);
  });

  it('POST /logout with a garbage token fails closed (401)', async () => {
    const res = await logout('not-a-real-access-token');
    expect(res.status).toBe(401);
  });
});

describe('SessionBus (unit)', () => {
  it('publish delivers to all subscribers with the supplied sub', () => {
    const bus = new SessionBus();
    const a: SessionEvent[] = [];
    const b: SessionEvent[] = [];
    const offA = bus.subscribe((e) => a.push(e));
    bus.subscribe((e) => b.push(e));
    bus.publish('0xWALLET', { type: 'logout', sid: 'sid-1', at: 123 });
    expect(a).toEqual([{ type: 'logout', sub: '0xWALLET', sid: 'sid-1', at: 123 }]);
    expect(b).toEqual([{ type: 'logout', sub: '0xWALLET', sid: 'sid-1', at: 123 }]);
    // After unsubscribing, A no longer receives.
    offA();
    bus.publish('0xWALLET2', { type: 'logout', at: 456 });
    expect(a).toHaveLength(1);
    expect(b).toHaveLength(2);
  });
});
