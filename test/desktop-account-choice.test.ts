import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { createHash, randomBytes } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { privateKeyToAccount } from 'viem/accounts';
import { type Hex } from 'viem';
import { SiweMessage } from 'siwe';
import { decodeJwt } from 'jose';
import { createProvider } from '../src/server.js';
import { CITRATE_CHAIN_ID } from '../src/siwe.js';

/**
 * Desktop sign-in must let the member choose the account.
 *
 * Citrate Core signs in through the system browser. Signing out of the app
 * revokes its refresh token, but the browser keeps its auth.citrate.ai
 * session, so a plain /auth request used to complete silently as the SAME
 * account — a member could never sign in as anyone else. For the desktop
 * client every authorization request now shows the sign-in page even when a
 * browser session exists; signing in there (as the same or a different
 * account) completes the request. Web RPs keep single sign-on.
 */

let server: Server;
let baseUrl: string;
let host: string;
const alice = privateKeyToAccount(`0x${'a1'.repeat(32)}` as Hex);
const bob = privateKeyToAccount(`0x${'b2'.repeat(32)}` as Hex);

const CORE = { clientId: 'citrate-core', redirectUri: 'http://127.0.0.1:53111/auth/callback' };
const WEB = { clientId: 'citrate-explorer', redirectUri: 'http://localhost:3001/auth/callback' };

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
});

afterAll(async () => {
  await new Promise<void>((res, rej) =>
    server.close((err) => (err ? rej(err) : res())),
  );
});

type Signer = typeof alice;
type Client = { clientId: string; redirectUri: string };

/** Start /auth with the browser's cookies; return the first redirect target. */
async function startAuth(jar: CookieJar, client: Client) {
  const codeVerifier = base64url(randomBytes(32));
  const codeChallenge = base64url(createHash('sha256').update(codeVerifier).digest());
  const authUrl =
    `${baseUrl}/auth?response_type=code&client_id=${encodeURIComponent(client.clientId)}` +
    `&redirect_uri=${encodeURIComponent(client.redirectUri)}` +
    `&scope=${encodeURIComponent('openid profile wallet')}` +
    `&code_challenge=${codeChallenge}&code_challenge_method=S256&state=${base64url(randomBytes(16))}`;
  const res = await fetch(authUrl, { headers: { cookie: jar.header() }, redirect: 'manual' });
  jar.absorb(res);
  return { location: res.headers.get('location')!, codeVerifier };
}

/**
 * Follow redirects until the client callback (returns the code) or a rendered
 * sign-in page (returns `{ signInPage: true }`). Auto-consent 303s are followed.
 */
async function follow(jar: CookieJar, client: Client, location: string) {
  for (let hop = 0; hop < 12; hop++) {
    const url = location.startsWith('http') ? location : `${baseUrl}${location}`;
    if (url.startsWith(client.redirectUri)) {
      return { code: new URL(url).searchParams.get('code')!, signInPage: false };
    }
    const res = await fetch(url, { headers: { cookie: jar.header() }, redirect: 'manual' });
    jar.absorb(res);
    if (res.status === 200) return { code: undefined, signInPage: true };
    expect(res.status).toBe(303);
    location = res.headers.get('location')!;
  }
  throw new Error('redirect chain did not end');
}

/** Complete the rendered sign-in page with a SIWE signature from `who`. */
async function signInOnPage(jar: CookieJar, who: Signer): Promise<string> {
  const challengeRes = await fetch(`${baseUrl}/siwe/challenge`, { headers: { cookie: jar.header() } });
  jar.absorb(challengeRes);
  const { nonce } = (await challengeRes.json()) as { nonce: string };
  const issuedAt = new Date();
  const message = new SiweMessage({
    domain: host,
    address: who.address,
    statement: 'Sign in to Citrate',
    uri: baseUrl,
    version: '1',
    chainId: CITRATE_CHAIN_ID,
    nonce,
    issuedAt: issuedAt.toISOString(),
    expirationTime: new Date(issuedAt.getTime() + 10 * 60 * 1000).toISOString(),
  }).prepareMessage();
  const signature = await who.signMessage({ message });
  const verifyRes = await fetch(`${baseUrl}/siwe/verify`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie: jar.header() },
    body: JSON.stringify({ message, signature }),
  });
  jar.absorb(verifyRes);
  return ((await verifyRes.json()) as { redirectTo: string }).redirectTo;
}

async function walletOf(client: Client, code: string, codeVerifier: string): Promise<string> {
  const tokenRes = await fetch(`${baseUrl}/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      client_id: client.clientId,
      redirect_uri: client.redirectUri,
      code_verifier: codeVerifier,
    }).toString(),
  });
  expect(tokenRes.status).toBe(200);
  const { id_token } = (await tokenRes.json()) as { id_token: string };
  return String(decodeJwt(id_token).wallet_address);
}

/** A browser that already holds an auth.citrate.ai session for `who`. */
async function browserSignedInAs(who: Signer): Promise<CookieJar> {
  const jar = new CookieJar();
  const { location, codeVerifier } = await startAuth(jar, WEB);
  const first = await follow(jar, WEB, location);
  expect(first.signInPage).toBe(true);
  const done = await follow(jar, WEB, await signInOnPage(jar, who));
  expect(await walletOf(WEB, done.code!, codeVerifier)).toBe(who.address);
  return jar;
}

describe('desktop sign-in shows the sign-in page even with a browser session', () => {
  it('does not complete silently as the browser session account', async () => {
    const jar = await browserSignedInAs(alice);
    const { location } = await startAuth(jar, CORE);
    const r = await follow(jar, CORE, location);
    expect(r.signInPage).toBe(true);
    expect(r.code).toBeUndefined();
  });

  it('lets the member sign in as a different account from that page', async () => {
    const jar = await browserSignedInAs(alice);
    const { location, codeVerifier } = await startAuth(jar, CORE);
    expect((await follow(jar, CORE, location)).signInPage).toBe(true);
    const done = await follow(jar, CORE, await signInOnPage(jar, bob));
    expect(await walletOf(CORE, done.code!, codeVerifier)).toBe(bob.address);
  });

  it('still lets the member continue as the same account', async () => {
    const jar = await browserSignedInAs(alice);
    const { location, codeVerifier } = await startAuth(jar, CORE);
    expect((await follow(jar, CORE, location)).signInPage).toBe(true);
    const done = await follow(jar, CORE, await signInOnPage(jar, alice));
    expect(await walletOf(CORE, done.code!, codeVerifier)).toBe(alice.address);
  });

  it('keeps single sign-on for web apps (no extra sign-in page)', async () => {
    const jar = await browserSignedInAs(alice);
    const { location, codeVerifier } = await startAuth(jar, WEB);
    const r = await follow(jar, WEB, location);
    expect(r.signInPage).toBe(false);
    expect(await walletOf(WEB, r.code!, codeVerifier)).toBe(alice.address);
  });
});
