/**
 * Authenticated hand-off (item 2, backend work order 2026-08-06).
 *
 * The desktop app cannot present its OIDC session to a browser navigation, so it
 * mints a subject-bound single-use nonce at `POST /kyc/handoff` and opens
 * `/kyc/start?handoff=<nonce>` / `/account?handoff=<nonce>`. Those surfaces resolve
 * the subject from the NONCE, not the browser cookie — the whole point being that
 * the page opens for the app's user regardless of which account the browser holds.
 *
 * Covered (spec §4 acceptance):
 *   - store: issue → consume once; replay / unknown / expired → null
 *   - #1 browser is A, hand-off is for B → the page opens for B (never A)
 *   - #2 no browser session, hand-off for B → opens for B, no 401
 *   - #3 a nonce is single-use: the replay fails
 *   - #4 an expired nonce fails closed
 *   - #5 no `handoff` param → cookie behaviour unchanged
 *   - mint: no/invalid token → 401; GET → 405; valid token → a handoff URL
 */
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { createHash, randomBytes } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createProvider } from '../src/server.js';
import { armEmailCapture, lastVerificationCode } from './helpers/verify.js';
import { InMemoryHandoffStore } from '../src/handoff-store.js';
import {
  setUserStore,
  setWebAuthnStore,
  InMemoryUserStore,
  InMemoryWebAuthnCredentialStore,
} from '../src/auth/stores.js';

const EXPLORER_REDIRECT = 'http://localhost:3001/auth/callback';
const b64url = (b: Buffer) =>
  b.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

class CookieJar {
  private readonly jar = new Map<string, string>();
  absorb(res: Response): void {
    const set =
      typeof (res.headers as Headers & { getSetCookie?: () => string[] }).getSetCookie === 'function'
        ? (res.headers as Headers & { getSetCookie: () => string[] }).getSetCookie()
        : [];
    for (const sc of set) {
      const [pair] = sc.split(';');
      const eq = pair.indexOf('=');
      if (eq === -1) continue;
      const k = pair.slice(0, eq).trim();
      const v = pair.slice(eq + 1).trim();
      if (v === '' || v === 'undefined') this.jar.delete(k);
      else this.jar.set(k, v);
    }
  }
  header(): string {
    return Array.from(this.jar.entries()).map(([k, v]) => `${k}=${v}`).join('; ');
  }
}

let server: Server;
let baseUrl: string;
let handoffStore: InMemoryHandoffStore;
let userStore: InMemoryUserStore;

/**
 * Full PKCE + email/password sign-up + token exchange → an opaque access token
 * for a fresh UUID-keyed user. Returns the token, the user's account id (sub), and
 * the sign-in cookie jar (a live browser session for that same user).
 */
async function signUpAndToken(
  email: string,
): Promise<{ token: string; sub: string; jar: CookieJar }> {
  const jar = new CookieJar();
  const verifier = b64url(randomBytes(32));
  const challenge = b64url(createHash('sha256').update(verifier).digest());
  const authUrl =
    `${baseUrl}/auth?response_type=code&client_id=citrate-explorer` +
    `&redirect_uri=${encodeURIComponent(EXPLORER_REDIRECT)}` +
    `&scope=${encodeURIComponent('openid profile wallet kyc')}` +
    `&code_challenge=${challenge}&code_challenge_method=S256&state=${b64url(randomBytes(8))}`;
  const authRes = await fetch(authUrl, { headers: { cookie: jar.header() }, redirect: 'manual' });
  jar.absorb(authRes);
  const loc = authRes.headers.get('location');
  if (loc) {
    const view = await fetch(`${baseUrl}${new URL(loc, baseUrl).pathname}`, {
      headers: { cookie: jar.header() },
      redirect: 'manual',
    });
    jar.absorb(view);
  }

  armEmailCapture();
  const reg = await fetch(`${baseUrl}/auth/password/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie: jar.header() },
    body: JSON.stringify({ email, password: 'correct-horse-battery' }),
    redirect: 'manual',
  });
  jar.absorb(reg);
  // FWA #87.1: register no longer signs in — verify the emailed code.
  const ver = await fetch(`${baseUrl}/auth/password/verify`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie: jar.header() },
    body: JSON.stringify({ email, code: lastVerificationCode() }),
    redirect: 'manual',
  });
  jar.absorb(ver);

  let location: string | null = ((await ver.json()) as { redirectTo: string }).redirectTo;
  let code = '';
  for (let hop = 0; hop < 12 && location; hop++) {
    const url = location.startsWith('http') ? location : `${baseUrl}${location}`;
    if (url.startsWith(EXPLORER_REDIRECT)) {
      code = new URL(url).searchParams.get('code') ?? '';
      break;
    }
    const res = await fetch(url, { headers: { cookie: jar.header() }, redirect: 'manual' });
    jar.absorb(res);
    location = res.headers.get('location');
  }

  const tokenRes = await fetch(`${baseUrl}/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      client_id: 'citrate-explorer',
      redirect_uri: EXPLORER_REDIRECT,
      code_verifier: verifier,
    }).toString(),
  });
  const tokenJson = (await tokenRes.json()) as { access_token?: string };
  const token = tokenJson.access_token ?? '';
  const rec = await userStore.findByEmail(email);
  return { token, sub: rec!.id, jar };
}

beforeAll(async () => {
  userStore = new InMemoryUserStore();
  setUserStore(userStore);
  setWebAuthnStore(new InMemoryWebAuthnCredentialStore());
  handoffStore = new InMemoryHandoffStore();
  const probe = createServer();
  await new Promise<void>((res) => probe.listen(0, '127.0.0.1', res));
  const { port } = probe.address() as AddressInfo;
  probe.close();
  baseUrl = `http://127.0.0.1:${port}`;
  const provider = await createProvider(baseUrl, { googleEnabled: false, handoffStore });
  server = createServer(provider.callback());
  await new Promise<void>((res) => server.listen(port, '127.0.0.1', res));
});
afterAll(async () => {
  await new Promise<void>((res, rej) => server.close((e) => (e ? rej(e) : res())));
});

describe('InMemoryHandoffStore', () => {
  it('issues a nonce that consumes exactly once (replay → null)', async () => {
    const store = new InMemoryHandoffStore();
    const nonce = await store.issue('sub-abc');
    expect(await store.consume(nonce)).toBe('sub-abc');
    expect(await store.consume(nonce)).toBeNull(); // #3 single-use
  });
  it('returns null for an unknown nonce', async () => {
    const store = new InMemoryHandoffStore();
    expect(await store.consume('never-issued')).toBeNull();
  });
  it('fails closed on an expired nonce (#4)', async () => {
    const store = new InMemoryHandoffStore(-1); // already expired on issue
    const nonce = await store.issue('sub-xyz');
    expect(await store.consume(nonce)).toBeNull();
  });
});

describe('POST /kyc/handoff (mint)', () => {
  it('401s without a Bearer token', async () => {
    const res = await fetch(`${baseUrl}/kyc/handoff`, { method: 'POST' });
    expect(res.status).toBe(401);
  });
  it('401s with an invalid token', async () => {
    const res = await fetch(`${baseUrl}/kyc/handoff`, {
      method: 'POST',
      headers: { authorization: 'Bearer not-a-real-token' },
    });
    expect(res.status).toBe(401);
  });
  it('405s on GET', async () => {
    const res = await fetch(`${baseUrl}/kyc/handoff`, { method: 'GET' });
    expect(res.status).toBe(405);
  });
  it('mints a /kyc/start hand-off URL for a valid token', async () => {
    const { token } = await signUpAndToken('minter@example.com');
    expect(token).not.toBe('');
    const res = await fetch(`${baseUrl}/kyc/handoff`, {
      method: 'POST',
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      body: JSON.stringify({ level: 'T3' }),
    });
    expect(res.status).toBe(200);
    const { url } = (await res.json()) as { url: string };
    expect(url).toContain('/kyc/start?handoff=');
    expect(url).toContain('level=T3');
  });
});

describe('hand-off consumption binds the page to the nonce subject, not the cookie', () => {
  it('#2 no browser session, hand-off for B → /account opens for B (no 401)', async () => {
    const { sub } = await signUpAndToken('bravo@example.com');
    const nonce = await handoffStore.issue(sub);
    const res = await fetch(`${baseUrl}/account?handoff=${nonce}`, { redirect: 'manual' });
    expect(res.status).toBe(200);
    expect(await res.text()).toContain('bravo@example.com');
  });

  it('#1 browser is A, hand-off is for B → /account opens for B, never A', async () => {
    const a = await signUpAndToken('alpha-admin@example.com');
    const b = await signUpAndToken('bravo-member@example.com');
    const nonce = await handoffStore.issue(b.sub);
    // The browser carries A's live session cookie; the hand-off is for B.
    const res = await fetch(`${baseUrl}/account?handoff=${nonce}`, {
      headers: { cookie: a.jar.header() },
      redirect: 'manual',
    });
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain('bravo-member@example.com'); // opens for B
    expect(html).not.toContain('alpha-admin@example.com'); // never A
  });

  it('#3 the nonce is single-use: the replay no longer binds', async () => {
    const { sub } = await signUpAndToken('charlie@example.com');
    const nonce = await handoffStore.issue(sub);
    const first = await fetch(`${baseUrl}/account?handoff=${nonce}`, { redirect: 'manual' });
    expect(await first.text()).toContain('charlie@example.com');
    // Replay: nonce is gone → no binding → the signed-out hub.
    const replay = await fetch(`${baseUrl}/account?handoff=${nonce}`, { redirect: 'manual' });
    expect(await replay.text()).toContain('Sign in through any Citrate app');
  });

  it('#4 /kyc/start with an invalid hand-off fails closed (401), never the cookie', async () => {
    const a = await signUpAndToken('delta@example.com');
    // A valid cookie session is present, but a bogus handoff must NOT fall back to it.
    const res = await fetch(`${baseUrl}/kyc/start?handoff=bogus-nonce&level=T3`, {
      headers: { cookie: a.jar.header() },
      redirect: 'manual',
    });
    expect(res.status).toBe(401);
    expect(await res.text()).toContain('invalid_handoff');
  });

  it('a valid hand-off passes /kyc/start auth (reaches the KYC provider, not 401)', async () => {
    const { sub } = await signUpAndToken('echo@example.com');
    const nonce = await handoffStore.issue(sub);
    const res = await fetch(`${baseUrl}/kyc/start?handoff=${nonce}&level=T3`, { redirect: 'manual' });
    // KYC_PROVIDER is unset in tests, so a successful auth lands on 503
    // kyc_unconfigured — decisively past the 401 auth gate.
    expect(res.status).toBe(503);
  });

  it('#5 no handoff param → unchanged cookie behaviour (signed-out render)', async () => {
    const res = await fetch(`${baseUrl}/account`, { redirect: 'manual' });
    expect(res.status).toBe(200);
    expect(await res.text()).toContain('Sign in through any Citrate app');
  });
});
