/**
 * PBA-L3a-008 (MEDIUM) — POST /logout destroyed the session and the presented
 * access token but left the grant's REFRESH token alive; an email-proven
 * password reset ended neither the account's other sessions nor its refresh
 * tokens. Whoever held a stolen refresh token or session cookie kept access.
 *
 * Fix under test:
 *   - /logout revokes the whole grant behind the presented token (refresh
 *     tokens included); `{"everywhere": true}` ends every grant and session;
 *   - a password reset ends every earlier session and refresh token.
 */
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { createHash, randomBytes } from 'node:crypto';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { privateKeyToAccount } from 'viem/accounts';
import type { Hex } from 'viem';
import { SiweMessage } from 'siwe';
import { createProvider } from '../src/server.js';
import { CITRATE_CHAIN_ID } from '../src/siwe.js';
import { setUserStore, InMemoryUserStore } from '../src/auth/stores.js';
import { setEmailVerificationStore, InMemoryEmailVerificationStore } from '../src/auth/email-verification-pg.js';
import { setEmailSender, resetEmailSender } from '../src/email-send.js';
import { Jar } from './helpers/admin-session.js';

const REDIRECT = 'http://localhost:3001/auth/callback';
const b64u = (b: Buffer): string => b.toString('base64url');
let server: Server;
let baseUrl: string;
let lastCode: string | null = null;

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
  resetEmailSender();
  await new Promise<void>((r) => server.close(() => r()));
});
beforeEach(() => {
  setUserStore(new InMemoryUserStore());
  setEmailVerificationStore(new InMemoryEmailVerificationStore());
  lastCode = null;
  setEmailSender(async (msg) => { lastCode = /(\d{6})/.exec(msg.subject)?.[1] ?? null; return true; });
});

interface Tokens { access_token: string; refresh_token: string }

/** Start /auth; return the jar (interaction cookies) + PKCE verifier. */
async function startAuth(jar: Jar): Promise<{ verifier: string; interactionLoc: string | null; firstLoc: string }> {
  const verifier = b64u(randomBytes(32));
  const challenge = b64u(createHash('sha256').update(verifier).digest());
  const a = await fetch(
    `${baseUrl}/auth?response_type=code&client_id=citrate-explorer&redirect_uri=${encodeURIComponent(REDIRECT)}` +
      `&scope=${encodeURIComponent('openid offline_access')}&prompt=consent&code_challenge=${challenge}&code_challenge_method=S256&state=s`,
    { redirect: 'manual', headers: { cookie: jar.header() } },
  );
  jar.absorb(a);
  const loc = a.headers.get('location') ?? '';
  const isInteraction = loc.includes('/interaction/');
  if (isInteraction) jar.absorb(await fetch(`${baseUrl}${new URL(loc, baseUrl).pathname}`, { headers: { cookie: jar.header() }, redirect: 'manual' }));
  return { verifier, interactionLoc: isInteraction ? loc : null, firstLoc: loc };
}

/** Follow redirects until the RP callback; exchange the code. */
async function finish(jar: Jar, start: string, verifier: string): Promise<Tokens> {
  let next = start;
  for (let i = 0; i < 10 && !next.startsWith(REDIRECT); i++) {
    const h = await fetch(next.startsWith('http') ? next : baseUrl + next, { headers: { cookie: jar.header() }, redirect: 'manual' });
    jar.absorb(h);
    next = h.headers.get('location') ?? '';
  }
  const code = new URL(next).searchParams.get('code')!;
  const t = await fetch(`${baseUrl}/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'authorization_code', code, client_id: 'citrate-explorer', redirect_uri: REDIRECT, code_verifier: verifier }).toString(),
  });
  const j = (await t.json()) as Tokens;
  expect(j.refresh_token, 'refresh token issued').toBeTruthy();
  return j;
}

async function siweTokens(pk: Hex, jar = new Jar()): Promise<{ tokens: Tokens; jar: Jar }> {
  const acct = privateKeyToAccount(pk);
  const { verifier } = await startAuth(jar);
  const { nonce } = (await (await fetch(`${baseUrl}/siwe/challenge`)).json()) as { nonce: string };
  const now = new Date();
  const message = new SiweMessage({ domain: new URL(baseUrl).host, address: acct.address, statement: 'Sign in to Citrate', uri: baseUrl, version: '1', chainId: CITRATE_CHAIN_ID, nonce, issuedAt: now.toISOString(), expirationTime: new Date(now.getTime() + 6e5).toISOString() }).prepareMessage();
  const v = await fetch(`${baseUrl}/siwe/verify`, { method: 'POST', headers: { 'content-type': 'application/json', cookie: jar.header() }, body: JSON.stringify({ message, signature: await acct.signMessage({ message }) }) });
  jar.absorb(v);
  return { tokens: await finish(jar, ((await v.json()) as { redirectTo: string }).redirectTo, verifier), jar };
}

async function passwordTokens(email: string, password: string, jar = new Jar()): Promise<{ tokens: Tokens; jar: Jar }> {
  const { verifier } = await startAuth(jar);
  const post = (path: string, body: unknown) => fetch(`${baseUrl}${path}`, { method: 'POST', headers: { 'content-type': 'application/json', cookie: jar.header() }, body: JSON.stringify(body) });
  const login = await post('/auth/password/login', { email, password });
  let body = (await login.json()) as { redirectTo?: string; status?: string };
  if (body.status === 'verification_required') {
    const v = await post('/auth/password/verify', { email, code: lastCode });
    jar.absorb(v);
    body = (await v.json()) as { redirectTo?: string };
  } else {
    jar.absorb(login);
  }
  return { tokens: await finish(jar, body.redirectTo!, verifier), jar };
}

/**
 * Does this browser still have a live SSO session? A plain /auth (no prompt)
 * for the trusted explorer client is answered without an interaction only when
 * a valid session exists.
 */
async function hasLiveSession(jar: Jar): Promise<boolean> {
  const ch = b64u(createHash('sha256').update(b64u(randomBytes(32))).digest());
  let next = `${baseUrl}/auth?response_type=code&client_id=citrate-explorer&redirect_uri=${encodeURIComponent(REDIRECT)}&scope=openid&code_challenge=${ch}&code_challenge_method=S256&state=s`;
  for (let i = 0; i < 10; i++) {
    const r = await fetch(next, { headers: { cookie: jar.header() }, redirect: 'manual' });
    const loc = r.headers.get('location') ?? '';
    if (loc.startsWith(REDIRECT)) return new URL(loc).searchParams.has('code');
    if (loc.includes('/interaction/') || !loc) return false;
    next = loc.startsWith('http') ? loc : baseUrl + loc;
  }
  return false;
}

const refresh = (rt: string) =>
  fetch(`${baseUrl}/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: rt, client_id: 'citrate-explorer' }).toString(),
  });
const logout = (at: string, body?: unknown) =>
  fetch(`${baseUrl}/logout`, { method: 'POST', headers: { authorization: `Bearer ${at}`, ...(body ? { 'content-type': 'application/json' } : {}) }, ...(body ? { body: JSON.stringify(body) } : {}) });

describe('PBA-L3a-008 logout revokes the refresh token', () => {
  it('after POST /logout the grant\'s refresh token no longer works', async () => {
    const { tokens } = await siweTokens(`0x${'b1'.repeat(32)}`);
    const out = await logout(tokens.access_token);
    expect(out.status).toBe(200);
    expect(await out.json()).not.toHaveProperty('everywhere');
    const r = await refresh(tokens.refresh_token);
    expect(r.status).toBe(400);
    expect(((await r.json()) as { error: string }).error).toBe('invalid_grant');
  });

  it('logout {everywhere:true} also ends the account\'s OTHER grants', async () => {
    const pk = `0x${'b2'.repeat(32)}` as Hex;
    const a = await siweTokens(pk);
    const b = await siweTokens(pk);
    const out = await logout(a.tokens.access_token, { everywhere: true });
    expect(out.status).toBe(200);
    expect(await out.json()).toMatchObject({ ok: true, everywhere: true });
    expect((await refresh(b.tokens.refresh_token)).status).toBe(400);
    // ...but it is not a permanent lock-out: a login in a LATER second works.
    await new Promise((r) => setTimeout(r, 2100));
    const c = await siweTokens(pk);
    expect((await refresh(c.tokens.refresh_token)).status).toBe(200);
  });

  it('?everywhere=1 is accepted; a non-JSON or non-boolean body is a plain logout', async () => {
    const pk = `0x${'b4'.repeat(32)}` as Hex;
    const a = await siweTokens(pk);
    const b = await siweTokens(pk);
    const plain1 = await fetch(`${baseUrl}/logout`, { method: 'POST', headers: { authorization: `Bearer ${a.tokens.access_token}`, 'content-type': 'text/plain' }, body: '{"everywhere":true}' });
    expect(await plain1.json()).not.toHaveProperty('everywhere');
    expect((await refresh(b.tokens.refresh_token)).status).toBe(200);
    const c = await siweTokens(pk);
    const plain2 = await logout(c.tokens.access_token, { everywhere: 'yes' });
    expect(await plain2.json()).not.toHaveProperty('everywhere');
    const d = await siweTokens(pk);
    const e = await siweTokens(pk);
    const q = await fetch(`${baseUrl}/logout?everywhere=1`, { method: 'POST', headers: { authorization: `Bearer ${d.tokens.access_token}` } });
    expect(await q.json()).toMatchObject({ everywhere: true });
    expect((await refresh(e.tokens.refresh_token)).status).toBe(400);
  });

  it('a plain logout leaves the account\'s other grants alone', async () => {
    const pk = `0x${'b3'.repeat(32)}` as Hex;
    const a = await siweTokens(pk);
    const b = await siweTokens(pk);
    expect((await logout(a.tokens.access_token)).status).toBe(200);
    expect((await refresh(b.tokens.refresh_token)).status).toBe(200);
  });
});

describe('PBA-L3a-008 password reset ends earlier sessions and refresh tokens', () => {
  it('a reset invalidates the old refresh token and forces the old browser session to sign in again', async () => {
    const email = 'reset@example.com';
    // Account + an existing logged-in browser (the "stolen" session/refresh token).
    const reg = new Jar();
    await startAuth(reg);
    await fetch(`${baseUrl}/auth/password/register`, { method: 'POST', headers: { 'content-type': 'application/json', cookie: reg.header() }, body: JSON.stringify({ email, password: 'original password 123' }) });
    const old = await passwordTokens(email, 'original password 123');
    expect(await hasLiveSession(old.jar)).toBe(true);
    // Owner resets the password from another browser (email-proven).
    await new Promise((r) => setTimeout(r, 1100)); // epoch is second-granular
    const resetJar = new Jar();
    const st = await startAuth(resetJar);
    const post = (path: string, body: unknown) => fetch(`${baseUrl}${path}`, { method: 'POST', headers: { 'content-type': 'application/json', cookie: resetJar.header() }, body: JSON.stringify(body) });
    await post('/auth/password/register', { email, password: 'brand new password 456' });
    const v = await post('/auth/password/verify', { email, code: lastCode });
    expect(v.status).toBe(200);
    resetJar.absorb(v);
    await finish(resetJar, ((await v.json()) as { redirectTo: string }).redirectTo, st.verifier);

    // The pre-reset refresh token is dead.
    const r = await refresh(old.tokens.refresh_token);
    expect(r.status).toBe(400);
    // The pre-reset browser session no longer silently signs in.
    expect(await hasLiveSession(old.jar)).toBe(false);
    // The resetting browser's own new session is unaffected.
    expect(await hasLiveSession(resetJar)).toBe(true);
  });
});
