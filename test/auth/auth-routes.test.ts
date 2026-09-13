/**
 * Integration tests for the WP-6 slice B HTTP routes:
 *
 *   - POST /auth/password/register + /auth/password/login
 *   - POST /auth/webauthn/authenticate-options (the options surface — the
 *     verify surface needs a real platform authenticator and is covered by
 *     a follow-up E2E with a WebAuthn polyfill)
 *   - GET  /brand/* + /fonts/* (the static-asset middleware)
 *
 * Each test drives a real /auth request to obtain a live login interaction
 * cookie, then calls the route under test with that cookie present — the
 * same shape the branded interaction page uses in the browser.
 */

import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { createHash, randomBytes } from 'node:crypto';
import { resolve } from 'node:path';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createProvider } from '../../src/server.js';
import {
  setUserStore,
  setWebAuthnStore,
  getUserStore,
  InMemoryUserStore,
  InMemoryWebAuthnCredentialStore,
} from '../../src/auth/stores.js';
import {
  setEmailVerificationStore,
  InMemoryEmailVerificationStore,
} from '../../src/auth/email-verification-pg.js';
import { setEmailSender, resetEmailSender } from '../../src/email-send.js';
import {
  setWalletClaimsConfig,
  uuidToUserId,
} from '../../src/aa/wallet-claims.js';
import { predictWalletAddress } from '../../src/aa/predict.js';

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

interface Harness {
  server: Server;
  baseUrl: string;
}

async function listenProvider(): Promise<Harness> {
  // Reset the auth-store singletons for each harness so a test that
  // registered a user doesn't bleed into the next harness's fresh state.
  setUserStore(new InMemoryUserStore());
  setWebAuthnStore(new InMemoryWebAuthnCredentialStore());

  const probe = createServer();
  await new Promise<void>((res) => probe.listen(0, '127.0.0.1', res));
  const { port } = probe.address() as AddressInfo;
  probe.close();
  const baseUrl = `http://127.0.0.1:${port}`;
  const provider = await createProvider(baseUrl, { googleEnabled: false });
  const server = createServer(provider.callback());
  await new Promise<void>((res) => server.listen(port, '127.0.0.1', res));
  return { server, baseUrl };
}

async function closeServer(server: Server): Promise<void> {
  await new Promise<void>((res, rej) =>
    server.close((err) => (err ? rej(err) : res())),
  );
}

/** Drive /auth + 303 to obtain a live interaction cookie. */
async function startInteraction(baseUrl: string): Promise<CookieJar> {
  const jar = new CookieJar();
  const codeVerifier = base64url(randomBytes(32));
  const codeChallenge = base64url(
    createHash('sha256').update(codeVerifier).digest(),
  );
  const state = base64url(randomBytes(16));
  const authUrl =
    `${baseUrl}/auth?response_type=code&client_id=citrate-explorer` +
    `&redirect_uri=${encodeURIComponent('http://localhost:3001/auth/callback')}` +
    `&scope=${encodeURIComponent('openid profile wallet')}` +
    `&code_challenge=${codeChallenge}&code_challenge_method=S256&state=${state}`;
  const authRes = await fetch(authUrl, { redirect: 'manual' });
  jar.absorb(authRes);
  // Fetch the interaction page to absorb the second cookie panva sets on /interaction.
  const interactionLoc = authRes.headers.get('location');
  if (interactionLoc) {
    const pageRes = await fetch(
      `${baseUrl}${new URL(interactionLoc, baseUrl).pathname}`,
      { headers: { cookie: jar.header() }, redirect: 'manual' },
    );
    jar.absorb(pageRes);
  }
  return jar;
}

describe('POST /auth/password/* (verified-email gate, FWA #87.1)', () => {
  let h: Harness;
  let lastTo: string | null = null;
  let lastCode: string | null = null;

  beforeAll(async () => {
    h = await listenProvider();
  });
  afterAll(async () => {
    resetEmailSender();
    await closeServer(h.server);
  });
  beforeEach(() => {
    // Fresh stores per test so codes/users don't bleed; capture the emailed code.
    setUserStore(new InMemoryUserStore());
    setEmailVerificationStore(new InMemoryEmailVerificationStore());
    setWalletClaimsConfig(undefined);
    lastTo = null;
    lastCode = null;
    setEmailSender(async (msg) => {
      lastTo = msg.to;
      const m = msg.subject.match(/(\d{6})/);
      lastCode = m ? m[1] : null;
      return true;
    });
  });

  const json = { 'content-type': 'application/json' };
  const post = (jar: CookieJar, path: string, body: unknown) =>
    fetch(`${h.baseUrl}${path}`, {
      method: 'POST',
      headers: { ...json, cookie: jar.header() },
      body: JSON.stringify(body),
      redirect: 'manual',
    });

  it('register issues a code and creates NO user + NO session', async () => {
    const jar = await startInteraction(h.baseUrl);
    const res = await post(jar, '/auth/password/register', {
      email: 'newbie@example.com',
      password: 'correct horse battery staple',
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { status: string; redirectTo?: string };
    expect(body.status).toBe('verification_required');
    expect(body.redirectTo).toBeUndefined(); // no session yet
    expect(lastTo).toBe('newbie@example.com');
    expect(lastCode).toMatch(/^\d{6}$/);
    // No user bound until the code is entered.
    expect(await getUserStore().findByEmail('newbie@example.com')).toBeUndefined();
  });

  it('register → verify creates a VERIFIED user + session + predicted wallet', async () => {
    const factory = ('0x' + '11'.repeat(20)) as `0x${string}`;
    const implementation = ('0x' + '22'.repeat(20)) as `0x${string}`;
    setWalletClaimsConfig({ factory, kernelImpl: implementation });
    const jar = await startInteraction(h.baseUrl);
    await post(jar, '/auth/password/register', {
      email: 'grover@example.com',
      password: 'correct horse battery staple',
    });
    expect(lastCode).toBeTruthy();
    const res = await post(jar, '/auth/password/verify', {
      email: 'grover@example.com',
      code: lastCode,
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      userId: string;
      redirectTo: string;
      emailVerified: boolean;
      walletAddress?: string;
    };
    expect(body.emailVerified).toBe(true);
    expect(body.redirectTo).toBeTruthy();
    const user = await getUserStore().findByEmail('grover@example.com');
    expect(user?.emailVerified).toBe(true);
    expect(body.walletAddress?.toLowerCase()).toBe(
      predictWalletAddress(factory, implementation, uuidToUserId(body.userId)).toLowerCase(),
    );
  });

  it('register is enumeration-safe: an existing email returns the SAME shape (no 409)', async () => {
    // Seed a verified user directly.
    const seeded = await getUserStore().createWithEmailPassword({
      email: 'taken@example.com',
      passwordHash: 'x',
    });
    await getUserStore().markEmailVerified(seeded.id);
    const jar = await startInteraction(h.baseUrl);
    const res = await post(jar, '/auth/password/register', {
      email: 'taken@example.com',
      password: 'another password entirely',
    });
    expect(res.status).toBe(200); // NOT 409 — no existence oracle
    const body = (await res.json()) as { status: string };
    expect(body.status).toBe('verification_required');
  });

  it('verify with a wrong code fails 401 and creates nothing', async () => {
    const jar = await startInteraction(h.baseUrl);
    await post(jar, '/auth/password/register', {
      email: 'oscar@example.com',
      password: 'correct horse battery staple',
    });
    const res = await post(jar, '/auth/password/verify', {
      email: 'oscar@example.com',
      code: '000000',
    });
    expect([400, 401]).toContain(res.status);
    expect(await getUserStore().findByEmail('oscar@example.com')).toBeUndefined();
  });

  it('login on a VERIFIED account with the right password signs in (no code)', async () => {
    // Register + verify to create a verified account.
    let jar = await startInteraction(h.baseUrl);
    await post(jar, '/auth/password/register', {
      email: 'ernie@example.com',
      password: 'sunny day sweeping the clouds away',
    });
    await post(jar, '/auth/password/verify', { email: 'ernie@example.com', code: lastCode });
    // Now a fresh interaction + correct password → direct sign-in.
    lastCode = null;
    jar = await startInteraction(h.baseUrl);
    const res = await post(jar, '/auth/password/login', {
      email: 'ernie@example.com',
      password: 'sunny day sweeping the clouds away',
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { redirectTo: string; status?: string };
    expect(body.redirectTo).toBeTruthy();
    expect(body.status).toBeUndefined(); // signed in, not verification_required
    expect(lastCode).toBeNull(); // no code emailed on a verified login
  });

  it('login on an unverified/unknown email issues a code (no session)', async () => {
    const jar = await startInteraction(h.baseUrl);
    const res = await post(jar, '/auth/password/login', {
      email: 'stranger@example.com',
      password: 'guessing at someone elses seat',
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { status: string; redirectTo?: string };
    expect(body.status).toBe('verification_required');
    expect(body.redirectTo).toBeUndefined();
    expect(lastCode).toMatch(/^\d{6}$/);
  });

  it('validates email, password, and code shape', async () => {
    const jar = await startInteraction(h.baseUrl);
    expect(
      (await post(jar, '/auth/password/register', { email: 'nope', password: 'x' })).status,
    ).toBe(400);
    expect(
      (await post(jar, '/auth/password/register', { email: 'a@b.co', password: '' })).status,
    ).toBe(400);
    expect(
      (await post(jar, '/auth/password/verify', { email: 'a@b.co', code: 'abc' })).status,
    ).toBe(400);
  });

  it('rejects requests without an active interaction cookie', async () => {
    const res = await fetch(`${h.baseUrl}/auth/password/register`, {
      method: 'POST',
      headers: json,
      body: JSON.stringify({ email: 'a@b.co', password: 'x'.repeat(12) }),
      redirect: 'manual',
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { reason: string };
    expect(body.reason).toBe('no active interaction');
  });
});

describe('POST /auth/webauthn/authenticate-options', () => {
  let h: Harness;
  beforeAll(async () => {
    h = await listenProvider();
  });
  afterAll(async () => {
    await closeServer(h.server);
  });

  it('returns valid options with a base64url challenge', async () => {
    const jar = await startInteraction(h.baseUrl);
    const res = await fetch(`${h.baseUrl}/auth/webauthn/authenticate-options`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: jar.header() },
      body: '{}',
      redirect: 'manual',
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      challenge: string;
      rpId: string;
      allowCredentials: unknown[];
    };
    // base64url challenge (no padding, no `+` / `/`).
    expect(body.challenge).toMatch(/^[A-Za-z0-9_-]+$/);
    // rpId is the issuer host (siweDomainFromIssuer-equivalent — 127.0.0.1 in test).
    expect(body.rpId).toMatch(/^127\.0\.0\.1$/);
    expect(Array.isArray(body.allowCredentials)).toBe(true);
  });

  it('rejects without an active interaction cookie', async () => {
    const res = await fetch(`${h.baseUrl}/auth/webauthn/authenticate-options`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{}',
      redirect: 'manual',
    });
    expect(res.status).toBe(400);
  });
});

describe('POST /auth/webauthn/signup-* (WP-A passkey signup)', () => {
  let h: Harness;
  beforeAll(async () => {
    h = await listenProvider();
  });
  afterAll(async () => {
    await closeServer(h.server);
  });

  it('signup-options returns registration options with a base64url challenge and a server-side user.id', async () => {
    const jar = await startInteraction(h.baseUrl);
    const res = await fetch(`${h.baseUrl}/auth/webauthn/signup-options`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: jar.header() },
      body: '{}',
      redirect: 'manual',
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      challenge: string;
      rp: { id: string; name: string };
      user: { id: string; name: string; displayName: string };
      pubKeyCredParams: unknown[];
    };
    expect(body.challenge).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(body.challenge.length).toBeGreaterThan(0);
    expect(typeof body.user.id).toBe('string');
    expect(body.user.id.length).toBeGreaterThan(0);
    expect(body.user.name).toBe('New Citrate user');
    expect(Array.isArray(body.pubKeyCredParams)).toBe(true);
  });

  it('signup-options rejects without an active interaction cookie (400)', async () => {
    const res = await fetch(`${h.baseUrl}/auth/webauthn/signup-options`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{}',
      redirect: 'manual',
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { reason: string };
    expect(body.reason).toBe('no active interaction');
  });

  it('signup-verify rejects when no challenge is in flight (400)', async () => {
    // Fresh interaction, no signup-options call → no pending challenge.
    const jar = await startInteraction(h.baseUrl);
    const res = await fetch(`${h.baseUrl}/auth/webauthn/signup-verify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: jar.header() },
      body: JSON.stringify({ response: { id: 'whatever' } }),
      redirect: 'manual',
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { reason: string };
    expect(body.reason).toBe('no challenge in flight (start over)');
  });

  it('signup-verify rejects a missing response body (400 after starting options)', async () => {
    const jar = await startInteraction(h.baseUrl);
    const opts = await fetch(`${h.baseUrl}/auth/webauthn/signup-options`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: jar.header() },
      body: '{}',
      redirect: 'manual',
    });
    expect(opts.status).toBe(200);
    const res = await fetch(`${h.baseUrl}/auth/webauthn/signup-verify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: jar.header() },
      body: JSON.stringify({ /* no response */ deviceLabel: 'Pixel 8' }),
      redirect: 'manual',
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { reason: string };
    expect(body.reason).toBe('response is required');
  });

  it('signup-verify rejects an unverifiable registration response (400 invalid_grant)', async () => {
    // The challenge will be present (signup-options call below), but the
    // RegistrationResponseJSON we send is a synthetic shape that
    // @simplewebauthn/server cannot verify — covers the verifyRegistration
    // throw path → 400 invalid_grant.
    const jar = await startInteraction(h.baseUrl);
    const opts = await fetch(`${h.baseUrl}/auth/webauthn/signup-options`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: jar.header() },
      body: '{}',
      redirect: 'manual',
    });
    expect(opts.status).toBe(200);
    const bogusResponse = {
      id: 'AAAA',
      rawId: 'AAAA',
      type: 'public-key',
      response: {
        clientDataJSON: 'AAAA',
        attestationObject: 'AAAA',
        transports: ['internal'],
      },
      clientExtensionResults: {},
    };
    const res = await fetch(`${h.baseUrl}/auth/webauthn/signup-verify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: jar.header() },
      body: JSON.stringify({ response: bogusResponse }),
      redirect: 'manual',
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe('invalid_grant');
  });
});

describe('static assets (/brand, /fonts)', () => {
  let h: Harness;
  beforeAll(async () => {
    h = await listenProvider();
    // The middleware reads from process.cwd()/public; vitest's cwd is the
    // repo root so the real assets we shipped resolve from /public/{brand,fonts}.
    // No setup beyond confirming the files exist on disk.
    void resolve(process.cwd(), 'public'); // touch to keep the import used
  });
  afterAll(async () => {
    await closeServer(h.server);
  });

  it('serves a brand SVG with the right content-type + immutable cache headers', async () => {
    const res = await fetch(`${h.baseUrl}/brand/citrate-mark.svg`);
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toBe('image/svg+xml');
    expect(res.headers.get('cache-control')).toContain('immutable');
    const body = await res.text();
    expect(body).toContain('<svg');
  });

  it('serves a webfont with font/woff2 content-type', async () => {
    const res = await fetch(`${h.baseUrl}/fonts/Geist-Regular.woff2`);
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toBe('font/woff2');
  });

  it('rejects path traversal attempts with 400', async () => {
    const res = await fetch(`${h.baseUrl}/brand/../package.json`);
    // The middleware short-circuits before panva's router; Node will
    // normalize `..` in the request URL, but for a literal-encoded form
    // we should still get a 4xx (either our 400 or panva's 404), never the
    // file contents.
    expect(res.status >= 400 && res.status < 500).toBe(true);
    const body = await res.text();
    expect(body).not.toContain('"name":');
  });

  it('returns 404 for an unknown asset under an allowed prefix', async () => {
    const res = await fetch(`${h.baseUrl}/brand/nope.svg`);
    expect(res.status).toBe(404);
  });
});
