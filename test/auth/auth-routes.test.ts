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
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createProvider } from '../../src/server.js';
import {
  setUserStore,
  setWebAuthnStore,
  InMemoryUserStore,
  InMemoryWebAuthnCredentialStore,
} from '../../src/auth/stores.js';

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

describe('POST /auth/password/*', () => {
  let h: Harness;
  beforeAll(async () => {
    h = await listenProvider();
  });
  afterAll(async () => {
    await closeServer(h.server);
  });

  it('register creates a new user and returns a redirectTo', async () => {
    const jar = await startInteraction(h.baseUrl);
    const res = await fetch(`${h.baseUrl}/auth/password/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: jar.header() },
      body: JSON.stringify({ email: 'alice@example.com', password: 'correct-horse' }),
      redirect: 'manual',
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { userId: string; redirectTo: string };
    expect(typeof body.userId).toBe('string');
    expect(body.redirectTo).toMatch(/\/auth\/?/);
  });

  it('register rejects a duplicate email with 409', async () => {
    // First registration succeeds.
    const jar1 = await startInteraction(h.baseUrl);
    const first = await fetch(`${h.baseUrl}/auth/password/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: jar1.header() },
      body: JSON.stringify({ email: 'bob@example.com', password: 'hunter2-secure' }),
      redirect: 'manual',
    });
    expect(first.status).toBe(200);

    const jar2 = await startInteraction(h.baseUrl);
    const dup = await fetch(`${h.baseUrl}/auth/password/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: jar2.header() },
      body: JSON.stringify({ email: 'bob@example.com', password: 'different-pw' }),
      redirect: 'manual',
    });
    expect(dup.status).toBe(409);
    const body = (await dup.json()) as { error: string };
    expect(body.error).toBe('email_taken');
  });

  it('register validates the email + password shape', async () => {
    const jar = await startInteraction(h.baseUrl);
    const badEmail = await fetch(`${h.baseUrl}/auth/password/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: jar.header() },
      body: JSON.stringify({ email: 'not-an-email', password: 'whatever-long' }),
      redirect: 'manual',
    });
    expect(badEmail.status).toBe(400);

    const jar2 = await startInteraction(h.baseUrl);
    const shortPw = await fetch(`${h.baseUrl}/auth/password/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: jar2.header() },
      body: JSON.stringify({ email: 'charlie@example.com', password: 'short' }),
      redirect: 'manual',
    });
    expect(shortPw.status).toBe(400);
  });

  it('login succeeds with the right password and returns a redirectTo', async () => {
    const jar = await startInteraction(h.baseUrl);
    const reg = await fetch(`${h.baseUrl}/auth/password/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: jar.header() },
      body: JSON.stringify({ email: 'dave@example.com', password: 'my-real-password' }),
      redirect: 'manual',
    });
    expect(reg.status).toBe(200);

    // New interaction for the subsequent login (the register call burned the
    // first interaction cookie via interactionResult).
    const jar2 = await startInteraction(h.baseUrl);
    const login = await fetch(`${h.baseUrl}/auth/password/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: jar2.header() },
      body: JSON.stringify({ email: 'dave@example.com', password: 'my-real-password' }),
      redirect: 'manual',
    });
    expect(login.status).toBe(200);
    const body = (await login.json()) as { userId: string; redirectTo: string };
    expect(typeof body.userId).toBe('string');
    expect(body.redirectTo).toMatch(/\/auth\/?/);
  });

  it('login fails with a generic 401 on a wrong password (no enumeration)', async () => {
    const jar = await startInteraction(h.baseUrl);
    await fetch(`${h.baseUrl}/auth/password/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: jar.header() },
      body: JSON.stringify({ email: 'eve@example.com', password: 'secret-secret' }),
      redirect: 'manual',
    });

    // Wrong password.
    const jar2 = await startInteraction(h.baseUrl);
    const wrong = await fetch(`${h.baseUrl}/auth/password/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: jar2.header() },
      body: JSON.stringify({ email: 'eve@example.com', password: 'wrong-secret' }),
      redirect: 'manual',
    });
    expect(wrong.status).toBe(401);
    const wrongBody = (await wrong.json()) as { reason: string };

    // Unknown email — must produce the same status + same shape.
    const jar3 = await startInteraction(h.baseUrl);
    const unknown = await fetch(`${h.baseUrl}/auth/password/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: jar3.header() },
      body: JSON.stringify({ email: 'never@example.com', password: 'any-password' }),
      redirect: 'manual',
    });
    expect(unknown.status).toBe(401);
    const unknownBody = (await unknown.json()) as { reason: string };
    expect(wrongBody.reason).toBe(unknownBody.reason);
  });

  it('rejects requests without an active interaction cookie', async () => {
    const res = await fetch(`${h.baseUrl}/auth/password/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'frank@example.com', password: 'whatever-pw' }),
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
