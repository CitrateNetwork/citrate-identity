/**
 * Integration tests for the Google OAuth routes (WP-6 slice C):
 *
 *   - GET /auth/google/start
 *   - GET /auth/google/callback
 *
 * Each test drives a real /auth request to obtain a live interaction
 * cookie, then exercises the route under test against the same kind of
 * harness the password + webauthn tests use. The token-exchange + JWKS
 * branches (the happy path through Google) need a full Google mock and
 * are covered by a follow-up E2E with a fixture jose key — this file
 * covers the routing + state + error branches that don't need the
 * remote.
 */

import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { createHash, randomBytes } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createProvider } from '../../src/server.js';

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

async function listenWithGoogle(env: {
  CITRATE_AA_GOOGLE_CLIENT_ID: string;
  CITRATE_AA_GOOGLE_CLIENT_SECRET: string;
}): Promise<Harness> {
  // Inject the env into process.env for the duration of the harness boot.
  // The harness teardown removes them; tests must be sequenced.
  const prevId = process.env.CITRATE_AA_GOOGLE_CLIENT_ID;
  const prevSecret = process.env.CITRATE_AA_GOOGLE_CLIENT_SECRET;
  process.env.CITRATE_AA_GOOGLE_CLIENT_ID = env.CITRATE_AA_GOOGLE_CLIENT_ID;
  process.env.CITRATE_AA_GOOGLE_CLIENT_SECRET = env.CITRATE_AA_GOOGLE_CLIENT_SECRET;

  const probe = createServer();
  await new Promise<void>((res) => probe.listen(0, '127.0.0.1', res));
  const { port } = probe.address() as AddressInfo;
  probe.close();
  const baseUrl = `http://127.0.0.1:${port}`;
  const provider = await createProvider(baseUrl, { googleEnabled: true });
  const server = createServer(provider.callback());
  await new Promise<void>((res) => server.listen(port, '127.0.0.1', res));

  // Restore env so unrelated tests don't see it.
  if (prevId === undefined) delete process.env.CITRATE_AA_GOOGLE_CLIENT_ID;
  else process.env.CITRATE_AA_GOOGLE_CLIENT_ID = prevId;
  if (prevSecret === undefined) delete process.env.CITRATE_AA_GOOGLE_CLIENT_SECRET;
  else process.env.CITRATE_AA_GOOGLE_CLIENT_SECRET = prevSecret;

  return { server, baseUrl };
}

async function closeServer(server: Server): Promise<void> {
  await new Promise<void>((res, rej) =>
    server.close((err) => (err ? rej(err) : res())),
  );
}

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

describe('GET /auth/google/*', () => {
  let h: Harness;
  beforeAll(async () => {
    h = await listenWithGoogle({
      CITRATE_AA_GOOGLE_CLIENT_ID: 'test-client-id.apps.googleusercontent.com',
      CITRATE_AA_GOOGLE_CLIENT_SECRET: 'test-client-secret',
    });
  });
  afterAll(async () => {
    await closeServer(h.server);
  });

  it('start: 303s to accounts.google.com with all required OAuth params', async () => {
    const jar = await startInteraction(h.baseUrl);
    const res = await fetch(`${h.baseUrl}/auth/google/start`, {
      headers: { cookie: jar.header() },
      redirect: 'manual',
    });
    expect(res.status).toBe(303);
    const location = res.headers.get('location');
    expect(location).toBeTruthy();
    const url = new URL(location!);
    expect(url.origin + url.pathname).toBe(
      'https://accounts.google.com/o/oauth2/v2/auth',
    );
    expect(url.searchParams.get('client_id')).toBe(
      'test-client-id.apps.googleusercontent.com',
    );
    expect(url.searchParams.get('response_type')).toBe('code');
    expect(url.searchParams.get('scope')).toBe('openid email profile');
    expect(url.searchParams.get('code_challenge_method')).toBe('S256');
    // state + nonce + code_challenge are all non-empty random tokens
    for (const p of ['state', 'nonce', 'code_challenge']) {
      expect(url.searchParams.get(p)).toMatch(/^[A-Za-z0-9_-]+$/);
    }
    expect(url.searchParams.get('redirect_uri')).toBe(
      `${h.baseUrl}/auth/google/callback`,
    );
  });

  it('start: 400 without an active interaction cookie', async () => {
    const res = await fetch(`${h.baseUrl}/auth/google/start`, {
      redirect: 'manual',
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { reason: string };
    expect(body.reason).toBe('no active interaction');
  });

  it('callback: 400 on missing code or state', async () => {
    const res = await fetch(`${h.baseUrl}/auth/google/callback`, {
      redirect: 'manual',
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { reason: string };
    expect(body.reason).toBe('missing code or state');
  });

  it('callback: 400 on unknown state (replay or expired)', async () => {
    const res = await fetch(
      `${h.baseUrl}/auth/google/callback?code=anything&state=neverissued`,
      { redirect: 'manual' },
    );
    expect(res.status).toBe(400);
    const body = (await res.json()) as { reason: string };
    expect(body.reason).toBe('unknown or expired state');
  });

  it("callback: 400 on Google-reported `error` query param", async () => {
    const res = await fetch(
      `${h.baseUrl}/auth/google/callback?error=access_denied`,
      { redirect: 'manual' },
    );
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string; reason: string };
    expect(body.error).toBe('google_oauth_failed');
    expect(body.reason).toBe('access_denied');
  });
});

describe('GET /auth/google/start without Google env (routes not mounted)', () => {
  let h: Harness;
  beforeAll(async () => {
    // No CITRATE_AA_GOOGLE_CLIENT_* set; createProvider receives
    // googleEnabled: false so the UI renders "not enabled" and
    // mountGoogleRoutes is skipped. A hit on the route should fall
    // through to panva's catch-all (404).
    const probe = createServer();
    await new Promise<void>((res) => probe.listen(0, '127.0.0.1', res));
    const { port } = probe.address() as AddressInfo;
    probe.close();
    const baseUrl = `http://127.0.0.1:${port}`;
    const provider = await createProvider(baseUrl, { googleEnabled: false });
    const server = createServer(provider.callback());
    await new Promise<void>((res) => server.listen(port, '127.0.0.1', res));
    h = { server, baseUrl };
  });
  afterAll(async () => {
    await closeServer(h.server);
  });

  it('start: route is not mounted (panva catch-all)', async () => {
    const res = await fetch(`${h.baseUrl}/auth/google/start`, {
      redirect: 'manual',
    });
    // panva responds with 400 invalid_request "unrecognized route" for
    // any unmounted path. The exact body shape is panva's; we just
    // assert it's not a 303 (which would mean our routes leaked
    // through).
    expect(res.status).not.toBe(303);
  });
});
