/**
 * Integration tests for the WP-C portal-registration route:
 *
 *   GET /kyc/start?level=T3|T4 — user-facing identity-verification kickoff.
 *
 * The endpoint requires an active OIDC interaction whose session carries
 * an accountId. We drive a full password sign-in to set the OIDC session
 * cookie, then start a NEW /auth flow with that cookie to land on an
 * interaction whose `session.accountId` is populated — the same shape
 * the dashboard would produce in production when a signed-in user
 * clicks "Verify identity".
 *
 * The KycProvider singleton is swapped per test (Mock) so we can assert
 * on calls without reaching a real vendor.
 */

import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { createHash, randomBytes } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createProvider } from '../src/server.js';
import {
  setUserStore,
  setWebAuthnStore,
  InMemoryUserStore,
  InMemoryWebAuthnCredentialStore,
} from '../src/auth/stores.js';
import {
  setKycProvider,
  MockKycProvider,
} from '../src/kyc-providers/index.js';

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
  mock: MockKycProvider;
}

async function listenProvider(args: { vendor: 'mock' | 'sumsub' }): Promise<Harness> {
  // Per-harness fresh in-memory stores + a fresh Mock provider so tests
  // don't leak state across describe blocks.
  setUserStore(new InMemoryUserStore());
  setWebAuthnStore(new InMemoryWebAuthnCredentialStore());
  const mock = new MockKycProvider({ mode: 'sandbox' });
  setKycProvider(mock);
  process.env.KYC_PROVIDER = args.vendor;

  const probe = createServer();
  await new Promise<void>((res) => probe.listen(0, '127.0.0.1', res));
  const { port } = probe.address() as AddressInfo;
  probe.close();
  const baseUrl = `http://127.0.0.1:${port}`;
  const provider = await createProvider(baseUrl, { googleEnabled: false });
  const server = createServer(provider.callback());
  await new Promise<void>((res) => server.listen(port, '127.0.0.1', res));
  return { server, baseUrl, mock };
}

async function closeServer(server: Server): Promise<void> {
  await new Promise<void>((res, rej) =>
    server.close((err) => (err ? rej(err) : res())),
  );
}

/**
 * Drive /auth + 303 to get a fresh interaction cookie. Pass
 * `forceFreshInteraction: true` to add `prompt=consent`, which forces
 * panva to render a new interaction even when the user is already
 * signed in to a trusted-first-party RP — the only way to reach
 * post-signin surfaces like /kyc/start (or /auth/webauthn/register-*).
 */
async function startInteraction(
  baseUrl: string,
  jar: CookieJar,
  args: { forceFreshInteraction?: boolean } = {},
): Promise<void> {
  const codeVerifier = base64url(randomBytes(32));
  const codeChallenge = base64url(
    createHash('sha256').update(codeVerifier).digest(),
  );
  const state = base64url(randomBytes(16));
  const promptParam = args.forceFreshInteraction ? '&prompt=consent' : '';
  const authUrl =
    `${baseUrl}/auth?response_type=code&client_id=citrate-explorer` +
    `&redirect_uri=${encodeURIComponent('http://localhost:3001/auth/callback')}` +
    `&scope=${encodeURIComponent('openid profile wallet')}${promptParam}` +
    `&code_challenge=${codeChallenge}&code_challenge_method=S256&state=${state}`;
  const authRes = await fetch(authUrl, {
    headers: { cookie: jar.header() },
    redirect: 'manual',
  });
  jar.absorb(authRes);
  const interactionLoc = authRes.headers.get('location');
  if (interactionLoc) {
    const pageRes = await fetch(
      `${baseUrl}${new URL(interactionLoc, baseUrl).pathname}`,
      { headers: { cookie: jar.header() }, redirect: 'manual' },
    );
    jar.absorb(pageRes);
  }
}

/**
 * Drive a full password sign-in + follow the post-login redirects until
 * the OIDC session cookie is set, then start a NEW /auth flow that lands
 * on an interaction whose `session.accountId` reflects the signed-in
 * user. Returns the cookie jar carrying both the OIDC session and the
 * new interaction cookie.
 */
async function signInAndStartFreshInteraction(
  baseUrl: string,
  args: { email: string; password: string },
): Promise<CookieJar> {
  const jar = new CookieJar();
  await startInteraction(baseUrl, jar);

  // Register → sets login on the interaction, returns a redirectTo that
  // resumes the /auth flow and completes consent + lands at the RP.
  const reg = await fetch(`${baseUrl}/auth/password/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie: jar.header() },
    body: JSON.stringify(args),
    redirect: 'manual',
  });
  jar.absorb(reg);
  expect(reg.status).toBe(200);
  const regBody = (await reg.json()) as { redirectTo: string };

  // Follow the redirect chain until we either land at the RP redirect
  // (the OIDC session cookie has been set by then) or run out of hops.
  let location: string | null = regBody.redirectTo;
  for (let hop = 0; hop < 10 && location; hop++) {
    const url = location.startsWith('http') ? location : `${baseUrl}${location}`;
    if (url.startsWith('http://localhost:3001/auth/callback')) break;
    const hopRes = await fetch(url, {
      headers: { cookie: jar.header() },
      redirect: 'manual',
    });
    jar.absorb(hopRes);
    location = hopRes.headers.get('location');
    if (hopRes.status !== 303 && hopRes.status !== 302) break;
  }

  // Now start a NEW /auth flow with the OIDC session cookie. For
  // trusted-first-party clients panva would auto-grant and skip the
  // interaction (the explorer/dashboard/studio are all trusted), so we
  // pass `prompt=consent` to force a fresh interaction whose
  // `session.accountId` is set — the shape /kyc/start expects.
  await startInteraction(baseUrl, jar, { forceFreshInteraction: true });
  return jar;
}

describe('GET /kyc/start (WP-C portal registration ladder)', () => {
  let h: Harness;
  beforeAll(async () => {
    h = await listenProvider({ vendor: 'mock' });
  });
  afterAll(async () => {
    await closeServer(h.server);
    delete process.env.KYC_PROVIDER;
  });

  it('rejects with 401 when there is neither an interaction nor a session (C.2)', async () => {
    // Post-C.2, /kyc/start falls back from interaction → session; with neither,
    // it asks the user to sign in (401) rather than 400 "no active interaction".
    const res = await fetch(`${h.baseUrl}/kyc/start`, { redirect: 'manual' });
    expect(res.status).toBe(401);
    const body = (await res.json()) as { reason: string };
    expect(body.reason).toMatch(/sign in first/);
  });

  it('rejects with 401 when the interaction has no accountId (not signed in)', async () => {
    const jar = new CookieJar();
    await startInteraction(h.baseUrl, jar);
    const res = await fetch(`${h.baseUrl}/kyc/start`, {
      headers: { cookie: jar.header() },
      redirect: 'manual',
    });
    expect(res.status).toBe(401);
    const body = (await res.json()) as { reason: string };
    expect(body.reason).toMatch(/sign in first/);
  });

  it('303s to a vendor-shaped URL when the provider is mock + interaction has accountId', async () => {
    const jar = await signInAndStartFreshInteraction(h.baseUrl, {
      email: 'kyc-start-1@example.com',
      password: 'correct-horse',
    });
    const beforeCalls = h.mock.calls.length;
    const res = await fetch(`${h.baseUrl}/kyc/start`, {
      headers: { cookie: jar.header() },
      redirect: 'manual',
    });
    expect(res.status).toBe(303);
    const loc = res.headers.get('location');
    expect(loc).toBeTruthy();
    expect(loc!).toMatch(/^https:\/\/kyc-mock\.invalid\/sdk\?token=/);
    expect(loc!).toMatch(/applicantId=mock_/);
    // Provider was hit exactly once for createApplicant + once for
    // mintClientSession on the first call.
    const afterCalls = h.mock.calls.slice(beforeCalls);
    expect(afterCalls.filter((c) => c.method === 'createApplicant').length).toBe(1);
    expect(afterCalls.filter((c) => c.method === 'mintClientSession').length).toBe(1);
  });

  it('caches the applicantId per session — second /kyc/start does not re-create the applicant', async () => {
    const jar = await signInAndStartFreshInteraction(h.baseUrl, {
      email: 'kyc-start-2@example.com',
      password: 'correct-horse',
    });

    const first = await fetch(`${h.baseUrl}/kyc/start`, {
      headers: { cookie: jar.header() },
      redirect: 'manual',
    });
    expect(first.status).toBe(303);
    const baseline = h.mock.calls.filter((c) => c.method === 'createApplicant').length;

    // A second /kyc/start needs a fresh interaction cookie (the prior
    // one was burned by /kyc/start's response). Re-use the same jar
    // (carrying the OIDC session) and start a fresh interaction with
    // prompt=consent.
    await startInteraction(h.baseUrl, jar, { forceFreshInteraction: true });

    const second = await fetch(`${h.baseUrl}/kyc/start`, {
      headers: { cookie: jar.header() },
      redirect: 'manual',
    });
    expect(second.status).toBe(303);
    const afterCount = h.mock.calls.filter((c) => c.method === 'createApplicant').length;
    // createApplicant should NOT have been called again for the same
    // accountId — the route caches it.
    expect(afterCount).toBe(baseline);
  });

  it('?level=T4 passes the KYB level hint to the adapter', async () => {
    const jar = await signInAndStartFreshInteraction(h.baseUrl, {
      email: 'kyc-start-3@example.com',
      password: 'correct-horse',
    });
    const beforeCalls = h.mock.calls.length;
    const res = await fetch(`${h.baseUrl}/kyc/start?level=T4`, {
      headers: { cookie: jar.header() },
      redirect: 'manual',
    });
    expect(res.status).toBe(303);
    const created = h.mock.calls
      .slice(beforeCalls)
      .find((c) => c.method === 'createApplicant');
    expect(created).toBeDefined();
    const args = created!.args[0] as { levelHint: string };
    expect(args.levelHint).toBe('kyb-entity');
  });

  it('rejects an unrecognised ?level value with 400', async () => {
    const jar = await signInAndStartFreshInteraction(h.baseUrl, {
      email: 'kyc-start-4@example.com',
      password: 'correct-horse',
    });
    const res = await fetch(`${h.baseUrl}/kyc/start?level=T99`, {
      headers: { cookie: jar.header() },
      redirect: 'manual',
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { reason: string };
    expect(body.reason).toMatch(/level must be T3/);
  });
});

describe('GET /kyc/start when KYC_PROVIDER is unset', () => {
  let h: Harness;
  beforeAll(async () => {
    // Force the unconfigured posture by clearing the singleton and the env.
    delete process.env.KYC_PROVIDER;
    h = await listenProvider({ vendor: 'mock' });
    // Override the per-harness setup: clear the provider after listen.
    setKycProvider(undefined);
    delete process.env.KYC_PROVIDER;
  });
  afterAll(async () => {
    await closeServer(h.server);
  });

  it('returns 503 kyc_unconfigured (after a valid signed-in interaction)', async () => {
    const jar = await signInAndStartFreshInteraction(h.baseUrl, {
      email: 'kyc-unconf-1@example.com',
      password: 'correct-horse',
    });
    const res = await fetch(`${h.baseUrl}/kyc/start`, {
      headers: { cookie: jar.header() },
      redirect: 'manual',
    });
    expect(res.status).toBe(503);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe('kyc_unconfigured');
  });
});
