/**
 * Google federation callback guards, pinned at the HTTP routes:
 *   - the id_token `nonce` must equal the one minted at /auth/google/start;
 *   - a `state` is single-use at the callback (a second callback with the same
 *     state is refused);
 *   - an unreachable state store fails closed at BOTH /start and /callback.
 *
 * Google is stubbed locally: the remote JWKS is replaced by a local key set and
 * the token endpoint by a patched `fetch`. No network, no host state.
 */
import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import { EventEmitter } from 'node:events';
import type { AddressInfo } from 'node:net';
import { SignJWT, exportJWK, generateKeyPair, createLocalJWKSet, type KeyLike } from 'jose';
import type Provider from 'oidc-provider';

// The routes build their Google key set at import time with createRemoteJWKSet;
// route it to a local key set so verification never leaves the process.
const jwksHolder = vi.hoisted(() => ({ set: null as null | ((...a: unknown[]) => unknown) }));
vi.mock('jose', async (importOriginal) => {
  const real = await importOriginal<typeof import('jose')>();
  return {
    ...real,
    createRemoteJWKSet: () => (...a: unknown[]) => {
      if (!jwksHolder.set) throw new Error('test JWKS not initialised');
      return jwksHolder.set(...a);
    },
  };
});

const PORT = 43219;
process.env.ISSUER_URL = `http://127.0.0.1:${PORT}`;
process.env.PORT = String(PORT);
process.env.COOKIE_KEYS = 'test-cookie-key-0123456789abcdef0123456789abcdef';
process.env.CITRATE_AA_GOOGLE_CLIENT_ID = 'test-google-client-id.apps.googleusercontent.com';
process.env.CITRATE_AA_GOOGLE_CLIENT_SECRET = 'test-google-client-secret';

class Jar {
  private readonly c = new Map<string, string>();
  absorb(res: Response): void {
    for (const raw of res.headers.getSetCookie?.() ?? []) {
      const [pair] = raw.split(';');
      const i = pair.indexOf('=');
      if (i > 0) {
        const k = pair.slice(0, i).trim();
        const v = pair.slice(i + 1).trim();
        if (v === '') this.c.delete(k); else this.c.set(k, v);
      }
    }
  }
  header(): string { return [...this.c.entries()].map(([k, v]) => `${k}=${v}`).join('; '); }
}
const realFetch = globalThis.fetch;
async function go(jar: Jar, url: string): Promise<Response> {
  const res = await realFetch(url, { redirect: 'manual', headers: { cookie: jar.header() } });
  jar.absorb(res);
  return res;
}

let server: { close(): void; address(): AddressInfo | string | null };
let base = '';
let signingKey: KeyLike;
/** The id_token the stubbed Google token endpoint returns next. */
let nextIdToken = '';

async function idToken(nonce: string, sub: string): Promise<string> {
  return new SignJWT({ nonce, email: `${sub}@example.com`, email_verified: true })
    .setProtectedHeader({ alg: 'RS256', kid: 'test-google-key' })
    .setIssuer('https://accounts.google.com')
    .setAudience(process.env.CITRATE_AA_GOOGLE_CLIENT_ID!)
    .setSubject(sub).setIssuedAt().setExpirationTime('10m').sign(signingKey);
}

beforeAll(async () => {
  const { privateKey, publicKey } = await generateKeyPair('RS256', { extractable: true });
  signingKey = privateKey;
  const pubJwk = await exportJWK(publicKey);
  pubJwk.kid = 'test-google-key'; pubJwk.alg = 'RS256'; pubJwk.use = 'sig';
  jwksHolder.set = createLocalJWKSet({ keys: [pubJwk] }) as unknown as (...a: unknown[]) => unknown;
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : (input as Request).url;
    if (url.startsWith('https://oauth2.googleapis.com/token'))
      return new Response(JSON.stringify({ id_token: nextIdToken }), { status: 200, headers: { 'content-type': 'application/json' } });
    if (!url.startsWith(base)) throw new Error(`unexpected outbound fetch in test: ${url}`);
    return realFetch(input as string | URL | Request, init);
  }) as typeof fetch;
  const { initAuthStoresFromEnv } = await import('../src/auth/stores.js');
  const { createProvider } = await import('../src/server.js');
  await initAuthStoresFromEnv({});
  const provider = await createProvider(process.env.ISSUER_URL!);
  server = provider.listen(PORT) as unknown as typeof server;
  await new Promise<void>((r) => (server as unknown as EventEmitter).once('listening', () => r()));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}, 30000);

afterAll(() => { server?.close(); });

/** Begin an OIDC interaction and /auth/google/start in one jar; return the minted state + nonce. */
async function startFlow(jar: Jar, tag: string): Promise<{ state: string; nonce: string }> {
  await go(
    jar,
    `${base}/auth?client_id=citrate-explorer&response_type=code` +
      `&scope=${encodeURIComponent('openid profile wallet')}` +
      `&redirect_uri=${encodeURIComponent(`${base}/auth/callback`)}` +
      `&state=${tag}&nonce=n&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256`,
  );
  const started = await go(jar, `${base}/auth/google/start`);
  expect(started.status).toBe(303);
  const loc = new URL(started.headers.get('location')!);
  return { state: loc.searchParams.get('state')!, nonce: loc.searchParams.get('nonce')! };
}

describe('Google callback: id_token nonce + single-use state', () => {
  it('refuses an id_token whose nonce differs from the one minted at start', async () => {
    const jar = new Jar();
    const { state, nonce } = await startFlow(jar, 'nonce1');
    nextIdToken = await idToken(`${nonce}-other`, 'google-sub-nonce');
    const res = await go(jar, `${base}/auth/google/callback?code=c&state=${encodeURIComponent(state)}`);
    expect(res.status).toBe(401);
    expect(((await res.json()) as { reason?: string }).reason).toBe('nonce mismatch');
  }, 20000);

  it('accepts the matching nonce once, then refuses the same state again', async () => {
    const jar = new Jar();
    const { state, nonce } = await startFlow(jar, 'replay1');
    nextIdToken = await idToken(nonce, 'google-sub-replay');
    const first = await go(jar, `${base}/auth/google/callback?code=c&state=${encodeURIComponent(state)}`);
    expect(first.status).toBe(303);
    const again = await go(jar, `${base}/auth/google/callback?code=c&state=${encodeURIComponent(state)}`);
    expect(again.status).toBe(400);
    expect(((await again.json()) as { reason?: string }).reason).toBe('unknown or expired state');
  }, 20000);
});

describe('Google routes fail closed when the shared state store is unreachable', () => {
  async function call(path: string, query: Record<string, string>) {
    const { mountGoogleRoutes } = await import('../src/auth/google-routes.js');
    let mw: ((ctx: unknown, next: () => Promise<void>) => Promise<void>) | null = null;
    const provider = {
      use: (fn: typeof mw) => { mw = fn; },
      interactionDetails: async () => ({ uid: 'uid-1' }),
    } as unknown as Provider;
    const down = async () => { throw new Error('ECONNREFUSED'); };
    mountGoogleRoutes(provider, {
      clientId: 'cid',
      clientSecret: 'secret',
      redirectUri: 'http://127.0.0.1/cb',
      redis: { set: down, get: down, getdel: down, del: down } as never,
    });
    const out = { status: 0, headers: {} as Record<string, string>, body: '' };
    const ctx = {
      method: 'GET',
      path,
      query,
      req: {},
      res: {
        writeHead: (s: number, h: Record<string, string>) => { out.status = s; out.headers = h; },
        end: (b?: string) => { out.body = b ?? ''; },
      },
    };
    await mw!(ctx, async () => undefined);
    return out;
  }

  it('/auth/google/start returns 503 and no redirect to Google', async () => {
    const r = await call('/auth/google/start', {});
    expect(r.status).toBe(503);
    expect(r.headers.location).toBeUndefined();
  });

  it('/auth/google/callback returns 503', async () => {
    const r = await call('/auth/google/callback', { code: 'c', state: 's' });
    expect(r.status).toBe(503);
  });
});
