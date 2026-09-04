/**
 * WP-I3 — ID-B-002 (HIGH) regression: Google-federation login-CSRF / session fixation.
 *
 * /auth/google/start records the originating interactionUid in the pending state, but
 * the callback resolved the interaction from the browser cookie without comparing it —
 * so an attacker could complete THEIR Google login into a VICTIM's in-flight
 * interaction. Fix: the callback rejects unless cookie interaction.uid === pending
 * interactionUid. Adapted from the auditor PoC (agent-B poc-google-login-csrf.ts):
 * two cookie jars, Google stubbed locally, no source patched.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { EventEmitter } from 'node:events';
import { Readable } from 'node:stream';
import { createRequire } from 'node:module';
import type { AddressInfo } from 'node:net';
import { SignJWT, exportJWK, generateKeyPair } from 'jose';

const PORT = 43217;
process.env.ISSUER_URL = `http://127.0.0.1:${PORT}`;
process.env.PORT = String(PORT);
process.env.COOKIE_KEYS = 'poc-cookie-key-0123456789abcdef0123456789abcdef';
process.env.CITRATE_AA_GOOGLE_CLIENT_ID = 'poc-google-client-id.apps.googleusercontent.com';
process.env.CITRATE_AA_GOOGLE_CLIENT_SECRET = 'poc-google-client-secret';

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

let server: { close(): void; address(): AddressInfo | string | null } & { listen?: unknown };
let base = '';

beforeAll(async () => {
  const { privateKey, publicKey } = await generateKeyPair('RS256', { extractable: true });
  const pubJwk = await exportJWK(publicKey);
  pubJwk.kid = 'poc-google-key'; pubJwk.alg = 'RS256'; pubJwk.use = 'sig';
  const jwks = JSON.stringify({ keys: [pubJwk] });
  const req_ = createRequire(import.meta.url);
  const httpsCjs = req_('node:https') as { get: (...a: unknown[]) => unknown };
  const origGet = httpsCjs.get;
  httpsCjs.get = function patched(this: unknown, ...args: unknown[]): unknown {
    if (String(args[0] ?? '').startsWith('https://www.googleapis.com/oauth2/v3/certs')) {
      const em = new EventEmitter() as EventEmitter & { destroy(): void };
      em.destroy = () => {};
      const body = Readable.from([Buffer.from(jwks, 'utf8')]) as Readable & { statusCode?: number };
      body.statusCode = 200;
      setImmediate(() => em.emit('response', body));
      return em;
    }
    return (origGet as (...a: unknown[]) => unknown).apply(this, args);
  };
  const attackerIdToken = await new SignJWT({ nonce: 'n', email_verified: false })
    .setProtectedHeader({ alg: 'RS256', kid: 'poc-google-key' })
    .setIssuer('https://accounts.google.com')
    .setAudience(process.env.CITRATE_AA_GOOGLE_CLIENT_ID!)
    .setSubject('attacker-google-sub').setIssuedAt().setExpirationTime('10m').sign(privateKey);
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : (input as Request).url;
    if (url.startsWith('https://oauth2.googleapis.com/token'))
      return new Response(JSON.stringify({ id_token: attackerIdToken }), { status: 200, headers: { 'content-type': 'application/json' } });
    return realFetch(input as string | URL | Request, init);
  }) as typeof fetch;

  const { initAuthStoresFromEnv } = await import('../src/auth/stores.js');
  const { createProvider } = await import('../src/server.js');
  await initAuthStoresFromEnv({});
  const provider = await createProvider(process.env.ISSUER_URL!);
  server = provider.listen(PORT) as typeof server;
  await new Promise<void>((r) => (server as unknown as EventEmitter).once('listening', () => r()));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}, 30000);

afterAll(() => { server?.close(); });

describe('ID-B-002 — Google callback binds state to the originating interaction', () => {
  it("rejects a callback whose state was minted under a DIFFERENT interaction (login-CSRF)", async () => {
    const authUrl = (state: string) =>
      `${base}/auth?client_id=citrate-explorer&response_type=code` +
      `&scope=${encodeURIComponent('openid profile wallet')}` +
      `&redirect_uri=${encodeURIComponent(`${base}/auth/callback`)}` +
      `&state=${state}&nonce=n&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256`;
    // attacker starts their own flow, captures the state bound to THEIR interaction
    const attacker = new Jar();
    await go(attacker, authUrl('atk'));
    const started = await go(attacker, `${base}/auth/google/start`);
    const state = new URL(started.headers.get('location')!).searchParams.get('state')!;
    // victim has their OWN in-flight interaction (different cookie)
    const victim = new Jar();
    await go(victim, authUrl('vic'));
    // attacker lures victim to the callback with the attacker's state
    const res = await go(victim, `${base}/auth/google/callback?code=whatever&state=${encodeURIComponent(state)}`);
    // FIX: the interaction-uid binding must refuse this before any token exchange.
    // RED (pre-fix): 303 — the victim's interaction resolves to the attacker's account.
    expect(res.status).toBe(400);
    const body = (await res.json()) as { reason?: string };
    expect(body.reason).toBe('interaction mismatch');
  }, 20000);
});
