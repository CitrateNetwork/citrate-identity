/**
 * AUTHSPINE S1-WP3 — the Account Hub (GET /account).
 *   - no session  → the friendly "sign in first" page
 *   - signed in   → the hub: identity + wallet + KYC status + Start-verification CTA + tier
 */
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { createHash, randomBytes } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createProvider } from '../src/server.js';
import { armEmailCapture, lastVerificationCode } from './helpers/verify.js';
import {
  setUserStore,
  setWebAuthnStore,
  InMemoryUserStore,
  InMemoryWebAuthnCredentialStore,
} from '../src/auth/stores.js';

let server: Server;
let baseUrl: string;

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
const b64url = (b: Buffer) => b.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

async function startInteraction(jar: CookieJar): Promise<void> {
  const verifier = b64url(randomBytes(32));
  const challenge = b64url(createHash('sha256').update(verifier).digest());
  const url =
    `${baseUrl}/auth?response_type=code&client_id=citrate-explorer` +
    `&redirect_uri=${encodeURIComponent('http://localhost:3001/auth/callback')}` +
    `&scope=${encodeURIComponent('openid profile wallet kyc')}` +
    `&code_challenge=${challenge}&code_challenge_method=S256&state=${b64url(randomBytes(8))}`;
  const r = await fetch(url, { headers: { cookie: jar.header() }, redirect: 'manual' });
  jar.absorb(r);
  const loc = r.headers.get('location');
  if (loc) {
    const p = await fetch(`${baseUrl}${new URL(loc, baseUrl).pathname}`, { headers: { cookie: jar.header() }, redirect: 'manual' });
    jar.absorb(p);
  }
}

/** Register (auto-signs-in) and follow the resume redirects so the OIDC session cookie is set. */
async function signUp(email: string): Promise<CookieJar> {
  const jar = new CookieJar();
  await startInteraction(jar);
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
  let loc: string | null = ((await ver.json()) as { redirectTo: string }).redirectTo;
  for (let i = 0; i < 10 && loc; i++) {
    const url = loc.startsWith('http') ? loc : `${baseUrl}${loc}`;
    if (url.startsWith('http://localhost:3001/auth/callback')) break;
    const hop = await fetch(url, { headers: { cookie: jar.header() }, redirect: 'manual' });
    jar.absorb(hop);
    loc = hop.headers.get('location');
    if (hop.status !== 302 && hop.status !== 303) break;
  }
  return jar;
}

beforeAll(async () => {
  setUserStore(new InMemoryUserStore());
  setWebAuthnStore(new InMemoryWebAuthnCredentialStore());
  const probe = createServer();
  await new Promise<void>((res) => probe.listen(0, '127.0.0.1', res));
  const { port } = probe.address() as AddressInfo;
  probe.close();
  baseUrl = `http://127.0.0.1:${port}`;
  const provider = await createProvider(baseUrl, { googleEnabled: false });
  server = createServer(provider.callback());
  await new Promise<void>((res) => server.listen(port, '127.0.0.1', res));
});
afterAll(async () => {
  await new Promise<void>((res, rej) => server.close((e) => (e ? rej(e) : res())));
});

describe('GET /account (Account Hub)', () => {
  it('renders the signed-out page when there is no session', async () => {
    const res = await fetch(`${baseUrl}/account`, { redirect: 'manual' });
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain('Sign in through any Citrate app');
  });

  it('renders the hub for a signed-in user with a Start-verification CTA + tier', async () => {
    const jar = await signUp('hubuser@example.com');
    const res = await fetch(`${baseUrl}/account`, { headers: { cookie: jar.header() }, redirect: 'manual' });
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain('Your Citrate account');
    expect(html).toContain('hubuser@example.com');
    // KYC not started → the start CTA + (no entitlement) Public tier.
    expect(html).toContain('/kyc/start?level=T3');
    expect(html).toContain('Public');
  });
});
