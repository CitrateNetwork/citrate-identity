/**
 * PBA-L3a-011 (identity part) — no rate limiting on the login endpoints. A
 * password-guessing run against /auth/password/login (per account from many IPs,
 * or per IP across many accounts) now hits 429. The SDK half of the finding
 * (verifyIdToken without exp, refresh sub check) belongs to lane SDK.
 */
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { createHash, randomBytes } from 'node:crypto';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createProvider } from '../src/server.js';
import { setUserStore, InMemoryUserStore, getUserStore } from '../src/auth/stores.js';
import { setEmailVerificationStore, InMemoryEmailVerificationStore } from '../src/auth/email-verification-pg.js';
import { setEmailSender, resetEmailSender } from '../src/email-send.js';
import { hashPassword } from '../src/auth/password.js';
import { LOGIN_LIMITS } from '../src/auth/rate-limit.js';

class Jar {
  m = new Map<string, string>();
  absorb(r: Response): void {
    for (const sc of r.headers.getSetCookie()) {
      const [p] = sc.split(';');
      const i = p.indexOf('=');
      const k = p.slice(0, i).trim(), v = p.slice(i + 1).trim();
      if (!v) this.m.delete(k); else this.m.set(k, v);
    }
  }
  header(): string { return [...this.m].map(([k, v]) => `${k}=${v}`).join('; '); }
}
const b64u = (b: Buffer): string => b.toString('base64url');

let server: Server;
let baseUrl: string;
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
beforeEach(async () => {
  setUserStore(new InMemoryUserStore());
  setEmailVerificationStore(new InMemoryEmailVerificationStore());
  setEmailSender(async () => true);
});

async function interaction(): Promise<Jar> {
  const jar = new Jar();
  const ch = b64u(createHash('sha256').update(b64u(randomBytes(32))).digest());
  const a = await fetch(`${baseUrl}/auth?response_type=code&client_id=citrate-explorer&redirect_uri=${encodeURIComponent('http://localhost:3001/auth/callback')}&scope=openid&code_challenge=${ch}&code_challenge_method=S256&state=s`, { redirect: 'manual' });
  jar.absorb(a);
  jar.absorb(await fetch(`${baseUrl}${new URL(a.headers.get('location')!, baseUrl).pathname}`, { headers: { cookie: jar.header() }, redirect: 'manual' }));
  return jar;
}
const login = (jar: Jar, email: string, password: string, ip: string) =>
  fetch(`${baseUrl}/auth/password/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie: jar.header(), 'x-forwarded-for': ip },
    body: JSON.stringify({ email, password }),
    redirect: 'manual',
  });

describe('PBA-L3a-011 login rate limiting', () => {
  it('per account: password guesses from rotating IPs stop at the budget, and a 429 carries Retry-After', async () => {
    const u = await getUserStore().createWithEmailPassword({ email: 'victim@example.com', passwordHash: await hashPassword('the real password 123') });
    await getUserStore().markEmailVerified(u.id);
    const jar = await interaction();
    const statuses: number[] = [];
    let retryAfter: string | null = null;
    for (let i = 0; i < LOGIN_LIMITS.loginPerAccount + 3; i++) {
      const r = await login(jar, 'victim@example.com', `wrong guess ${i} xxxx`, `100.64.1.${i + 1}`);
      statuses.push(r.status);
      if (r.status === 429) retryAfter = r.headers.get('retry-after');
    }
    expect(statuses.slice(0, LOGIN_LIMITS.loginPerAccount).every((s) => s === 401)).toBe(true);
    expect(statuses.slice(LOGIN_LIMITS.loginPerAccount).every((s) => s === 429)).toBe(true);
    expect(Number(retryAfter)).toBeGreaterThan(0);
    // Once limited, even the right password is refused for the window.
    expect((await login(jar, 'victim@example.com', 'the real password 123', '100.64.9.9')).status).toBe(429);
  });

  it('per IP: one source spraying many accounts is cut off', async () => {
    const jar = await interaction();
    const statuses: number[] = [];
    for (let i = 0; i < LOGIN_LIMITS.loginPerIp + 2; i++) {
      statuses.push((await login(jar, `spray${i}@example.com`, 'Password123 guess', '203.0.113.99')).status);
    }
    expect(statuses.filter((s) => s === 429).length).toBeGreaterThanOrEqual(2);
    expect(statuses.slice(0, LOGIN_LIMITS.loginPerIp).includes(429)).toBe(false);
  });

  it('register (code issuance) is limited per IP', async () => {
    const jar = await interaction();
    const statuses: number[] = [];
    for (let i = 0; i < LOGIN_LIMITS.issuePerIp + 2; i++) {
      const r = await fetch(`${baseUrl}/auth/password/register`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', cookie: jar.header(), 'x-forwarded-for': '203.0.113.123' },
        body: JSON.stringify({ email: `new${i}@example.com`, password: 'a long enough password' }),
      });
      statuses.push(r.status);
    }
    expect(statuses.slice(0, LOGIN_LIMITS.issuePerIp).every((s) => s === 200)).toBe(true);
    expect(statuses.slice(LOGIN_LIMITS.issuePerIp).every((s) => s === 429)).toBe(true);
  });

  it('distinct IPs + distinct accounts are not limited (login and register keys are per IP / per account)', async () => {
    const jar = await interaction();
    for (let i = 0; i < LOGIN_LIMITS.loginPerIp + 5; i++) {
      expect((await login(jar, `fresh${i}@example.com`, 'Password123 guess', `100.70.0.${i + 1}`)).status).not.toBe(429);
    }
    for (let i = 0; i < LOGIN_LIMITS.issuePerIp + 5; i++) {
      const r = await fetch(`${baseUrl}/auth/password/register`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', cookie: jar.header(), 'x-forwarded-for': `100.71.0.${i + 1}` },
        body: JSON.stringify({ email: `reg${i}@example.com`, password: 'a long enough password' }),
      });
      expect(r.status).not.toBe(429);
    }
  });

  it('createProvider honours an injected limiter (the production Redis limiter is wired, not a default)', async () => {
    const probe = createServer();
    await new Promise<void>((r) => probe.listen(0, '127.0.0.1', r));
    const { port } = probe.address() as AddressInfo;
    probe.close();
    const url = `http://127.0.0.1:${port}`;
    const p2 = await createProvider(url, { googleEnabled: false, rateLimiter: { hit: async () => false } });
    const s2 = createServer(p2.callback());
    await new Promise<void>((r) => s2.listen(port, '127.0.0.1', r));
    try {
      const saved = baseUrl;
      baseUrl = url;
      const jar = await interaction();
      const r = await login(jar, 'anyone@example.com', 'Password123 guess', '100.72.0.1');
      baseUrl = saved;
      expect(r.status).toBe(429);
    } finally {
      await new Promise<void>((r) => s2.close(() => r()));
    }
  });

  it('the per-IP key uses the proxy-appended (rightmost) XFF entry, so a spoofed left entry does not reset it', async () => {
    const jar = await interaction();
    const statuses: number[] = [];
    for (let i = 0; i < LOGIN_LIMITS.loginPerIp + 2; i++) {
      statuses.push((await login(jar, `sp${i}@example.com`, 'Password123 guess', `9.9.9.${i}, 198.18.0.1`)).status);
    }
    expect(statuses).toContain(429);
  });
});
