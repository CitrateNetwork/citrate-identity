/**
 * R2 verifier nit (PBA-L3a-002 / -011): the per-account verify and login budgets
 * let ONE attacker lock a victim out, window after window. The account budget
 * now also has a per-(account, IP) component that one source exhausts first,
 * so a single-source attacker can no longer reach the account-wide cap. The
 * account-wide cap stays (it is what bounds distributed guessing); a
 * distributed attacker (≥3 sources) can still trigger it — tracked as DEFERRED.
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
afterAll(async () => { resetEmailSender(); await new Promise<void>((r) => server.close(() => r())); });
beforeEach(() => {
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
const post = (jar: Jar, path: string, body: unknown, ip: string) =>
  fetch(`${baseUrl}${path}`, { method: 'POST', headers: { 'content-type': 'application/json', cookie: jar.header(), 'x-forwarded-for': ip }, body: JSON.stringify(body) });

describe('single-source attacker cannot lock the victim out', () => {
  it('login: one IP hammering the victim account is cut off before the account cap; the victim still signs in', async () => {
    const u = await getUserStore().createWithEmailPassword({ email: 'victim@example.com', passwordHash: await hashPassword('the real password 123') });
    await getUserStore().markEmailVerified(u.id);
    const jar = await interaction();
    const att: number[] = [];
    for (let i = 0; i < LOGIN_LIMITS.loginPerAccount + 5; i++) att.push((await post(jar, '/auth/password/login', { email: 'victim@example.com', password: `wrong ${i} xxxxxxxx` }, '203.0.113.66')).status);
    expect(att.filter((s) => s !== 429).length).toBe(LOGIN_LIMITS.loginPerAccountIp);
    const victim = await interaction();
    expect((await post(victim, '/auth/password/login', { email: 'victim@example.com', password: 'the real password 123' }, '198.51.100.20')).status).toBe(200);
  });

  it('verify: one IP guessing the victim\'s code is cut off before the account cap', async () => {
    const jar = await interaction();
    const att: number[] = [];
    for (let i = 0; i < LOGIN_LIMITS.verifyPerAccount + 5; i++) att.push((await post(jar, '/auth/password/verify', { email: 'v2@example.com', code: '123456' }, '203.0.113.67')).status);
    expect(att.filter((s) => s !== 429).length).toBe(LOGIN_LIMITS.verifyPerAccountIp);
    expect((await post(jar, '/auth/password/verify', { email: 'v2@example.com', code: '123456' }, '198.51.100.21')).status).not.toBe(429);
  });

  it('the account-wide cap still bounds a distributed attacker', async () => {
    const jar = await interaction();
    const st: number[] = [];
    for (let i = 0; i < 30; i++) st.push((await post(jar, '/auth/password/verify', { email: 'v3@example.com', code: '123456' }, `100.80.0.${i + 1}`)).status);
    expect(st.filter((s) => s !== 429).length).toBe(LOGIN_LIMITS.verifyPerAccount);
  });

  it('per-(account, IP) budgets are below the account caps', () => {
    expect(LOGIN_LIMITS.loginPerAccountIp).toBeLessThan(LOGIN_LIMITS.loginPerAccount);
    expect(LOGIN_LIMITS.verifyPerAccountIp).toBeLessThan(LOGIN_LIMITS.verifyPerAccount);
  });
});
