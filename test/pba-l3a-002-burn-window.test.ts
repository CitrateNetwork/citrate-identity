/**
 * PBA-L3a-002 residual (found by the R2 verifier, verify-evidence/v-002.test.ts
 * "BYPASS: burning a code…"): exhausting a code's 5 attempts DELETED the row,
 * which also reset the per-email send window. Burn, re-issue, burn … gave 10
 * codes per inbox per window (budget 5) and 50 store comparisons (budget 25).
 *
 * Fix under test: a burned / expired code keeps its row (send_count + window);
 * only a SUCCESSFUL verify deletes it.
 */
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { createHash, randomBytes } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  PgEmailVerificationStore,
  InMemoryEmailVerificationStore,
  MAX_ATTEMPTS,
  MAX_SENDS_PER_WINDOW,
  setEmailVerificationStore,
  type EmailVerificationStore,
  type PgLike,
} from '../src/auth/email-verification-pg.js';
import { createProvider } from '../src/server.js';
import { setUserStore, InMemoryUserStore } from '../src/auth/stores.js';
import { setEmailSender, resetEmailSender } from '../src/email-send.js';
import type { RateLimiter } from '../src/auth/rate-limit.js';
import { testPg, type TestPg } from './helpers/pg.js';

let compares = 0;
function counting(inner: PgLike): PgLike {
  return {
    query: async (t, p) => {
      const r = await inner.query(t, p);
      if (/^\s*UPDATE email_verification_codes SET attempts/i.test(t)) compares += r.rows.length;
      return r;
    },
  };
}

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
const allowAll: RateLimiter = { hit: async () => true };

let db: TestPg;
let sent = 0;
let lastCode: string | null = null;
beforeAll(() => {
  db = testPg();
  setEmailSender(async (msg) => { lastCode = /(\d{6})/.exec(msg.subject)?.[1] ?? null; sent++; return true; });
});
afterAll(async () => {
  resetEmailSender();
  setEmailVerificationStore(new InMemoryEmailVerificationStore());
  await db.close();
});

async function boot(rateLimiter?: RateLimiter): Promise<{ server: Server; baseUrl: string }> {
  const probe = createServer();
  await new Promise<void>((r) => probe.listen(0, '127.0.0.1', r));
  const { port } = probe.address() as AddressInfo;
  probe.close();
  const baseUrl = `http://127.0.0.1:${port}`;
  const provider = await createProvider(baseUrl, { googleEnabled: false, ...(rateLimiter ? { rateLimiter } : {}) });
  const server = createServer(provider.callback());
  await new Promise<void>((r) => server.listen(port, '127.0.0.1', r));
  return { server, baseUrl };
}
async function interaction(baseUrl: string): Promise<Jar> {
  const jar = new Jar();
  const ch = b64u(createHash('sha256').update(b64u(randomBytes(32))).digest());
  const a = await fetch(`${baseUrl}/auth?response_type=code&client_id=citrate-explorer&redirect_uri=${encodeURIComponent('http://localhost:3001/auth/callback')}&scope=openid&code_challenge=${ch}&code_challenge_method=S256&state=s`, { redirect: 'manual' });
  jar.absorb(a);
  jar.absorb(await fetch(`${baseUrl}${new URL(a.headers.get('location')!, baseUrl).pathname}`, { headers: { cookie: jar.header() }, redirect: 'manual' }));
  return jar;
}
const post = (baseUrl: string, jar: Jar, path: string, body: unknown, ip: string) =>
  fetch(`${baseUrl}${path}`, { method: 'POST', headers: { 'content-type': 'application/json', cookie: jar.header(), 'x-forwarded-for': ip }, body: JSON.stringify(body) });

const stores: Array<[string, () => Promise<EmailVerificationStore>]> = [
  ['postgres', async () => {
    await db.reset(['email_verification_codes']);
    const s = new PgEmailVerificationStore(counting(db.pool as PgLike));
    await s.ensureSchema();
    return s;
  }],
  ['in-memory', async () => new InMemoryEmailVerificationStore()],
];

for (const [name, make] of stores) {
  describe(`PBA-L3a-002 residual: burning a code does not reset the send window (${name})`, () => {
    for (const [label, lim] of [['limiter off', allowAll], ['default limiter', undefined]] as const) {
      it(`burn / re-issue cycles stay within ${MAX_SENDS_PER_WINDOW} codes per window (${label})`, async () => {
        setUserStore(new InMemoryUserStore());
        setEmailVerificationStore(await make());
        sent = 0; compares = 0;
        const { server, baseUrl } = await boot(lim);
        try {
          const jar = await interaction(baseUrl);
          let n = 0;
          for (let cycle = 0; cycle < 10; cycle++) {
            await post(baseUrl, jar, '/auth/password/register', { email: 'burn@example.com', password: 'attacker chosen password 1' }, `11.0.${cycle}.${n++ & 255}`);
            for (let k = 0; k < MAX_ATTEMPTS; k++) {
              const guess = lastCode === '000000' ? '000001' : '000000';
              await post(baseUrl, jar, '/auth/password/verify', { email: 'burn@example.com', code: guess }, `12.${cycle}.${k}.${n++ & 255}`);
            }
          }
          expect(sent).toBeLessThanOrEqual(MAX_SENDS_PER_WINDOW);
          if (name === 'postgres') expect(compares).toBeLessThanOrEqual(MAX_SENDS_PER_WINDOW * MAX_ATTEMPTS);
        } finally {
          await new Promise<void>((r) => server.close(() => r()));
        }
      }, 60_000);
    }

    it('a burned code stays unusable, and a success still deletes the row (single use)', async () => {
      const s = await make();
      const { code } = await s.issue('x@example.com', 'h');
      const wrong = code === '000000' ? '000001' : '000000';
      for (let k = 0; k < MAX_ATTEMPTS; k++) await s.consume('x@example.com', wrong);
      expect(await s.consume('x@example.com', code!)).toEqual({ ok: false });
      const again = await s.issue('x@example.com', 'h2');
      expect(again.rateLimited).toBe(false);
      expect(await s.consume('x@example.com', again.code!)).toEqual({ ok: true, passwordHash: 'h2' });
      expect(await s.consume('x@example.com', again.code!)).toEqual({ ok: false });
    });
  });
}
