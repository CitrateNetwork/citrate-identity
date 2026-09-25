/**
 * PBA-L3a-002 (HIGH) — the email-code attempt cap was a read-then-write, so
 * concurrent wrong guesses all read the same counter: 200 concurrent guesses were
 * processed against a MAX_ATTEMPTS=5 cap and the real code still verified.
 *
 * Inverted PoC + tripwire. Runs on REAL Postgres when IDENTITY_TEST_PG_URL is set
 * (the skeptic asked for a repro "through the HTTP route against real Postgres"),
 * otherwise on pg-mem with a latency shim that interleaves the queries.
 */
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { createHash, randomBytes } from 'node:crypto';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  PgEmailVerificationStore,
  MAX_ATTEMPTS,
  setEmailVerificationStore,
  InMemoryEmailVerificationStore,
  type PgLike,
} from '../src/auth/email-verification-pg.js';
import { createProvider } from '../src/server.js';
import { setUserStore, InMemoryUserStore, getUserStore } from '../src/auth/stores.js';
import { setEmailSender, resetEmailSender } from '../src/email-send.js';
import { testPg, type TestPg } from './helpers/pg.js';

/** Model real round-trip latency so pg-mem interleaves concurrent statements. */
function withLatency(inner: PgLike, ms = 2): PgLike {
  return { query: async (t, p) => { await new Promise((r) => setTimeout(r, ms)); return inner.query(t, p); } };
}

/**
 * Comparison oracle: every code comparison needs the stored `code_hash` in hand,
 * so count the statements that hand one back. The fix must keep this at
 * MAX_ATTEMPTS per issued code however the guesses are interleaved.
 */
const counter = { hashReads: 0 };
function counting(inner: PgLike): PgLike {
  return {
    query: async (t, p) => {
      const r = await inner.query(t, p);
      const first = r.rows[0] as Record<string, unknown> | undefined;
      if (first && 'code_hash' in first) counter.hashReads += r.rows.length;
      return r;
    },
  };
}

let db: TestPg;
beforeAll(() => { db = testPg(); });
afterAll(async () => { await db.close(); });

async function freshStore(): Promise<PgEmailVerificationStore> {
  await db.reset(['email_verification_codes']);
  counter.hashReads = 0;
  const s = new PgEmailVerificationStore(counting(withLatency(db.pool as PgLike)));
  await s.ensureSchema();
  return s;
}

const wrongGuesses = (code: string, n: number): string[] =>
  Array.from({ length: n }, (_, i) => String((Number(code) + 1 + i) % 1_000_000).padStart(6, '0'));

describe(`PBA-L3a-002 store: attempt cap holds under concurrency (${process.env.IDENTITY_TEST_PG_URL ? 'real Postgres' : 'pg-mem'})`, () => {
  it('the audit PoC is dead: 200 concurrent wrong guesses, then the real code is REJECTED', async () => {
    const store = await freshStore();
    const { code } = await store.issue('victim@example.com', 'attacker-argon-hash');
    const results = await Promise.all(wrongGuesses(code!, 200).map((g) => store.consume('victim@example.com', g)));
    expect(results.every((r) => !r.ok)).toBe(true);
    expect(counter.hashReads).toBeLessThanOrEqual(MAX_ATTEMPTS);
    const hit = await store.consume('victim@example.com', code!);
    expect(hit.ok).toBe(false);
    expect(hit.passwordHash).toBeUndefined();
  });

  it('tripwire: at most MAX_ATTEMPTS comparisons per code — a correct guess buried in a concurrent burst never lands', async () => {
    for (let trial = 0; trial < 5; trial++) {
      const store = await freshStore();
      const { code } = await store.issue('victim@example.com', 'h');
      const guesses = wrongGuesses(code!, 60);
      guesses.splice(30, 0, code!); // real code at position 30, well past the cap
      const results = await Promise.all(guesses.map((g) => store.consume('victim@example.com', g)));
      expect(results.filter((r) => r.ok)).toHaveLength(0);
    }
  });

  it('the cap is exactly MAX_ATTEMPTS: the right code on the last allowed attempt still verifies', async () => {
    const store = await freshStore();
    const { code } = await store.issue('user@example.com', 'h');
    for (const g of wrongGuesses(code!, MAX_ATTEMPTS - 1)) expect((await store.consume('user@example.com', g)).ok).toBe(false);
    expect(await store.consume('user@example.com', code!)).toEqual({ ok: true, passwordHash: 'h' });
  });

  it('single-use under concurrency: two simultaneous correct submissions → exactly one succeeds', async () => {
    const store = await freshStore();
    const { code } = await store.issue('user@example.com', 'h');
    const results = await Promise.all([store.consume('user@example.com', code!), store.consume('user@example.com', code!)]);
    expect(results.filter((r) => r.ok)).toHaveLength(1);
    expect(results).toContainEqual({ ok: false });
  });

  it('the last allowed wrong guess deletes the row immediately (no dead code left behind)', async () => {
    const store = await freshStore();
    const { code } = await store.issue('user@example.com', 'h');
    for (const g of wrongGuesses(code!, MAX_ATTEMPTS - 1)) await store.consume('user@example.com', g);
    const before = await (db.pool as PgLike).query('SELECT attempts FROM email_verification_codes WHERE email = $1', ['user@example.com']);
    expect(before.rows).toHaveLength(1);
    expect(await store.consume('user@example.com', wrongGuesses(code!, MAX_ATTEMPTS)[MAX_ATTEMPTS - 1]!)).toEqual({ ok: false });
    const after = await (db.pool as PgLike).query('SELECT attempts FROM email_verification_codes WHERE email = $1', ['user@example.com']);
    expect(after.rows).toHaveLength(0);
  });

  it('a code issued without a password returns ok with no passwordHash key', async () => {
    const store = await freshStore();
    const { code } = await store.issue('user@example.com');
    expect(await store.consume('user@example.com', code!)).toEqual({ ok: true });
  });

  it('an expired code is rejected and removed', async () => {
    const store = await freshStore();
    const { code } = await store.issue('user@example.com', 'h');
    await (db.pool as PgLike).query(
      `UPDATE email_verification_codes SET expires_at = $2 WHERE email = $1`,
      ['user@example.com', new Date(Date.now() - 1000).toISOString()],
    );
    expect((await store.consume('user@example.com', code!)).ok).toBe(false);
    const { rows } = await (db.pool as PgLike).query('SELECT 1 FROM email_verification_codes WHERE email = $1', ['user@example.com']);
    expect(rows).toHaveLength(0);
  });
});

// ── through the real HTTP route ────────────────────────────────────────────
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

describe('PBA-L3a-002 HTTP: /auth/password/verify burst against the Postgres store', () => {
  let server: Server;
  let baseUrl: string;
  let lastCode: string | null = null;

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
    setEmailVerificationStore(new InMemoryEmailVerificationStore());
    await new Promise<void>((r) => server.close(() => r()));
  });
  beforeEach(async () => {
    setUserStore(new InMemoryUserStore());
    setEmailVerificationStore(await freshStore());
    lastCode = null;
    setEmailSender(async (msg) => { lastCode = /(\d{6})/.exec(msg.subject)?.[1] ?? null; return true; });
  });

  async function interaction(): Promise<Jar> {
    const jar = new Jar();
    const ch = b64u(createHash('sha256').update(b64u(randomBytes(32))).digest());
    const a = await fetch(`${baseUrl}/auth?response_type=code&client_id=citrate-explorer&redirect_uri=${encodeURIComponent('http://localhost:3001/auth/callback')}&scope=openid&code_challenge=${ch}&code_challenge_method=S256&state=s`, { redirect: 'manual' });
    jar.absorb(a);
    const loc = a.headers.get('location')!;
    jar.absorb(await fetch(`${baseUrl}${new URL(loc, baseUrl).pathname}`, { headers: { cookie: jar.header() }, redirect: 'manual' }));
    return jar;
  }
  const post = (jar: Jar, path: string, body: unknown, ip = '203.0.113.7') =>
    fetch(`${baseUrl}${path}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: jar.header(), 'x-forwarded-for': ip },
      body: JSON.stringify(body),
      redirect: 'manual',
    });

  it('a concurrent wrong-code burst burns the code: the real code no longer signs in, and the row is gone', async () => {
    const jar = await interaction();
    expect((await post(jar, '/auth/password/register', { email: 'victim@example.com', password: 'attacker chosen password 1' })).status).toBe(200);
    const code = lastCode!;
    expect(code).toMatch(/^\d{6}$/);
    // Spread over many source IPs so the per-IP limiter is not what stops it.
    const burst = await Promise.all(
      wrongGuesses(code, 200).map((g, i) => post(jar, '/auth/password/verify', { email: 'victim@example.com', code: g }, `198.51.${100 + (i >> 8)}.${(i % 250) + 1}`)),
    );
    expect(burst.every((r) => r.status !== 200)).toBe(true);
    // At most MAX_ATTEMPTS guesses were ever compared against the stored hash.
    expect(counter.hashReads).toBeLessThanOrEqual(MAX_ATTEMPTS);
    const { rows } = await (db.pool as PgLike).query('SELECT attempts FROM email_verification_codes WHERE email = $1', ['victim@example.com']);
    expect(rows).toHaveLength(0); // cap reached → code invalidated
    const real = await post(jar, '/auth/password/verify', { email: 'victim@example.com', code }, '192.0.2.200');
    expect(real.status).not.toBe(200);
    expect(await getUserStore().findByEmail('victim@example.com')).toBeUndefined();
  });

  it('per-IP rate limit on code verification (with L3a-011): one IP gets 429 before exhausting guesses across codes', async () => {
    const jar = await interaction();
    await post(jar, '/auth/password/register', { email: 'someone@example.com', password: 'a password that is long' }, '203.0.113.50');
    const statuses: number[] = [];
    for (let i = 0; i < 40; i++) {
      statuses.push((await post(jar, '/auth/password/verify', { email: `x${i}@example.com`, code: '123456' }, '203.0.113.50')).status);
    }
    expect(statuses).toContain(429);
    expect(statuses.filter((s) => s !== 429).length).toBeLessThanOrEqual(30);
  });

  it('per-account rate limit on code verification: many IPs, one email → 429', async () => {
    const jar = await interaction();
    const statuses: number[] = [];
    for (let i = 0; i < 25; i++) {
      statuses.push((await post(jar, '/auth/password/verify', { email: 'target@example.com', code: '123456' }, `100.64.0.${i + 1}`)).status);
    }
    expect(statuses).toContain(429);
    expect(statuses.filter((s) => s !== 429).length).toBeLessThanOrEqual(15);
  });

  it('distinct IPs and distinct accounts do not share a budget (keys are per IP and per account)', async () => {
    const jar = await interaction();
    const statuses: number[] = [];
    for (let i = 0; i < 40; i++) {
      statuses.push((await post(jar, '/auth/password/verify', { email: `solo${i}@example.com`, code: '123456' }, `100.65.0.${i + 1}`)).status);
    }
    expect(statuses).not.toContain(429);
  });

  it('a 429 is the documented shape with Retry-After = the window', async () => {
    const jar = await interaction();
    let last: Response | undefined;
    for (let i = 0; i < 20; i++) last = await post(jar, '/auth/password/verify', { email: 'shape@example.com', code: '123456' }, `100.66.0.${i + 1}`);
    expect(last!.status).toBe(429);
    expect(last!.headers.get('retry-after')).toBe('900');
    expect(await last!.json()).toMatchObject({ error: 'too_many_requests' });
  });
});
