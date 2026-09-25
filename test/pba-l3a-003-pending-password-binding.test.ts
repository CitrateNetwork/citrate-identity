/**
 * PBA-L3a-003 (MEDIUM) — the pending password stashed with an email code was
 * replaced by whoever requested a code last, and entering the code set THAT
 * password. An attacker who requests a code for the victim's address right after
 * the victim does gets their own password installed when the victim types the
 * (attacker-triggered) code.
 *
 * Fix: the code + pending password are bound to the requesting interaction; a
 * code only verifies inside the interaction that asked for it.
 */
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { createHash, randomBytes } from 'node:crypto';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createProvider } from '../src/server.js';
import { setUserStore, InMemoryUserStore, getUserStore } from '../src/auth/stores.js';
import {
  setEmailVerificationStore,
  InMemoryEmailVerificationStore,
  PgEmailVerificationStore,
  type EmailVerificationStore,
  type PgLike,
} from '../src/auth/email-verification-pg.js';
import { setEmailSender, resetEmailSender } from '../src/email-send.js';
import { verifyPassword } from '../src/auth/password.js';
import { testPg, type TestPg } from './helpers/pg.js';

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
let lastCode: string | null = null;
let db: TestPg;

beforeAll(async () => {
  db = testPg();
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
  await db.close();
  await new Promise<void>((r) => server.close(() => r()));
});

async function interaction(): Promise<Jar> {
  const jar = new Jar();
  const ch = b64u(createHash('sha256').update(b64u(randomBytes(32))).digest());
  const a = await fetch(`${baseUrl}/auth?response_type=code&client_id=citrate-explorer&redirect_uri=${encodeURIComponent('http://localhost:3001/auth/callback')}&scope=openid&code_challenge=${ch}&code_challenge_method=S256&state=s`, { redirect: 'manual' });
  jar.absorb(a);
  jar.absorb(await fetch(`${baseUrl}${new URL(a.headers.get('location')!, baseUrl).pathname}`, { headers: { cookie: jar.header() }, redirect: 'manual' }));
  return jar;
}
const post = (jar: Jar, path: string, body: unknown) =>
  fetch(`${baseUrl}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie: jar.header() },
    body: JSON.stringify(body),
    redirect: 'manual',
  });

const stores: Array<[string, () => Promise<EmailVerificationStore>]> = [
  ['in-memory', async () => new InMemoryEmailVerificationStore()],
  ['postgres', async () => {
    await db.reset(['email_verification_codes']);
    const s = new PgEmailVerificationStore(db.pool as PgLike);
    await s.ensureSchema();
    return s;
  }],
];

for (const [name, make] of stores) {
  describe(`PBA-L3a-003 pending password is bound to the requester (${name} store)`, () => {
    beforeEach(async () => {
      setUserStore(new InMemoryUserStore());
      setEmailVerificationStore(await make());
      lastCode = null;
      setEmailSender(async (msg) => { lastCode = /(\d{6})/.exec(msg.subject)?.[1] ?? null; return true; });
    });

    it('an attacker-triggered code typed into the victim\'s signup does NOT install the attacker\'s password', async () => {
      const victim = await interaction();
      const attacker = await interaction();
      expect((await post(victim, '/auth/password/register', { email: 'victim@example.com', password: 'victim password 12345' })).status).toBe(200);
      // Attacker requests a code for the same address; the victim's inbox gets it.
      expect((await post(attacker, '/auth/password/register', { email: 'victim@example.com', password: 'attacker password 666' })).status).toBe(200);
      const code = lastCode!;
      const r = await post(victim, '/auth/password/verify', { email: 'victim@example.com', code });
      expect(r.status).toBe(401);
      expect(await getUserStore().findByEmail('victim@example.com')).toBeUndefined();
    });

    it('the attacker-triggered code cannot reset an EXISTING account\'s password either', async () => {
      const setup = await interaction();
      await post(setup, '/auth/password/register', { email: 'owner@example.com', password: 'original password 123' });
      expect((await post(setup, '/auth/password/verify', { email: 'owner@example.com', code: lastCode })).status).toBe(200);
      const victim = await interaction();
      const attacker = await interaction();
      await post(attacker, '/auth/password/login', { email: 'owner@example.com', password: 'attacker password 666' });
      // login on a verified account with the WRONG password is a 401, not a code;
      // the reset path is register-with-existing-email:
      await post(attacker, '/auth/password/register', { email: 'owner@example.com', password: 'attacker password 666' });
      const code = lastCode!;
      expect((await post(victim, '/auth/password/verify', { email: 'owner@example.com', code })).status).toBe(401);
      const u = await getUserStore().findByEmail('owner@example.com');
      expect(await verifyPassword('attacker password 666', u!.passwordHash!)).toBe(false);
      expect(await verifyPassword('original password 123', u!.passwordHash!)).toBe(true);
    });

    it('the requester\'s own code still verifies in the interaction that requested it', async () => {
      const victim = await interaction();
      const attacker = await interaction();
      await post(attacker, '/auth/password/register', { email: 'v2@example.com', password: 'attacker password 666' });
      await post(victim, '/auth/password/register', { email: 'v2@example.com', password: 'victim password 12345' });
      const r = await post(victim, '/auth/password/verify', { email: 'v2@example.com', code: lastCode });
      expect(r.status).toBe(200);
      const u = await getUserStore().findByEmail('v2@example.com');
      expect(await verifyPassword('victim password 12345', u!.passwordHash!)).toBe(true);
    });
  });
}

describe('PBA-L3a-003 store-level binding', () => {
  for (const [name, make] of stores) {
    it(`${name}: a code verifies only with its binding; a mismatch burns an attempt`, async () => {
      const s = await make();
      const { code } = await s.issue('a@b.co', 'h', 'bind-A');
      expect(await s.consume('a@b.co', code!, 'bind-B')).toEqual({ ok: false });
      expect(await s.consume('a@b.co', code!)).toEqual({ ok: false });
      expect(await s.consume('a@b.co', code!, 'bind-A')).toEqual({ ok: true, passwordHash: 'h' });
    });
    it(`${name}: an unbound code (legacy issue without binding) still verifies without one`, async () => {
      const s = await make();
      const { code } = await s.issue('c@d.co', 'h');
      expect(await s.consume('c@d.co', code!)).toEqual({ ok: true, passwordHash: 'h' });
    });
  }
});

describe('PBA-L3a-003 schema upgrade', () => {
  it('ensureSchema adds the binding column to a pre-existing table, idempotently', async () => {
    await db.reset(['email_verification_codes']);
    // Build the pre-L3a-003 table shape: today's table minus the binding column.
    await new PgEmailVerificationStore(db.pool as PgLike).ensureSchema();
    await (db.pool as PgLike).query('ALTER TABLE email_verification_codes DROP COLUMN binding');
    const probe = await (db.pool as PgLike).query(
      `SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'email_verification_codes' AND column_name = 'binding'`,
    );
    expect(probe.rows).toHaveLength(0);
    const s = new PgEmailVerificationStore(db.pool as PgLike);
    await s.ensureSchema();
    await s.ensureSchema();
    const { code } = await s.issue('up@example.com', 'h', 'bind');
    expect(await s.consume('up@example.com', code!, 'other')).toEqual({ ok: false });
    expect(await s.consume('up@example.com', code!, 'bind')).toEqual({ ok: true, passwordHash: 'h' });
  });
});
