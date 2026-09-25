/**
 * PBA-L3a-001 (HIGH) — the KYC admin console was cross-site-request-forgeable.
 *
 * The audit PoC (evidence/pba-l3a-001-admin-kyc-csrf.test.ts) showed a
 * cross-site `text/plain` POST carrying an admin's panva `_session` cookie
 * (SameSite=None by library default) flip an attacker's KYC case to `verified`.
 * This is that PoC inverted, through the real createProvider() app and a real
 * SIWE admin login — plus the tripwire: EVERY admin state-changing route rejects
 * a cross-site / wrong-content-type / token-less POST.
 */
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { randomBytes } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { privateKeyToAccount } from 'viem/accounts';
import type { Hex } from 'viem';
import { newDb } from 'pg-mem';
import { createProvider } from '../src/server.js';
import { setKycProvider } from '../src/kyc-providers/index.js';
import { InhouseKycProvider } from '../src/kyc-providers/inhouse.js';
import { KycCaseStore } from '../src/kyc-cases-pg.js';
import { KycAuditLog, setKycAuditLog } from '../src/kyc-audit-pg.js';
import { newDek, wrapDek } from '../src/kyc-crypto.js';
import * as adminRoutes from '../src/admin-kyc-routes.js';
import { readFileSync } from 'node:fs';
import { Jar, openConsole, sameOriginJson, siweLogin } from './helpers/admin-session.js';

/** Every admin POST route. The source-scan test below keeps this list honest. */
const ROUTES = [
  '/admin/kyc/adjudicate',
  '/admin/kyc/unlock/request',
  '/admin/kyc/unlock/approve',
  '/admin/kyc/delete',
  '/admin/kyc/dsar/request',
  '/admin/kyc/dsar/approve',
];

const admin = privateKeyToAccount(`0x${'c3'.repeat(32)}` as Hex);
let server: Server;
let baseUrl: string;
let store: KycCaseStore;
const master = randomBytes(32);
const jar = new Jar();
let csrf = '';

beforeAll(async () => {
  const db = newDb();
  const pg = db.adapters.createPg();
  store = new KycCaseStore(new pg.Pool());
  const audit = new KycAuditLog(new pg.Pool());
  await store.ensureSchema();
  await audit.ensureSchema();
  const probe = createServer();
  await new Promise<void>((r) => probe.listen(0, '127.0.0.1', r));
  const { port } = probe.address() as AddressInfo;
  probe.close();
  baseUrl = `http://127.0.0.1:${port}`;
  const oidc = await createProvider(baseUrl, { googleEnabled: false });
  setKycProvider(new InhouseKycProvider({ mode: 'sandbox', store, masterKey: master, sessionSecret: 's', webhookSecret: 'wh', captureBaseUrl: `${baseUrl}/verify` }));
  setKycAuditLog(audit);
  process.env.KYC_ADMIN_SUBS = admin.address;
  server = createServer(oidc.callback());
  await new Promise<void>((r) => server.listen(port, '127.0.0.1', r));
  await siweLogin(baseUrl, admin, jar);
  csrf = await openConsole(baseUrl, jar);
});
afterAll(async () => {
  setKycProvider(undefined);
  setKycAuditLog(undefined);
  delete process.env.KYC_ADMIN_SUBS;
  await new Promise<void>((r) => server.close(() => r()));
});

async function pendingCase(): Promise<string> {
  const c = await store.createCase(`0xAttacker${randomBytes(4).toString('hex')}`, wrapDek(newDek(), master));
  await store.setDecision(c.caseId, { decision: 'needs-review', retentionUntil: Date.now() + 864e5 });
  return c.caseId;
}

/**
 * Every /admin/kyc/... path literal in a source text: single-, double- or
 * back-quoted, any path characters (hyphens, digits, template placeholders).
 * The old `[a-z/]+` scan silently skipped such paths (R2 verifier nit).
 */
export function scanAdminPaths(src: string): Set<string> {
  return new Set([...src.matchAll(/['"`](\/admin\/kyc\/[^'"`\s?#]+)['"`]/g)].map((m) => m[1]!));
}

describe('PBA-L3a-001 admin console CSRF', () => {
  it('the route scan sees hyphenated, numeric, template and double-quoted paths', () => {
    const planted = [
      "if (ctx.path === '/admin/kyc/re-verify') {}",
      'if (ctx.path === "/admin/kyc/v2/export") {}',
      'const p = `/admin/kyc/${id}/purge`;',
      "if (ctx.path === '/admin/kyc/case_2') {}",
    ].join('\n');
    expect([...scanAdminPaths(planted)].sort()).toEqual(['/admin/kyc/${id}/purge', '/admin/kyc/case_2', '/admin/kyc/re-verify', '/admin/kyc/v2/export']);
    // …and a planted unguarded hyphenated route would fail the tripwire below.
    const guarded = (adminRoutes as { ADMIN_STATE_CHANGING_ROUTES?: readonly string[] }).ADMIN_STATE_CHANGING_ROUTES ?? [];
    const readOnly = (adminRoutes as { ADMIN_READ_ROUTES?: readonly string[] }).ADMIN_READ_ROUTES ?? [];
    expect([...guarded, ...readOnly]).not.toContain('/admin/kyc/re-verify');
  });

  it('tripwire: every /admin/kyc/* path in the route source is guarded and covered here', () => {
    const src = readFileSync(new URL('../src/admin-kyc-routes.ts', import.meta.url), 'utf8');
    const declared = scanAdminPaths(src);
    expect(declared.size).toBeGreaterThanOrEqual(6);
    const guarded = (adminRoutes as { ADMIN_STATE_CHANGING_ROUTES?: readonly string[] }).ADMIN_STATE_CHANGING_ROUTES ?? [];
    const readOnly = (adminRoutes as { ADMIN_READ_ROUTES?: readonly string[] }).ADMIN_READ_ROUTES ?? [];
    for (const p of declared) {
      if (p === '/admin/kyc/callback') continue;
      expect([...guarded, ...readOnly], `${p} is neither a guarded POST nor a declared read route`).toContain(p);
    }
    for (const p of guarded) expect(ROUTES, `${p} is not exercised by this CSRF test`).toContain(p);
  });

  it('the panva _session cookie is no longer SameSite=None', () => {
    const sess = jar.raw.find((c) => c.startsWith('_session='));
    expect(sess).toBeDefined();
    expect(sess!.toLowerCase()).not.toContain('samesite=none');
    expect(sess!.toLowerCase()).toMatch(/samesite=(lax|strict)/);
  });

  it('the console mints a SameSite=Strict admin cookie and embeds a CSRF token', () => {
    const adm = jar.raw.find((c) => c.startsWith('_kyc_admin='));
    expect(adm).toBeDefined();
    expect(adm!.toLowerCase()).toContain('samesite=strict');
    expect(adm!.toLowerCase()).toContain('httponly');
    expect(csrf.length).toBeGreaterThan(20);
  });

  it('the audit PoC is dead: a cross-site text/plain POST cannot adjudicate', async () => {
    const caseId = await pendingCase();
    const body = `{"caseId":"${caseId}","decision":"verified","reason":"x","p":"="}`;
    const r = await fetch(`${baseUrl}/admin/kyc/adjudicate`, {
      method: 'POST',
      headers: { 'content-type': 'text/plain', origin: 'https://evil.example', 'sec-fetch-site': 'cross-site', cookie: jar.header() },
      body,
    });
    expect(r.status).toBe(403);
    expect((await store.getCase(caseId))?.status).not.toBe('verified');
  });

  // Tripwire: every admin state-changing route, every CSRF shape.
  const attacks: Array<[string, (h: Record<string, string>) => Record<string, string>]> = [
    ['cross-site Origin', (h) => ({ ...h, origin: 'https://evil.example', 'sec-fetch-site': 'cross-site' })],
    ['same-site sibling origin', (h) => ({ ...h, origin: 'https://explorer.citrate.ai', 'sec-fetch-site': 'same-site' })],
    ['no Origin header', (h) => { const { origin: _o, ...rest } = h; return rest; }],
    ['text/plain body', (h) => ({ ...h, 'content-type': 'text/plain' })],
    ['form-urlencoded body', (h) => ({ ...h, 'content-type': 'application/x-www-form-urlencoded' })],
    ['missing CSRF token', (h) => { const { 'x-csrf-token': _t, ...rest } = h; return rest; }],
    ['wrong CSRF token', (h) => ({ ...h, 'x-csrf-token': 'A'.repeat(43) })],
  ];
  for (const route of ROUTES) {
    for (const [name, mutate] of attacks) {
      it(`${route} rejects ${name}`, async () => {
        const caseId = await pendingCase();
        const r = await fetch(`${baseUrl}${route}`, {
          method: 'POST',
          headers: mutate(sameOriginJson(baseUrl, jar, csrf)),
          body: JSON.stringify({ caseId, decision: 'verified', reason: 'x', sub: 'x', unlockId: 'x', requestId: 'x' }),
        });
        expect(r.status).toBe(403);
        expect(((await r.json()) as { error: string }).error).toBe('csrf_rejected');
        expect((await store.getCase(caseId))?.status).not.toBe('verified');
      });
    }
  }

  it('a POST without the strict admin cookie is rejected even with a valid token', async () => {
    const caseId = await pendingCase();
    const h = sameOriginJson(baseUrl, jar, csrf);
    h.cookie = h.cookie.split('; ').filter((c) => !c.startsWith('_kyc_admin=')).join('; ');
    const r = await fetch(`${baseUrl}/admin/kyc/adjudicate`, { method: 'POST', headers: h, body: JSON.stringify({ caseId, decision: 'verified', reason: 'x' }) });
    expect(r.status).toBe(403);
  });

  it('the same admin\'s CSRF token from a DIFFERENT session is refused (token is session-bound)', async () => {
    const jar2 = new Jar();
    await siweLogin(baseUrl, admin, jar2);
    const csrf2 = await openConsole(baseUrl, jar2);
    expect(csrf2).not.toBe(csrf);
    const caseId = await pendingCase();
    // session 1's cookies + session 2's token (and the reverse) both fail
    for (const [j, t] of [[jar, csrf2], [jar2, csrf]] as const) {
      const r = await fetch(`${baseUrl}/admin/kyc/adjudicate`, { method: 'POST', headers: sameOriginJson(baseUrl, j, t), body: JSON.stringify({ caseId, decision: 'verified', reason: 'x' }) });
      expect(r.status).toBe(403);
    }
    expect((await store.getCase(caseId))?.status).not.toBe('verified');
    // each session with its own token still works
    const ok = await fetch(`${baseUrl}/admin/kyc/adjudicate`, { method: 'POST', headers: sameOriginJson(baseUrl, jar2, csrf2), body: JSON.stringify({ caseId, decision: 'verified', reason: 'x' }) });
    expect(ok.status).toBe(200);
  });

  it('every admin console response forbids framing (clickjacking)', async () => {
    const page = await fetch(`${baseUrl}/admin/kyc`, { headers: { cookie: jar.header(), accept: 'text/html' } });
    const api = await fetch(`${baseUrl}/admin/kyc/cases`, { headers: { cookie: jar.header(), 'sec-fetch-site': 'same-origin' } });
    const denied = await fetch(`${baseUrl}/admin/kyc/cases`);
    for (const r of [page, api, denied]) {
      expect(r.headers.get('x-frame-options')).toBe('DENY');
      expect(r.headers.get('content-security-policy')).toContain("frame-ancestors 'none'");
    }
  });

  it('a cross-origin credentialed GET of the case list is refused', async () => {
    const r = await fetch(`${baseUrl}/admin/kyc/cases`, {
      headers: { origin: 'https://explorer.citrate.ai', 'sec-fetch-site': 'same-site', cookie: jar.header() },
    });
    expect(r.status).toBe(403);
    expect(r.headers.get('access-control-allow-origin')).toBeNull();
  });

  it('the legitimate same-origin console flow still adjudicates', async () => {
    const caseId = await pendingCase();
    const r = await fetch(`${baseUrl}/admin/kyc/adjudicate`, {
      method: 'POST',
      headers: sameOriginJson(baseUrl, jar, csrf),
      body: JSON.stringify({ caseId, decision: 'verified', reason: 'ok' }),
    });
    expect(r.status).toBe(200);
    expect((await store.getCase(caseId))?.status).toBe('verified');
    const list = await fetch(`${baseUrl}/admin/kyc/cases`, { headers: { 'sec-fetch-site': 'same-origin', cookie: jar.header() } });
    expect(list.status).toBe(200);
  });
});

describe('PBA-L3a-001 guard helpers (mutation-hardening)', () => {
  const { adminBinding, isSameOrigin, isJsonContentType } = adminRoutes.__testing;
  const req = (headers: Record<string, string>) => ({ headers }) as never;
  const ISS = 'https://auth.citrate.ai';

  it('isSameOrigin: Sec-Fetch-Site other than same-origin is refused even with the right Origin', () => {
    expect(isSameOrigin(req({ 'sec-fetch-site': 'cross-site', origin: ISS }), ISS, true)).toBe(false);
    expect(isSameOrigin(req({ 'sec-fetch-site': 'same-site', origin: ISS }), ISS, true)).toBe(false);
    expect(isSameOrigin(req({ 'sec-fetch-site': 'none', origin: ISS }), ISS, true)).toBe(false);
    expect(isSameOrigin(req({ 'sec-fetch-site': 'same-origin', origin: ISS }), ISS, true)).toBe(true);
  });
  it('isSameOrigin: Origin must equal the issuer origin; absent only allowed when not required', () => {
    expect(isSameOrigin(req({ origin: ISS }), ISS, true)).toBe(true);
    expect(isSameOrigin(req({ origin: 'https://evil.example' }), ISS, false)).toBe(false);
    expect(isSameOrigin(req({}), ISS, true)).toBe(false);
    expect(isSameOrigin(req({}), ISS, false)).toBe(true);
    expect(isSameOrigin(req({ 'sec-fetch-site': 'same-origin' }), ISS, false)).toBe(true);
    // An empty header is treated as absent, not as a value.
    expect(isSameOrigin(req({ origin: '' }), ISS, false)).toBe(true);
    expect(isSameOrigin(req({ origin: '' }), ISS, true)).toBe(false);
  });
  it('isJsonContentType: media type only, parameters and case ignored', () => {
    expect(isJsonContentType(req({ 'content-type': 'application/json' }))).toBe(true);
    expect(isJsonContentType(req({ 'content-type': 'Application/JSON; charset=utf-8' }))).toBe(true);
    expect(isJsonContentType(req({ 'content-type': ' application/json ;x=1' }))).toBe(true);
    expect(isJsonContentType(req({ 'content-type': 'text/plain' }))).toBe(false);
    expect(isJsonContentType(req({ 'content-type': 'application/json-patch+json' }))).toBe(false);
    expect(isJsonContentType(req({}))).toBe(false);
  });
  it('adminBinding: cookie and CSRF values differ, are per-session, and are keyed on COOKIE_KEYS[0]', () => {
    const prev = process.env.COOKIE_KEYS;
    try {
      process.env.COOKIE_KEYS = ' , k-one-000000000000000000000000000, k-two';
      const a = adminBinding('cookie', 'sess-1');
      expect(adminBinding('csrf', 'sess-1')).not.toBe(a);
      expect(adminBinding('cookie', 'sess-2')).not.toBe(a);
      process.env.COOKIE_KEYS = 'k-one-000000000000000000000000000';
      expect(adminBinding('cookie', 'sess-1')).toBe(a);
      process.env.COOKIE_KEYS = 'k-two';
      expect(adminBinding('cookie', 'sess-1')).not.toBe(a);
      delete process.env.COOKIE_KEYS;
      const dflt = adminBinding('cookie', 'sess-1');
      process.env.COOKIE_KEYS = 'citrate-identity-dev-cookie-key';
      expect(adminBinding('cookie', 'sess-1')).toBe(dflt);
    } finally {
      if (prev === undefined) delete process.env.COOKIE_KEYS;
      else process.env.COOKIE_KEYS = prev;
    }
  });
});
