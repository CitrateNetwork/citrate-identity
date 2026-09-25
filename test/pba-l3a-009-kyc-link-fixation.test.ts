/**
 * PBA-L3a-009 (LOW) — KYC link fixation. /kyc/start redirects to
 * /verify?session=<capture token>, and that token alone authorised the whole
 * capture: an attacker could start KYC for THEIR account, send the link to a
 * victim, and the victim's ID + face would verify the attacker's account.
 *
 * Fix under test: /kyc/start binds the capture token to the browser that started
 * it (an HttpOnly cookie whose hash is inside the signed token); the capture API
 * refuses a desktop token without that cookie. Phone hand-off tokens (minted by
 * the bound browser for the QR code) stay cookie-less.
 */
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { randomBytes } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { newDb } from 'pg-mem';
import { createProvider } from '../src/server.js';
import { setKycProvider } from '../src/kyc-providers/index.js';
import { InhouseKycProvider } from '../src/kyc-providers/inhouse.js';
import { KycCaseStore } from '../src/kyc-cases-pg.js';
import { InMemoryHandoffStore } from '../src/handoff-store.js';
import { Jar } from './helpers/admin-session.js';

let server: Server;
let baseUrl: string;
const handoffs = new InMemoryHandoffStore();
let savedVendor: string | undefined;

beforeAll(async () => {
  const db = newDb();
  const store = new KycCaseStore(new (db.adapters.createPg().Pool)());
  await store.ensureSchema();
  const probe = createServer();
  await new Promise<void>((r) => probe.listen(0, '127.0.0.1', r));
  const { port } = probe.address() as AddressInfo;
  probe.close();
  baseUrl = `http://127.0.0.1:${port}`;
  savedVendor = process.env.KYC_PROVIDER;
  process.env.KYC_PROVIDER = 'inhouse';
  const oidc = await createProvider(baseUrl, { googleEnabled: false, handoffStore: handoffs });
  setKycProvider(new InhouseKycProvider({ mode: 'sandbox', store, masterKey: randomBytes(32), sessionSecret: 'sess', webhookSecret: 'wh', captureBaseUrl: `${baseUrl}/verify` }));
  server = createServer(oidc.callback());
  await new Promise<void>((r) => server.listen(port, '127.0.0.1', r));
});
afterAll(async () => {
  setKycProvider(undefined);
  if (savedVendor === undefined) delete process.env.KYC_PROVIDER;
  else process.env.KYC_PROVIDER = savedVendor;
  await new Promise<void>((r) => server.close(() => r()));
});

/** The attacker (or the legit user) starts KYC in THEIR browser. */
async function startKyc(sub: string): Promise<{ jar: Jar; token: string }> {
  const jar = new Jar();
  const nonce = await handoffs.issue(sub);
  const r = await fetch(`${baseUrl}/kyc/start?handoff=${nonce}&level=T3`, { redirect: 'manual' });
  expect(r.status).toBe(303);
  jar.absorb(r);
  const loc = new URL(r.headers.get('location')!);
  return { jar, token: loc.searchParams.get('session')! };
}

describe('PBA-L3a-009 capture link is bound to the starting browser', () => {
  it('the victim\'s browser (no binding cookie) cannot use the attacker\'s capture link', async () => {
    const { token } = await startKyc('0xattacker-sub');
    const dek = await fetch(`${baseUrl}/verify/dek?session=${encodeURIComponent(token)}`);
    expect(dek.status).toBe(403);
    const consent = await fetch(`${baseUrl}/verify/consent`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ session: token, consent: { bipa: true, terms: true }, identityCt: 'x' }),
    });
    expect(consent.status).toBe(403);
  });

  it('a different browser\'s binding cookie does not match either', async () => {
    const a = await startKyc('0xattacker-sub-2');
    const b = await startKyc('0xvictim-sub');
    const r = await fetch(`${baseUrl}/verify/dek?session=${encodeURIComponent(a.token)}`, { headers: { cookie: b.jar.header() } });
    expect(r.status).toBe(403);
  });

  it('the browser that started KYC proceeds; its cookie is HttpOnly and scoped to /verify', async () => {
    const { jar, token } = await startKyc('0xuser-sub');
    const r = await fetch(`${baseUrl}/verify/dek?session=${encodeURIComponent(token)}`, { headers: { cookie: jar.header() } });
    expect(r.status).toBe(200);
    const sc = jar.raw.find((c) => c.startsWith('_kyc_capture='))!;
    expect(sc).toBeDefined();
    expect(sc.toLowerCase()).toContain('httponly');
    expect(sc).toContain('Path=/verify');
  });

  it('the phone hand-off minted by the bound browser works without a cookie; a hand-off token cannot mint another', async () => {
    const { jar, token } = await startKyc('0xuser-sub-2');
    const h = await fetch(`${baseUrl}/verify/handoff`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: jar.header() },
      body: JSON.stringify({ session: token }),
    });
    expect(h.status).toBe(200);
    const phone = ((await h.json()) as { token: string }).token;
    expect((await fetch(`${baseUrl}/verify/dek?session=${encodeURIComponent(phone)}`)).status).toBe(200);
    const chain = await fetch(`${baseUrl}/verify/handoff`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ session: phone }) });
    expect(chain.status).toBe(403);
  });

  it('an unbound desktop token (not minted through /kyc/start) is refused', async () => {
    const { getKycProvider } = await import('../src/kyc-providers/index.js');
    const ih = getKycProvider() as InhouseKycProvider;
    const { applicantId } = await ih.createApplicant({ externalUserId: '0xunbound', levelHint: 'basic-individual' });
    const { token } = await ih.mintClientSession({ applicantId, externalUserId: '0xunbound', ttlSec: 600 });
    expect(ih.verifyCaptureToken(token)?.bh).toBeUndefined();
    const r = await fetch(`${baseUrl}/verify/dek?session=${encodeURIComponent(token)}`, { headers: { cookie: '_kyc_capture=anything' } });
    expect(r.status).toBe(403);
    expect(((await r.json()) as { error: string }).error).toBe('capture_not_bound_to_this_browser');
  });

  it('the binding cookie does not clobber the kyc_return cookie set by the same response', async () => {
    const nonce = await handoffs.issue('0xreturn-sub');
    const r = await fetch(`${baseUrl}/kyc/start?handoff=${nonce}&level=T3&return_to=${encodeURIComponent('https://dataroom.citrate.ai/after')}`, { redirect: 'manual' });
    const names = r.headers.getSetCookie().map((c) => c.split('=')[0]);
    expect(names).toContain('_kyc_capture');
    expect(names).toContain('kyc_return');
  });

  it('the desktop status poll also requires the binding', async () => {
    const { jar, token } = await startKyc('0xuser-sub-4');
    expect((await fetch(`${baseUrl}/verify/status?session=${encodeURIComponent(token)}`)).status).toBe(403);
    expect((await fetch(`${baseUrl}/verify/status?session=${encodeURIComponent(token)}`, { headers: { cookie: jar.header() } })).status).toBe(200);
  });
});
