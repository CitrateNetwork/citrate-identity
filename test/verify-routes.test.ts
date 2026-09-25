/**
 * VERI-S2 — the token-gated /verify capture flow, driven end-to-end against a real
 * `createProvider` server with an in-house provider over a pg-mem case store.
 * Proves the client-side envelope (produced by `sealField`, the exact format the
 * browser JS emits) round-trips through the routes into the encrypted store.
 */
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { newDb } from 'pg-mem';
import { randomBytes } from 'node:crypto';
import { createProvider } from '../src/server.js';
import { setKycProvider } from '../src/kyc-providers/index.js';
import { InhouseKycProvider } from '../src/kyc-providers/inhouse.js';
import { KycCaseStore } from '../src/kyc-cases-pg.js';
import { openField, sealField } from '../src/kyc-crypto.js';

let server: Server;
let baseUrl: string;
let provider: InhouseKycProvider;
let store: KycCaseStore;
const master = randomBytes(32);

async function freshStore(): Promise<KycCaseStore> {
  const db = newDb();
  const pg = db.adapters.createPg();
  const s = new KycCaseStore(new pg.Pool());
  await s.ensureSchema();
  return s;
}

beforeAll(async () => {
  store = await freshStore();
  provider = new InhouseKycProvider({
    mode: 'sandbox',
    store,
    masterKey: master,
    sessionSecret: 'sess',
    webhookSecret: 'wh',
    captureBaseUrl: 'https://auth.citrate.ai/verify',
  });

  const probe = createServer();
  await new Promise<void>((res) => probe.listen(0, '127.0.0.1', res));
  const { port } = probe.address() as AddressInfo;
  probe.close();
  baseUrl = `http://127.0.0.1:${port}`;
  const oidc = await createProvider(baseUrl, { googleEnabled: false });
  setKycProvider(provider); // override boot init with our in-house instance
  server = createServer(oidc.callback());
  await new Promise<void>((res) => server.listen(port, '127.0.0.1', res));
});
afterAll(async () => {
  setKycProvider(undefined);
  await new Promise<void>((res, rej) => server.close((e) => (e ? rej(e) : res())));
});

// PBA-L3a-009: /kyc/start binds the capture token to the starting browser via the
// `_kyc_capture` cookie; this suite plays that browser.
const BIND = 'test-browser-binding-secret';
const BROWSER = { cookie: `_kyc_capture=${BIND}` };

/** Open a case + mint a capture token, as /kyc/start would. */
async function newSession(sub: string): Promise<{ caseId: string; token: string; dek: Buffer }> {
  const { applicantId } = await provider.createApplicant({ externalUserId: sub, levelHint: 'basic-individual' });
  const s = await provider.mintClientSession({ applicantId, externalUserId: sub, ttlSec: 600, browserBinding: BIND });
  const dek = (await provider.getCaseDek(applicantId))!;
  return { caseId: applicantId, token: s.token, dek };
}
const post = (path: string, body: unknown) =>
  fetch(`${baseUrl}${path}`, { method: 'POST', headers: { 'content-type': 'application/json', ...BROWSER }, body: JSON.stringify(body), redirect: 'manual' });

describe('/verify capture flow (VERI-S2)', () => {
  it('GET /verify serves the capture UI', async () => {
    const r = await fetch(`${baseUrl}/verify?session=x`);
    expect(r.status).toBe(200);
    const html = await r.text();
    expect(html).toContain('Verify your identity');
    expect(html).toContain('/verify/dek'); // client fetches the DEK
    expect(html).not.toContain('sumsub');
  });

  it('rejects an invalid/missing session token (401)', async () => {
    expect((await fetch(`${baseUrl}/verify/dek?session=bad`)).status).toBe(401);
    expect((await post('/verify/consent', { session: 'bad', consent: { bipa: true, terms: true }, identityCt: 'x' })).status).toBe(401);
  });

  it('GET /verify/dek returns the case DEK for the valid session', async () => {
    const { token, dek } = await newSession('sub-dek');
    const r = await fetch(`${baseUrl}/verify/dek?session=${encodeURIComponent(token)}`, { headers: BROWSER });
    expect(r.status).toBe(200);
    const j = (await r.json()) as { dek: string };
    expect(Buffer.from(j.dek, 'base64').equals(dek)).toBe(true);
  });

  it('full flow: consent → document → liveness → complete, all stored as ciphertext', async () => {
    const { caseId, token, dek } = await newSession('sub-flow');

    // Step 1 — consent + client-sealed identity (sealField = the browser envelope).
    const identity = JSON.stringify({ name: 'Ada Lovelace', dob: '1815-12-10', nationality: 'GB' });
    const c = await post('/verify/consent', { session: token, consent: { bipa: true, terms: true }, identityCt: sealField(identity, dek) });
    expect(c.status).toBe(200);

    // Step 2 — document (Tier-3 evidence).
    expect((await post('/verify/evidence', { session: token, kind: 'document', ciphertext: sealField('DOC-BYTES', dek) })).status).toBe(200);
    // Step 3 — liveness (Tier-2 biometric).
    expect((await post('/verify/evidence', { session: token, kind: 'liveness', ciphertext: sealField('FACE-BYTES', dek) })).status).toBe(200);
    // Complete.
    expect((await post('/verify/complete', { session: token })).status).toBe(200);

    // The store holds ONLY ciphertext; the server round-trips it via the DEK.
    const stored = await store.getCase(caseId);
    expect(stored?.identityCt).toBeDefined();
    expect(stored?.identityCt).not.toContain('Ada');
    expect(openField(stored!.identityCt!, dek)).toBe(identity);

    const ev = await store.listEvidence(caseId);
    const liveness = ev.find((e) => e.kind === 'liveness');
    expect(liveness?.tier).toBe(2);
    expect(liveness?.destroyAfter).toBeDefined(); // biometric scheduled for destruction
    expect(openField(liveness!.ciphertext!, dek)).toBe('FACE-BYTES');
    expect(ev.find((e) => e.kind === 'document')?.tier).toBe(3);

    // Status reports capture complete (the desktop poll signal).
    const st = (await (await fetch(`${baseUrl}/verify/status?session=${encodeURIComponent(token)}`, { headers: BROWSER })).json()) as { captureComplete: boolean; status: string };
    expect(st.captureComplete).toBe(true);
    expect(st.status).toBe('pending'); // decision is VERI-S3's job
  });

  it('rejects consent without both BIPA + terms', async () => {
    const { token, dek } = await newSession('sub-noconsent');
    const r = await post('/verify/consent', { session: token, consent: { bipa: true, terms: false }, identityCt: sealField('{}', dek) });
    expect(r.status).toBe(400);
    expect(((await r.json()) as { error: string }).error).toBe('consent_required');
  });

  it('device hand-off mints a fresh, valid phone-scoped token bound to the same case', async () => {
    const { caseId, token } = await newSession('sub-handoff');
    const r = await post('/verify/handoff', { session: token });
    expect(r.status).toBe(200);
    const j = (await r.json()) as { mobileUrl: string; token: string };
    expect(j.mobileUrl).toContain('/verify?session=');
    // The handed-off token authenticates for the SAME case.
    const claims = provider.verifyCaptureToken(j.token);
    expect(claims?.caseId).toBe(caseId);
    // And it works against the live routes — from the phone, which has no cookie.
    expect((await fetch(`${baseUrl}/verify/dek?session=${encodeURIComponent(j.token)}`)).status).toBe(200);
  });
});
