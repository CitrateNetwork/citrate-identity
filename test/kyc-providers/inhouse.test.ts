import { describe, expect, it, beforeEach } from 'vitest';
import { newDb, type IMemoryDb } from 'pg-mem';
import { randomBytes } from 'node:crypto';
import { KycCaseStore } from '../../src/kyc-cases-pg.js';
import { InhouseKycProvider } from '../../src/kyc-providers/inhouse.js';

/**
 * VERI-S1-WP1 — the in-house KycProvider adapter, backed by a REAL encrypted
 * case store (pg-mem). Exercises all six interface methods + the capture-token
 * and internal-webhook seams that VERI-S2/S3 drive.
 */
function freshDb(): { makePool: () => InstanceType<ReturnType<IMemoryDb['adapters']['createPg']>['Pool']> } {
  const db = newDb();
  const pg = db.adapters.createPg();
  return { makePool: () => new pg.Pool() };
}

async function newProvider() {
  const store = new KycCaseStore(freshDb().makePool());
  await store.ensureSchema();
  const provider = new InhouseKycProvider({
    mode: 'sandbox',
    store,
    masterKey: randomBytes(32),
    sessionSecret: 'sess-secret',
    webhookSecret: 'wh-secret',
    captureBaseUrl: 'https://auth.citrate.ai/verify',
    retentionDays: 365,
  });
  return { store, provider };
}

describe('InhouseKycProvider (VERI-S1)', () => {
  let store: KycCaseStore;
  let provider: InhouseKycProvider;

  beforeEach(async () => {
    ({ store, provider } = await newProvider());
  });

  it('createApplicant opens a case; idempotent while in-progress', async () => {
    const a = await provider.createApplicant({ externalUserId: 'sub-1', levelHint: 'basic-individual' });
    expect(a.applicantId).toMatch(/^case_/);
    const b = await provider.createApplicant({ externalUserId: 'sub-1', levelHint: 'basic-individual' });
    expect(b.applicantId).toBe(a.applicantId); // reused (still created/pending)
    // A different user gets a distinct case.
    const c = await provider.createApplicant({ externalUserId: 'sub-2', levelHint: 'basic-individual' });
    expect(c.applicantId).not.toBe(a.applicantId);
  });

  it('mintClientSession returns a Citrate-hosted capture URL + valid token, moves case to pending', async () => {
    const { applicantId } = await provider.createApplicant({ externalUserId: 'sub-3', levelHint: 'basic-individual' });
    const s = await provider.mintClientSession({ applicantId, externalUserId: 'sub-3', ttlSec: 600, returnTo: '/account' });
    expect(s.redirectUrl).toContain('https://auth.citrate.ai/verify?');
    expect(s.redirectUrl).toContain('session=');
    expect(s.redirectUrl).not.toContain('sumsub');
    expect((await store.getCase(applicantId))?.status).toBe('pending');

    const claims = provider.verifyCaptureToken(s.token);
    expect(claims?.caseId).toBe(applicantId);
    expect(claims?.sub).toBe('sub-3');
  });

  it('mintClientSession refuses a caseId that is not the user’s', async () => {
    const { applicantId } = await provider.createApplicant({ externalUserId: 'owner', levelHint: 'basic-individual' });
    await expect(
      provider.mintClientSession({ applicantId, externalUserId: 'attacker', ttlSec: 60 }),
    ).rejects.toThrow(/does not belong/);
  });

  it('verifyCaptureToken rejects tampered + expired tokens', async () => {
    const { applicantId } = await provider.createApplicant({ externalUserId: 'sub-4', levelHint: 'basic-individual' });
    const s = await provider.mintClientSession({ applicantId, externalUserId: 'sub-4', ttlSec: 600 });
    expect(provider.verifyCaptureToken(s.token + 'x')).toBeNull(); // tampered sig
    expect(provider.verifyCaptureToken(s.token, Date.now() + 601_000)).toBeNull(); // past exp
    expect(provider.verifyCaptureToken('not-a-token')).toBeNull();
  });

  it('verifyWebhook: rejects missing/bad signature, accepts a correctly-signed body', async () => {
    expect(provider.verifyWebhook({}, Buffer.from('{}'))).toBe(false);
    const { body, headers } = provider.buildSignedWebhook({ caseId: 'case_x', kind: 'verified' });
    expect(provider.verifyWebhook(headers, body)).toBe(true);
    expect(provider.verifyWebhook({ 'x-citrate-kyc-sig': 'deadbeef' }, body)).toBe(false);
  });

  it('parseWebhookEvent(verified) records the decision + retention on the case', async () => {
    const { applicantId } = await provider.createApplicant({ externalUserId: 'sub-5', levelHint: 'basic-individual' });
    const now = Date.now();
    const { body, headers } = provider.buildSignedWebhook({
      caseId: applicantId,
      externalUserId: 'sub-5',
      kind: 'verified',
      occurredAt: now,
      screeningResult: 'clear',
    });
    expect(provider.verifyWebhook(headers, body)).toBe(true);
    const ev = await provider.parseWebhookEvent(body);
    expect(ev.kind).toBe('verified');
    expect(ev.applicantId).toBe(applicantId);

    const c = await store.getCase(applicantId);
    expect(c?.status).toBe('verified');
    expect(c?.verifiedAt).toBe(now);
    expect(c?.expiresAt).toBe(now + 365 * 864e5);
    expect(c?.retentionUntil).toBe(now + 365 * 864e5);
    expect(c?.screeningResult).toBe('clear');
  });

  it('getApplicantStatus reflects store state; unknown case → unverified', async () => {
    const { applicantId } = await provider.createApplicant({ externalUserId: 'sub-6', levelHint: 'basic-individual' });
    expect((await provider.getApplicantStatus(applicantId)).state).toBe('unverified'); // created
    const { body } = provider.buildSignedWebhook({ caseId: applicantId, kind: 'verified' });
    await provider.parseWebhookEvent(body);
    expect((await provider.getApplicantStatus(applicantId)).state).toBe('verified');
    expect((await provider.getApplicantStatus('case_missing')).state).toBe('unverified');
  });

  it('deleteApplicant removes the case (right-to-delete)', async () => {
    const { applicantId } = await provider.createApplicant({ externalUserId: 'sub-7', levelHint: 'basic-individual' });
    await provider.deleteApplicant(applicantId);
    expect(await store.getCase(applicantId)).toBeUndefined();
  });

  it('a fresh case never reaches verified without a signed decision (fail-closed)', async () => {
    const { applicantId } = await provider.createApplicant({ externalUserId: 'sub-8', levelHint: 'basic-individual' });
    await provider.mintClientSession({ applicantId, externalUserId: 'sub-8', ttlSec: 60 });
    // No decision webhook yet → still pending, not verified.
    expect((await provider.getApplicantStatus(applicantId)).state).toBe('pending');
  });
});
