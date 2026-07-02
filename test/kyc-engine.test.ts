import { describe, expect, it, beforeEach } from 'vitest';
import { newDb, type IMemoryDb } from 'pg-mem';
import { randomBytes } from 'node:crypto';
import { KycCaseStore } from '../src/kyc-cases-pg.js';
import { newDek, sealBytes, sealField, unwrapDek, wrapDek } from '../src/kyc-crypto.js';
import { loadSanctionsList, type SanctionsEntry } from '../src/kyc-screening.js';
import {
  VerificationEngine,
  type DocumentAnalyzer,
  type LivenessAnalyzer,
} from '../src/kyc-engine.js';
import { InhouseKycProvider } from '../src/kyc-providers/inhouse.js';

/**
 * VERI-S3 — the verification engine. Runs synthetic capture→engine→decision cases
 * with injected analyzer results (the real ISO-30107-3 PAD/OCR model backends
 * implement these interfaces). Proves: verified/rejected/needs-review routing,
 * biometric destruction after the match, and a signed decision that the in-house
 * provider's /kyc/webhook path accepts (→ entitlement).
 */
const WEBHOOK_SECRET = 'wh-secret';
const SANCTIONS: SanctionsEntry[] = [
  { name: 'Vladimir Ivanov', type: 'individual', programs: ['UKRAINE'], source: 'OFAC-SDN' },
];
const passLiveness: LivenessAnalyzer = { async analyze() { return { pass: true, confidence: 0.99 }; } };
const failLiveness: LivenessAnalyzer = { async analyze() { return { pass: false, confidence: 0.95, reason: 'presentation attack' }; } };
const okDoc: DocumentAnalyzer = { async analyze() { return { authentic: true, extracted: {} }; } };

describe('VerificationEngine (VERI-S3)', () => {
  let store: KycCaseStore;
  const master = randomBytes(32);

  beforeEach(async () => {
    const db: IMemoryDb = newDb();
    const pg = db.adapters.createPg();
    store = new KycCaseStore(new pg.Pool());
    await store.ensureSchema();
  });

  /** Seed a captured case (identity + document + liveness), return { caseId, dek }. */
  async function capturedCase(name: string, nationality = 'United Kingdom') {
    const dek = newDek();
    const c = await store.createCase('sub-' + name.replace(/\s/g, ''), wrapDek(dek, master));
    await store.setIdentityCiphertext(c.caseId, sealField(JSON.stringify({ name, dob: '1990-01-01', nationality }), dek));
    await store.addEvidence({ caseId: c.caseId, kind: 'document', tier: 3, ciphertext: sealBytes(Buffer.from('ID-IMAGE'), dek) });
    await store.addEvidence({ caseId: c.caseId, kind: 'liveness', tier: 2, ciphertext: sealBytes(Buffer.from('FACE-IMAGE'), dek), destroyAfter: Date.now() + 864e5 });
    return { caseId: c.caseId };
  }

  function engine(opts: { liveness?: LivenessAnalyzer; document?: DocumentAnalyzer }) {
    return new VerificationEngine({
      store,
      getDek: async (id: string) => { const c = await store.getCase(id); return c ? unwrapDek(c.wrappedDek, master) : null; },
      screener: loadSanctionsList(SANCTIONS, '2026-07-01'),
      webhookSecret: WEBHOOK_SECRET,
      liveness: opts.liveness,
      document: opts.document,
    });
  }

  it('VERIFIED: clean identity + live match + authentic doc; biometric destroyed; signed webhook valid', async () => {
    const { caseId } = await capturedCase('Ada Lovelace');
    const res = (await engine({ liveness: passLiveness, document: okDoc }).runCase(caseId))!;
    expect(res.decision).toBe('verified');
    expect(res.biometricsDestroyed).toBe(1);

    // Biometric is provably gone.
    const ev = await store.listEvidence(caseId);
    expect(ev.find((e) => e.kind === 'liveness')?.ciphertext).toBeUndefined();
    // Case decision recorded.
    const c = await store.getCase(caseId);
    expect(c?.status).toBe('verified');

    // The signed decision flows through the UNCHANGED /kyc/webhook path.
    const provider = new InhouseKycProvider({ mode: 'sandbox', store, masterKey: master, sessionSecret: 's', webhookSecret: WEBHOOK_SECRET, captureBaseUrl: 'https://x/verify' });
    expect(provider.verifyWebhook(res.signedWebhook.headers, res.signedWebhook.body)).toBe(true);
    const ev2 = await provider.parseWebhookEvent(res.signedWebhook.body);
    expect(ev2.kind).toBe('verified');
  });

  it('NEEDS-REVIEW: a sanctioned identity is never auto-verified', async () => {
    const { caseId } = await capturedCase('Vladimir Ivanov', 'Russia');
    const res = (await engine({ liveness: passLiveness, document: okDoc }).runCase(caseId))!;
    expect(res.decision).toBe('needs-review');
    expect(res.screening.result).toBe('hit');
    expect(res.reasons.some((r) => /sanctions/.test(r))).toBe(true);
    expect(res.biometricsDestroyed).toBe(1); // still destroyed
  });

  it('REVIEW (not reject): a failed liveness / presentation attack goes to a human, never auto-rejected', async () => {
    const { caseId } = await capturedCase('Ada Lovelace');
    const res = (await engine({ liveness: failLiveness, document: okDoc }).runCase(caseId))!;
    // Lenient posture: the engine never auto-rejects — a failed match / suspected spoof
    // is routed to compliance review (+ email fallback), not hard-blocked.
    expect(res.decision).toBe('needs-review');
  });

  it('FAIL-CLOSED: no model backend → needs-review, never a fabricated verified (Rule 1)', async () => {
    const { caseId } = await capturedCase('Ada Lovelace');
    const res = (await engine({}).runCase(caseId))!; // no analyzers injected
    expect(res.decision).toBe('needs-review');
    expect(res.reasons.some((r) => /no liveness .* backend/.test(r))).toBe(true);
  });

  it('an embargoed nationality routes to needs-review even with a clean name + pass', async () => {
    const { caseId } = await capturedCase('Ada Lovelace', 'Iran');
    const res = (await engine({ liveness: passLiveness, document: okDoc }).runCase(caseId))!;
    expect(res.decision).toBe('needs-review');
    expect(res.screening.result).toBe('review');
  });

  it('returns null for an unknown case', async () => {
    expect(await engine({ liveness: passLiveness, document: okDoc }).runCase('case_nope')).toBeNull();
  });
});
