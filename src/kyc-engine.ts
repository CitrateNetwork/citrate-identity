/**
 * VERI verification engine (VERI-S3-WP1/2/4).
 *
 * Orchestrates a decision for a captured case with **no vendor call**:
 *   1. Load the case + evidence; unwrap the DEK; decrypt identity + document + face.
 *   2. Run the pluggable analyzers — liveness PAD + 1:1 face match (WP1), document
 *      OCR/MRZ + authenticity (WP2) — and the in-house sanctions screener (WP3).
 *   3. Combine → `verified | rejected | needs-review`.
 *   4. **Destroy the biometric immediately** (BIPA, `ADR-2026-07-01-biometric-bipa`).
 *   5. Record the decision + emit a signed decision webhook for the UNCHANGED
 *      `/kyc/webhook` entitlement path (WP4, planset D1).
 *
 * FAIL-CLOSED (Rule 1 — no fabricated `verified`): the liveness + document analyzers
 * are model backends injected at construction. If a backend is absent, the engine
 * routes the case to **needs-review** (human adjudication) — it NEVER auto-verifies.
 * The real self-hosted ISO-30107-3 PAD + face-match + OCR/MRZ models (planset D5,
 * US-hosted) implement `LivenessAnalyzer` / `DocumentAnalyzer`; wiring them in is the
 * model-integration step, tracked separately. This module is provider-agnostic and
 * fully offline-testable with analyzer results injected.
 */

import { createHmac } from 'node:crypto';

import type { KycCaseStore } from './kyc-cases-pg.js';
import { openBytes, openField, unwrapDek } from './kyc-crypto.js';
import type { SanctionsScreener, ScreeningResult } from './kyc-screening.js';

export interface LivenessResult {
  /** True only if the frame is a live human AND matches the ID portrait (1:1). */
  pass: boolean;
  confidence: number;
  reason?: string;
  requiresReview?: boolean;
}
export interface DocumentResult {
  authentic: boolean;
  extracted?: { name?: string; dob?: string; docNumber?: string; nationality?: string };
  reason?: string;
  requiresReview?: boolean;
}

/** Model backend: presentation-attack detection + 1:1 face match. US-hosted (D5). */
export interface LivenessAnalyzer {
  analyze(input: { faceImage: Buffer; idPortrait?: Buffer }): Promise<LivenessResult>;
}
/** Model backend: document OCR/MRZ + authenticity/tamper checks. */
export interface DocumentAnalyzer {
  analyze(input: { docImage: Buffer }): Promise<DocumentResult>;
}

export type EngineDecision = 'verified' | 'rejected' | 'needs-review';

export interface EngineResult {
  caseId: string;
  decision: EngineDecision;
  reasons: string[];
  screening: ScreeningResult;
  liveness?: LivenessResult;
  document?: DocumentResult;
  biometricsDestroyed: number;
  /** Signed decision event for POST /kyc/webhook (the unchanged entitlement path). */
  signedWebhook: { body: Buffer; headers: Record<string, string> };
}

export interface VerificationEngineDeps {
  store: KycCaseStore;
  masterKey: Buffer;
  screener: SanctionsScreener;
  /** HMAC secret matching the in-house provider's decision webhook. */
  webhookSecret: string;
  liveness?: LivenessAnalyzer;
  document?: DocumentAnalyzer;
}

const DECISION_TO_KIND: Record<EngineDecision, 'verified' | 'rejected' | 'pending'> = {
  verified: 'verified',
  rejected: 'rejected',
  'needs-review': 'pending',
};

export class VerificationEngine {
  constructor(private readonly deps: VerificationEngineDeps) {}

  /** Run the decision pipeline for a captured case. Returns null for an unknown case. */
  async runCase(caseId: string, now: number = Date.now()): Promise<EngineResult | null> {
    const { store, masterKey, screener } = this.deps;
    const c = await store.getCase(caseId);
    if (!c) return null;

    const dek = unwrapDek(c.wrappedDek, masterKey);
    const identity = c.identityCt
      ? (JSON.parse(openField(c.identityCt, dek)) as { name?: string; dob?: string; nationality?: string })
      : {};
    const evidence = await store.listEvidence(caseId);
    const docEv = evidence.find((e) => e.kind === 'document' && e.ciphertext);
    const faceEv = evidence.find((e) => (e.kind === 'liveness' || e.kind === 'selfie') && e.ciphertext);

    const reasons: string[] = [];

    // --- Document (WP2) ---
    let document: DocumentResult | undefined;
    if (!docEv?.ciphertext) {
      reasons.push('no document captured');
    } else if (!this.deps.document) {
      reasons.push('no document-analysis backend configured');
    } else {
      document = await this.deps.document.analyze({ docImage: openBytes(docEv.ciphertext, dek) });
      if (!document.authentic) reasons.push(`document not authentic: ${document.reason ?? 'unspecified'}`);
      if (document.requiresReview) reasons.push('document flagged for review');
    }

    // --- Liveness + 1:1 match (WP1) ---
    let liveness: LivenessResult | undefined;
    if (!faceEv?.ciphertext) {
      reasons.push('no liveness capture');
    } else if (!this.deps.liveness) {
      reasons.push('no liveness (PAD/face-match) backend configured');
    } else {
      liveness = await this.deps.liveness.analyze({
        faceImage: openBytes(faceEv.ciphertext, dek),
        idPortrait: docEv?.ciphertext ? openBytes(docEv.ciphertext, dek) : undefined,
      });
      if (!liveness.pass) reasons.push(`liveness/match failed: ${liveness.reason ?? 'unspecified'}`);
      if (liveness.requiresReview) reasons.push('liveness flagged for review');
    }

    // --- Sanctions / export screening (WP3) ---
    const screening = screener.screen(
      { name: identity.name ?? '', nationality: identity.nationality, dob: identity.dob },
      now,
    );
    if (screening.result === 'hit') reasons.push(`sanctions hit (${screening.hits[0]?.entry.source ?? 'list'})`);
    if (screening.result === 'review') reasons.push(`screening review: ${screening.reviewReason ?? 'weak match'}`);

    // --- Combine → decision ---
    const decision = this.decide({ liveness, document, screening, hasFace: !!faceEv, hasDoc: !!docEv });

    // --- Destroy the biometric immediately (BIPA) ---
    const biometricsDestroyed = await store.destroyBiometricsForCase(caseId, now);

    // --- Record decision on the case + build the entitlement-path webhook ---
    await store.setDecision(caseId, {
      decision,
      screeningResult: screening.result,
      ...(decision === 'verified'
        ? { verifiedAt: now, expiresAt: now + 365 * 24 * 60 * 60 * 1000, retentionUntil: now + 365 * 24 * 60 * 60 * 1000 }
        : { retentionUntil: now + 365 * 24 * 60 * 60 * 1000 }),
    });

    const signedWebhook = this.signDecision({
      caseId,
      externalUserId: c.externalUserId,
      kind: DECISION_TO_KIND[decision],
      occurredAt: now,
      screeningResult: screening.result,
    });

    return { caseId, decision, reasons, screening, liveness, document, biometricsDestroyed, signedWebhook };
  }

  private decide(x: {
    liveness?: LivenessResult;
    document?: DocumentResult;
    screening: ScreeningResult;
    hasFace: boolean;
    hasDoc: boolean;
  }): EngineDecision {
    // Hard rejects: a confident spoof / no-match or a confirmed-fake document.
    if (x.liveness && x.liveness.pass === false && !x.liveness.requiresReview) return 'rejected';
    if (x.document && x.document.authentic === false && !x.document.requiresReview) return 'rejected';

    // Anything uncertain or unscreenable → human adjudication (fail-closed).
    if (!x.hasFace || !x.hasDoc) return 'needs-review';
    if (!x.liveness || !x.document) return 'needs-review'; // no model backend → review
    if (x.liveness.requiresReview || x.document.requiresReview) return 'needs-review';
    if (x.screening.result !== 'clear') return 'needs-review'; // hit/review → adjudicate

    // All green.
    if (x.liveness.pass && x.document.authentic) return 'verified';
    return 'needs-review';
  }

  private signDecision(evt: {
    caseId: string;
    externalUserId?: string;
    kind: 'verified' | 'rejected' | 'pending';
    occurredAt: number;
    screeningResult: string;
  }): { body: Buffer; headers: Record<string, string> } {
    const body = Buffer.from(JSON.stringify(evt), 'utf8');
    const sig = createHmac('sha256', this.deps.webhookSecret).update(body).digest('hex');
    return { body, headers: { 'x-citrate-kyc-sig': sig } };
  }
}
