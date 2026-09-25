/**
 * InhouseKycProvider — Citrate's own server-blind KYC/AML + liveness verifier
 * (program VERI). Implements the vendor-agnostic {@link KycProvider} interface so
 * it drops into the existing `KYC_PROVIDER` seam with no route/entitlement changes.
 *
 * ADRs: kyc-inhouse-provider, kyc-data-controller-reversal (server-blind),
 * kyc-not-msb-retention-erasure (retention), biometric-bipa (destroy-after-match).
 *
 * How the 6 methods map to an in-house flow (vs. a vendor):
 *   createApplicant   → open a verification **case** in the encrypted store
 *                       (mint a per-case DEK, wrap it under the master key).
 *   mintClientSession → mint a short-lived, HMAC-signed **capture token** and
 *                       return the Citrate-hosted capture URL (NOT a vendor URL).
 *   verifyWebhook     → verify the HMAC of the internal capture/decision webhook
 *                       (the S3 verification engine posts the decision back).
 *   parseWebhookEvent → translate that decision into a KycEvent + update the case.
 *   getApplicantStatus→ read the case status from the store.
 *   deleteApplicant   → delete/tombstone the case (right-to-delete; D3).
 *
 * The interface stays PII-free: it returns only ids + lifecycle state. All PII
 * lives in the encrypted case store behind this adapter (`kyc-cases-pg.ts`).
 *
 * NB (Rule 1 — no mocks in prod): this is a REAL provider. Its data source is the
 * Postgres `kyc_cases`/`kyc_evidence` tables via {@link KycCaseStore}; the capture
 * UI (VERI-S2) and verification engine (VERI-S3) drive it — until those land, the
 * decision webhook is produced by S3, so on a fresh deploy a case reaches only
 * `pending` (fail-closed), never a fake `verified`.
 */

import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

import { KycCaseStore } from '../kyc-cases-pg.js';
import { newDek, unwrapDek, wrapDek } from '../kyc-crypto.js';
import type {
  KycEvent,
  KycEventKind,
  KycProvider,
  KycProviderBaseConfig,
  KycStatus,
} from './types.js';

const DAY_MS = 24 * 60 * 60 * 1000;

export interface InhouseKycProviderConfig extends KycProviderBaseConfig {
  /** The encrypted case store (Postgres-backed). */
  store: KycCaseStore;
  /** 32-byte master key that wraps per-case DEKs (from `masterKeyFromEnv`). */
  masterKey: Buffer;
  /** HMAC secret for capture session tokens. */
  sessionSecret: string;
  /** HMAC secret for the internal capture/decision webhook. */
  webhookSecret: string;
  /** Base URL of the Citrate-hosted capture flow, e.g. `https://auth.citrate.ai/verify`. */
  captureBaseUrl: string;
  /** Tier-1 retention window in days (D3 default ~12 months). */
  retentionDays?: number;
  /** Verified-claim TTL in ms (default 365d). */
  verifiedTtlMs?: number;
}

/** Decoded capture token payload. */
export interface CaptureTokenClaims {
  caseId: string;
  sub: string;
  exp: number; // unix seconds
  /**
   * PBA-L3a-009: sha256 (base64url) of the browser-binding secret /kyc/start set
   * as the `_kyc_capture` cookie. A desktop capture token only works in that
   * browser, so a capture link cannot be handed to someone else.
   */
  bh?: string;
  /** 'handoff' = phone token minted by the bound browser for the QR hop. */
  k?: 'handoff';
}

/** PBA-L3a-009: the cookie carrying the capture browser-binding secret. */
export const CAPTURE_BINDING_COOKIE = '_kyc_capture';

/** Hash a browser-binding secret for embedding in the signed capture token. */
export function captureBindingHash(secret: string): string {
  return createHash('sha256').update(`kyc-capture:${secret}`).digest('base64url');
}

/** Shape of the internal decision webhook the S3 engine posts to /kyc/webhook. */
interface DecisionEvent {
  caseId: string;
  externalUserId?: string;
  kind: KycEventKind;
  occurredAt?: number;
  screeningResult?: string;
}

function b64url(buf: Buffer): string {
  return buf.toString('base64url');
}

export class InhouseKycProvider implements KycProvider {
  private readonly store: KycCaseStore;
  private readonly masterKey: Buffer;
  private readonly sessionSecret: string;
  private readonly webhookSecret: string;
  private readonly captureBaseUrl: string;
  private readonly retentionMs: number;
  private readonly verifiedTtlMs: number;

  constructor(config: InhouseKycProviderConfig) {
    this.store = config.store;
    this.masterKey = config.masterKey;
    this.sessionSecret = config.sessionSecret;
    this.webhookSecret = config.webhookSecret;
    this.captureBaseUrl = config.captureBaseUrl.replace(/\/+$/, '');
    this.retentionMs = (config.retentionDays ?? 365) * DAY_MS;
    this.verifiedTtlMs = config.verifiedTtlMs ?? 365 * DAY_MS;
  }

  /**
   * Open (or reuse) a verification case. Idempotent while a verification is in
   * flight: an in-progress (`created`/`pending`) case for the same user is
   * reused; once a case reaches a decision, a fresh case starts (re-verification).
   */
  async createApplicant(input: {
    externalUserId: string;
    levelHint: string;
    email?: string;
    phone?: string;
  }): Promise<{ applicantId: string }> {
    const existing = await this.store.getLatestCaseForUser(input.externalUserId);
    if (existing && (existing.status === 'created' || existing.status === 'pending')) {
      return { applicantId: existing.caseId };
    }
    const dek = newDek();
    const c = await this.store.createCase(input.externalUserId, wrapDek(dek, this.masterKey));
    return { applicantId: c.caseId };
  }

  /**
   * Mint a single-use, short-TTL capture token bound to (caseId, sub) and return
   * the Citrate-hosted capture URL. The capture UI (VERI-S2) validates the token
   * with {@link verifyCaptureToken} before accepting uploads.
   */
  async mintClientSession(input: {
    applicantId: string;
    externalUserId: string;
    ttlSec: number;
    returnTo?: string;
    /** PBA-L3a-009: the `_kyc_capture` cookie secret of the starting browser. */
    browserBinding?: string;
  }): Promise<{ token: string; expiresAt: number; redirectUrl?: string }> {
    const c = await this.store.getCase(input.applicantId);
    if (!c) throw new Error(`inhouse: unknown caseId ${input.applicantId}`);
    if (c.externalUserId !== input.externalUserId) {
      throw new Error('inhouse: caseId does not belong to this user');
    }
    const exp = Math.floor(Date.now() / 1000) + Math.max(1, input.ttlSec);
    const token = this.signCaptureToken({
      caseId: c.caseId,
      sub: input.externalUserId,
      exp,
      ...(input.browserBinding ? { bh: captureBindingHash(input.browserBinding) } : {}),
    });
    // Move the case to `pending` — a capture session exists.
    if (c.status === 'created') await this.store.setStatus(c.caseId, 'pending');
    const q = new URLSearchParams({ session: token });
    if (input.returnTo) q.set('return', input.returnTo);
    return { token, expiresAt: exp, redirectUrl: `${this.captureBaseUrl}?${q.toString()}` };
  }

  /**
   * Verify the internal capture/decision webhook. `x-citrate-kyc-sig` =
   * HMAC-SHA256(rawBody, webhookSecret) hex. Constant-time; never throws.
   */
  verifyWebhook(headers: Record<string, string>, rawBody: Buffer): boolean {
    const sig = headers['x-citrate-kyc-sig'];
    if (typeof sig !== 'string' || sig.length === 0) return false;
    const expected = createHmac('sha256', this.webhookSecret).update(rawBody).digest('hex');
    const a = Buffer.from(sig);
    const b = Buffer.from(expected);
    if (a.length !== b.length) return false;
    return timingSafeEqual(a, b);
  }

  /**
   * Translate a verified decision webhook into a {@link KycEvent} and record the
   * decision on the case (status + retention window). Caller MUST have called
   * {@link verifyWebhook} first.
   */
  async parseWebhookEvent(rawBody: Buffer): Promise<KycEvent> {
    const d = JSON.parse(rawBody.toString('utf8')) as DecisionEvent;
    const occurredAt = d.occurredAt ?? Date.now();
    const c = await this.store.getCase(d.caseId);

    if (c) {
      if (d.kind === 'verified') {
        await this.store.setDecision(c.caseId, {
          decision: 'verified',
          screeningResult: d.screeningResult,
          verifiedAt: occurredAt,
          expiresAt: occurredAt + this.verifiedTtlMs,
          retentionUntil: occurredAt + this.retentionMs,
        });
      } else if (d.kind === 'rejected') {
        await this.store.setDecision(c.caseId, {
          decision: 'rejected',
          screeningResult: d.screeningResult,
          retentionUntil: occurredAt + this.retentionMs,
        });
      } else if (d.kind === 'pending') {
        await this.store.setStatus(c.caseId, 'pending');
      } else if (d.kind === 'reset') {
        await this.store.setStatus(c.caseId, 'created');
      }
    }

    return {
      externalUserId: d.externalUserId ?? c?.externalUserId,
      applicantId: d.caseId,
      kind: d.kind,
      occurredAt,
      raw: d,
    };
  }

  async getApplicantStatus(applicantId: string): Promise<KycStatus> {
    const c = await this.store.getCase(applicantId);
    if (!c) return { state: 'unverified', providerRaw: null };
    const state: KycStatus['state'] =
      c.status === 'verified'
        ? 'verified'
        : c.status === 'rejected'
          ? 'rejected'
          : c.status === 'pending'
            ? 'pending'
            : 'unverified';
    return {
      state,
      verifiedAt: c.verifiedAt,
      expiresAt: c.expiresAt,
      providerRaw: { caseId: c.caseId, status: c.status, decision: c.decision },
    };
  }

  /** Right-to-delete: delete (or tombstone under a legal hold) the case. */
  async deleteApplicant(applicantId: string): Promise<void> {
    await this.store.deleteCase(applicantId);
  }

  // ── capture-token signing (used by mintClientSession + the S2 capture route) ──

  private signCaptureToken(claims: CaptureTokenClaims): string {
    const payload = b64url(Buffer.from(JSON.stringify(claims), 'utf8'));
    const sig = createHmac('sha256', this.sessionSecret).update(payload).digest('base64url');
    return `${payload}.${sig}`;
  }

  /**
   * Mint a fresh short-TTL capture token for an existing case — used by the
   * desktop→mobile hand-off (VERI-S2-WP4) to issue a phone-scoped token bound to
   * the same case, without re-running createApplicant.
   */
  mintCaptureToken(caseId: string, sub: string, ttlSec: number): { token: string; expiresAt: number } {
    const exp = Math.floor(Date.now() / 1000) + Math.max(1, ttlSec);
    // PBA-L3a-009: marked as a hand-off token (the phone has no binding cookie).
    return { token: this.signCaptureToken({ caseId, sub, exp, k: 'handoff' }), expiresAt: exp };
  }

  /**
   * Unwrap the case DEK (server-blind: the DB holds only the master-wrapped DEK).
   * The capture UI fetches this over TLS to seal artifacts client-side before
   * upload; the S3 engine uses it to process, then re-seal/destroy. Returns null
   * for an unknown case. NOTE (server-blind hardening, tracked): the stronger model
   * is client-generated DEKs wrapped under an asymmetric KMS public key so the
   * server never holds the DEK in the clear — a crypto-hardening follow-up (O7).
   */
  async getCaseDek(caseId: string): Promise<Buffer | null> {
    const c = await this.store.getCase(caseId);
    if (!c) return null;
    return unwrapDek(c.wrappedDek, this.masterKey);
  }

  /** The encrypted case store behind this provider (capture routes persist to it). */
  get caseStore(): KycCaseStore {
    return this.store;
  }

  /**
   * Validate a capture token (VERI-S2 calls this before accepting uploads):
   * checks the HMAC (constant-time) and expiry, returns the claims or null.
   */
  verifyCaptureToken(token: string, now: number = Date.now()): CaptureTokenClaims | null {
    const dot = token.indexOf('.');
    if (dot <= 0) return null;
    const payload = token.slice(0, dot);
    const sig = token.slice(dot + 1);
    const expected = createHmac('sha256', this.sessionSecret).update(payload).digest('base64url');
    const a = Buffer.from(sig);
    const b = Buffer.from(expected);
    if (a.length !== b.length || !timingSafeEqual(a, b)) return null;
    let claims: CaptureTokenClaims;
    try {
      claims = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as CaptureTokenClaims;
    } catch {
      return null;
    }
    if (!claims.caseId || !claims.sub || typeof claims.exp !== 'number') return null;
    if (claims.exp * 1000 <= now) return null;
    return claims;
  }

  /**
   * Test/engine helper: build a body + signature pair that authenticates against
   * this provider's webhook (mirrors MockKycProvider.buildSignedWebhook). The
   * VERI-S3 verification engine produces the real ones.
   */
  buildSignedWebhook(payload: DecisionEvent): { body: Buffer; headers: Record<string, string> } {
    const body = Buffer.from(JSON.stringify(payload), 'utf8');
    const sig = createHmac('sha256', this.webhookSecret).update(body).digest('hex');
    return { body, headers: { 'x-citrate-kyc-sig': sig } };
  }
}
