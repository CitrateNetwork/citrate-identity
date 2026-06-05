/**
 * MockKycProvider — deterministic in-process KycProvider for tests and dev.
 *
 * Goals:
 *   - Drive the OIDC interaction + webhook code paths end-to-end without
 *     reaching the real vendor.
 *   - Let tests assert on what was called (every method records calls).
 *   - Be deterministic: applicant ids and tokens are derived from
 *     `externalUserId`, not random.
 *
 * This provider is selected by `KYC_PROVIDER=mock`. It refuses to load
 * in production (the factory in `./index.ts` enforces that).
 */

import { createHmac, timingSafeEqual } from 'node:crypto';

import type {
  KycEvent,
  KycEventKind,
  KycProvider,
  KycProviderBaseConfig,
  KycStatus,
} from './types.js';

/** Construction config. */
export interface MockKycProviderConfig extends KycProviderBaseConfig {
  /** Secret used by `verifyWebhook` for HMAC. Defaults to a fixed test value. */
  webhookSecret?: string;
  /**
   * Pre-seed an applicant's verdict so a synthetic completion can be
   * scripted in tests. Keyed by `externalUserId`.
   */
  scriptedVerdicts?: Record<string, KycEventKind>;
}

interface RecordedCall {
  method: keyof KycProvider;
  args: unknown[];
  at: number;
}

interface MockApplicant {
  applicantId: string;
  externalUserId: string;
  state: KycStatus['state'];
  verifiedAt?: number;
  expiresAt?: number;
}

export class MockKycProvider implements KycProvider {
  /** All method calls in order. Tests assert on this. */
  public readonly calls: RecordedCall[] = [];

  private readonly applicants = new Map<string, MockApplicant>();
  private readonly externalIndex = new Map<string, string>();
  private readonly scriptedVerdicts: Record<string, KycEventKind>;
  private readonly webhookSecret: string;

  constructor(config: MockKycProviderConfig = { mode: 'sandbox' }) {
    this.scriptedVerdicts = config.scriptedVerdicts ?? {};
    this.webhookSecret = config.webhookSecret ?? 'mock-webhook-secret';
  }

  private record(method: keyof KycProvider, args: unknown[]): void {
    this.calls.push({ method, args, at: Date.now() });
  }

  async createApplicant(input: {
    externalUserId: string;
    levelHint: string;
    email?: string;
    phone?: string;
  }): Promise<{ applicantId: string }> {
    this.record('createApplicant', [input]);

    // Idempotent on externalUserId — same id → same applicantId.
    const existing = this.externalIndex.get(input.externalUserId);
    if (existing) return { applicantId: existing };

    const applicantId = `mock_${input.externalUserId}_${this.applicants.size + 1}`;
    this.applicants.set(applicantId, {
      applicantId,
      externalUserId: input.externalUserId,
      state: 'pending',
    });
    this.externalIndex.set(input.externalUserId, applicantId);
    return { applicantId };
  }

  async mintClientSession(input: {
    applicantId: string;
    externalUserId: string;
    ttlSec: number;
  }): Promise<{ token: string; expiresAt: number; redirectUrl?: string }> {
    this.record('mintClientSession', [input]);
    if (!this.applicants.has(input.applicantId)) {
      throw new Error(`mock: unknown applicantId ${input.applicantId}`);
    }
    const expiresAt = Math.floor(Date.now() / 1000) + Math.max(1, input.ttlSec);
    return {
      token: `mocksdk_${input.applicantId}_${expiresAt}`,
      expiresAt,
    };
  }

  /**
   * Mock webhook signature: `x-mock-sig = HMAC_SHA256(rawBody, webhookSecret)` hex.
   * Mirrors Sumsub's "verify-by-recomputing-from-raw-body" pattern so tests
   * exercise the same constant-time-compare seam as the real adapter.
   */
  verifyWebhook(headers: Record<string, string>, rawBody: Buffer): boolean {
    this.record('verifyWebhook', [headers, rawBody]);
    const sig = headers['x-mock-sig'];
    if (typeof sig !== 'string' || sig.length === 0) return false;
    const expected = createHmac('sha256', this.webhookSecret).update(rawBody).digest('hex');
    const a = Buffer.from(sig);
    const b = Buffer.from(expected);
    if (a.length !== b.length) return false;
    return timingSafeEqual(a, b);
  }

  async parseWebhookEvent(rawBody: Buffer): Promise<KycEvent> {
    this.record('parseWebhookEvent', [rawBody]);
    const decoded = JSON.parse(rawBody.toString('utf8')) as {
      applicantId: string;
      externalUserId?: string;
      kind: KycEventKind;
      occurredAt?: number;
    };

    // Apply scripted-verdict overlay on synthetic completion.
    let kind = decoded.kind;
    if (decoded.externalUserId && this.scriptedVerdicts[decoded.externalUserId]) {
      kind = this.scriptedVerdicts[decoded.externalUserId];
    }

    const applicant = this.applicants.get(decoded.applicantId);
    if (applicant) {
      switch (kind) {
        case 'verified':
          applicant.state = 'verified';
          applicant.verifiedAt = Date.now();
          // Default 1-year expiry, matching the production adapter's posture.
          applicant.expiresAt = applicant.verifiedAt + 365 * 24 * 60 * 60 * 1000;
          break;
        case 'rejected':
          applicant.state = 'rejected';
          break;
        case 'pending':
          applicant.state = 'pending';
          break;
        case 'reset':
          applicant.state = 'unverified';
          applicant.verifiedAt = undefined;
          applicant.expiresAt = undefined;
          break;
      }
    }

    return {
      externalUserId: decoded.externalUserId,
      applicantId: decoded.applicantId,
      kind,
      occurredAt: decoded.occurredAt ?? Date.now(),
      raw: decoded,
    };
  }

  async getApplicantStatus(applicantId: string): Promise<KycStatus> {
    this.record('getApplicantStatus', [applicantId]);
    const a = this.applicants.get(applicantId);
    if (!a) {
      return { state: 'unverified', providerRaw: null };
    }
    return {
      state: a.state,
      verifiedAt: a.verifiedAt,
      expiresAt: a.expiresAt,
      providerRaw: { applicantId: a.applicantId, externalUserId: a.externalUserId },
    };
  }

  async deleteApplicant(applicantId: string): Promise<void> {
    this.record('deleteApplicant', [applicantId]);
    const a = this.applicants.get(applicantId);
    if (!a) return;
    this.applicants.delete(applicantId);
    this.externalIndex.delete(a.externalUserId);
  }

  /**
   * Test helper: produce a body + signature pair that authenticates
   * against this provider, so tests can exercise the webhook path
   * without manually computing HMACs.
   */
  buildSignedWebhook(payload: {
    applicantId: string;
    externalUserId?: string;
    kind: KycEventKind;
    occurredAt?: number;
  }): { body: Buffer; headers: Record<string, string> } {
    const body = Buffer.from(JSON.stringify(payload), 'utf8');
    const sig = createHmac('sha256', this.webhookSecret).update(body).digest('hex');
    return { body, headers: { 'x-mock-sig': sig } };
  }
}
