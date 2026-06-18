/**
 * SumsubKycProvider — Sumsub REST + WebSDK adapter.
 *
 * Implements {@link KycProvider} against Sumsub's `api.sumsub.com` REST
 * surface (https://docs.sumsub.com/reference/authentication).
 *
 * Authentication on every outbound call:
 *   - `X-App-Token`: the app token issued by Sumsub.
 *   - `X-App-Access-Ts`: Unix seconds at request time (60s tolerance).
 *   - `X-App-Access-Sig`: lowercase hex HMAC-SHA256 over
 *     `ts + METHOD + path-with-query + body`, using the secret key.
 *
 * Webhook verification (https://docs.sumsub.com/docs/user-verification-webhooks):
 *   - `x-payload-digest-alg` declares the algorithm
 *     (`HMAC_SHA256_HEX`, `HMAC_SHA512_HEX`, or legacy `HMAC_SHA1_HEX`).
 *   - `x-payload-digest` is the lowercase hex digest of the raw body
 *     under the per-webhook secret from the Webhook Manager.
 *
 * **The raw body MUST NOT be re-serialised before HMAC verification.**
 * Any JSON parse → stringify round trip changes whitespace / key order
 * and breaks the digest.
 */

import { createHmac, timingSafeEqual } from 'node:crypto';

import { KYC_LEVELS, type KycLevel, isKycLevel } from './level-hints.js';
import type {
  KycEvent,
  KycEventKind,
  KycProvider,
  KycProviderBaseConfig,
  KycStatus,
} from './types.js';

/** Construction config for the Sumsub adapter. */
export interface SumsubKycProviderConfig extends KycProviderBaseConfig {
  /** Sumsub app token. Sandbox tokens are prefixed `sbx:`. */
  appToken: string;
  /** Secret used to sign outbound REST calls. */
  secretKey: string;
  /** Per-webhook secret from the Sumsub Webhook Manager. */
  webhookSecret: string;
  /** Dashboard-configured Sumsub level for {@link KYC_LEVELS.BASIC_INDIVIDUAL}. */
  basicLevelName: string;
  /** Optional override (default `https://api.sumsub.com`). Regional hosts allowed. */
  baseUrl?: string;
  /** Defaults to `globalThis.fetch`. Injectable for tests. */
  fetchImpl?: typeof fetch;
}

/** A single point of vendor-string resolution per `ADR-2026-06-05-kyc-provider-abstraction`. */
function resolveLevelName(level: string, config: SumsubKycProviderConfig): string {
  if (!isKycLevel(level)) {
    throw new Error(`Sumsub: unknown levelHint "${level}"`);
  }
  switch (level as KycLevel) {
    case KYC_LEVELS.BASIC_INDIVIDUAL:
      return config.basicLevelName;
    case KYC_LEVELS.ENHANCED_INDIVIDUAL:
      throw new Error(
        'Sumsub: ENHANCED_INDIVIDUAL not configured at COMP-S1 (see planset COMP-S4)',
      );
    case KYC_LEVELS.KYB_ENTITY:
      throw new Error(
        'Sumsub: KYB_ENTITY not configured at COMP-S1 (see planset COMP-S4)',
      );
  }
}

/** Maps Sumsub's lifecycle vocabulary to the four-state internal enum. */
export function mapSumsubKind(
  type: string,
  reviewStatus: string | undefined,
  reviewAnswer: string | undefined,
): KycEventKind {
  // Type-first dispatch keeps the table readable.
  switch (type) {
    case 'applicantReviewed': {
      if (reviewStatus === 'completed') {
        if (reviewAnswer === 'GREEN') return 'verified';
        if (reviewAnswer === 'RED') return 'rejected';
      }
      // Unexpected combinations land as pending so the user isn't stranded.
      return 'pending';
    }
    case 'applicantPending':
    case 'applicantPrechecked':
    case 'applicantOnHold':
    case 'applicantCreated':
      return 'pending';
    case 'applicantReset':
    case 'applicantPersonalDataDeleted':
      return 'reset';
    case 'applicantLevelChanged':
      return 'pending';
    default:
      return 'pending';
  }
}

/** Default expires-at horizon for verified claims (1 year). Adjustable later via env. */
const VERIFIED_TTL_MS = 365 * 24 * 60 * 60 * 1000;

/** Webhook digest algorithms Sumsub may declare. */
const DIGEST_ALGS: Record<string, string> = {
  HMAC_SHA256_HEX: 'sha256',
  HMAC_SHA512_HEX: 'sha512',
  HMAC_SHA1_HEX: 'sha1',
};

export class SumsubKycProvider implements KycProvider {
  private readonly config: SumsubKycProviderConfig;
  private readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;

  constructor(config: SumsubKycProviderConfig) {
    if (!config.appToken || !config.secretKey || !config.webhookSecret) {
      throw new Error('SumsubKycProvider: appToken, secretKey, webhookSecret are required');
    }
    if (!config.basicLevelName) {
      throw new Error('SumsubKycProvider: basicLevelName is required');
    }
    this.config = config;
    this.baseUrl = (config.baseUrl ?? 'https://api.sumsub.com').replace(/\/+$/, '');
    this.fetchImpl = config.fetchImpl ?? globalThis.fetch;
    if (typeof this.fetchImpl !== 'function') {
      throw new Error('SumsubKycProvider: no fetch implementation available');
    }
  }

  // ── Public API (KycProvider conformance) ──────────────────────────────

  async createApplicant(input: {
    externalUserId: string;
    levelHint: string;
    email?: string;
    phone?: string;
  }): Promise<{ applicantId: string }> {
    // Sumsub is idempotent-by-design: a GET-by-externalUserId returns
    // the existing applicant if one already exists, avoiding duplicates
    // on a retry.
    const existing = await this.tryGetByExternalUserId(input.externalUserId);
    if (existing) return { applicantId: existing };

    const levelName = resolveLevelName(input.levelHint, this.config);
    const body = JSON.stringify({
      externalUserId: input.externalUserId,
      type: 'individual',
      ...(input.email ? { email: input.email } : {}),
      ...(input.phone ? { phone: input.phone } : {}),
    });
    const path = `/resources/applicants?levelName=${encodeURIComponent(levelName)}`;
    const res = await this.signedFetch('POST', path, body);
    const json = (await res.json()) as { id?: string };
    if (!json.id) throw new Error('Sumsub: createApplicant: no id in response');
    return { applicantId: json.id };
  }

  async mintClientSession(input: {
    applicantId: string;
    externalUserId: string;
    ttlSec: number;
    returnTo?: string;
  }): Promise<{ token: string; expiresAt: number; redirectUrl?: string }> {
    const ttl = Math.max(60, Math.min(input.ttlSec, 3600));
    // Generate a HOSTED external WebSDK link (a real, redirectable URL).
    // Redirecting the browser to the idensic page with an embedded-SDK access
    // token yields "Initialization failed. Unknown url." — that token is for
    // snsWebSdk.init() inside a page, not a URL. `userId` (= our externalUserId)
    // links to the applicant createApplicant already made; `redirect` sends the
    // user back to the data room natively after verification.
    const body = JSON.stringify({
      levelName: this.config.basicLevelName,
      userId: input.externalUserId,
      ttlInSecs: ttl,
      ...(input.returnTo
        ? { redirect: { successUrl: input.returnTo, rejectUrl: input.returnTo } }
        : {}),
    });
    const res = await this.signedFetch(
      'POST',
      '/resources/sdkIntegrations/levels/-/websdkLink',
      body,
    );
    const json = (await res.json()) as { url?: string };
    if (!json.url) {
      throw new Error('Sumsub: mintClientSession: no url in websdkLink response');
    }
    return {
      token: '',
      expiresAt: Math.floor(Date.now() / 1000) + ttl,
      redirectUrl: json.url,
    };
  }

  verifyWebhook(headers: Record<string, string>, rawBody: Buffer): boolean {
    const sig = headers['x-payload-digest'];
    const alg = headers['x-payload-digest-alg'] ?? 'HMAC_SHA256_HEX';
    if (typeof sig !== 'string' || sig.length === 0) return false;
    const nodeAlg = DIGEST_ALGS[alg];
    if (!nodeAlg) return false;
    const expected = createHmac(nodeAlg, this.config.webhookSecret)
      .update(rawBody)
      .digest('hex');
    const a = Buffer.from(sig);
    const b = Buffer.from(expected);
    if (a.length !== b.length) return false;
    try {
      return timingSafeEqual(a, b);
    } catch {
      return false;
    }
  }

  async parseWebhookEvent(rawBody: Buffer): Promise<KycEvent> {
    // Sumsub inlines the verdict — no follow-up HTTP needed. Defined as
    // async to share the signature with CLEAR (see ADR-2026-06-05-…).
    const decoded = JSON.parse(rawBody.toString('utf8')) as {
      applicantId: string;
      externalUserId?: string;
      type: string;
      reviewStatus?: string;
      reviewResult?: { reviewAnswer?: string; reviewRejectType?: string };
      createdAtMs?: number;
    };
    const kind = mapSumsubKind(
      decoded.type,
      decoded.reviewStatus,
      decoded.reviewResult?.reviewAnswer,
    );
    return {
      externalUserId: decoded.externalUserId,
      applicantId: decoded.applicantId,
      kind,
      occurredAt: decoded.createdAtMs ?? Date.now(),
      // raw is intentionally the full body so audit can inspect it.
      // Callers MUST NOT persist this verbatim — anything outside the
      // closed KycClaim shape gets dropped at the store boundary.
      raw: decoded,
    };
  }

  async getApplicantStatus(applicantId: string): Promise<KycStatus> {
    const res = await this.signedFetch(
      'GET',
      `/resources/applicants/${encodeURIComponent(applicantId)}/one`,
      '',
    );
    const json = (await res.json()) as {
      id?: string;
      review?: {
        reviewStatus?: string;
        reviewResult?: { reviewAnswer?: string };
      };
      createdAt?: string;
    };
    const reviewStatus = json.review?.reviewStatus;
    const reviewAnswer = json.review?.reviewResult?.reviewAnswer;

    let state: KycStatus['state'] = 'unverified';
    let verifiedAt: number | undefined;
    let expiresAt: number | undefined;

    if (reviewStatus === 'completed' && reviewAnswer === 'GREEN') {
      state = 'verified';
      verifiedAt = Date.now();
      expiresAt = verifiedAt + VERIFIED_TTL_MS;
    } else if (reviewStatus === 'completed' && reviewAnswer === 'RED') {
      state = 'rejected';
    } else if (reviewStatus && reviewStatus !== 'init') {
      state = 'pending';
    }

    return { state, verifiedAt, expiresAt, providerRaw: json };
  }

  async deleteApplicant(applicantId: string): Promise<void> {
    // Sumsub's "delete" surface is a personal-data deletion, not a
    // record drop. See applicantPersonalDataDeleted webhook.
    await this.signedFetch(
      'POST',
      `/resources/applicants/${encodeURIComponent(applicantId)}/erase`,
      '',
    );
  }

  // ── Private ───────────────────────────────────────────────────────────

  /**
   * Signed REST call. `pathWithQuery` MUST start with `/` and include any
   * query string. Body is the raw string to send (empty for GET).
   */
  private async signedFetch(
    method: 'GET' | 'POST' | 'DELETE',
    pathWithQuery: string,
    body: string,
  ): Promise<Response> {
    const ts = Math.floor(Date.now() / 1000).toString();
    const sigInput = ts + method + pathWithQuery + body;
    const sig = createHmac('sha256', this.config.secretKey)
      .update(sigInput, 'utf8')
      .digest('hex');
    const headers: Record<string, string> = {
      'X-App-Token': this.config.appToken,
      'X-App-Access-Ts': ts,
      'X-App-Access-Sig': sig,
      Accept: 'application/json',
    };
    if (method !== 'GET') {
      headers['Content-Type'] = 'application/json';
    }

    const res = await this.fetchImpl(`${this.baseUrl}${pathWithQuery}`, {
      method,
      headers,
      body: method === 'GET' ? undefined : body,
    });
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      throw new Error(`Sumsub ${method} ${pathWithQuery} failed: ${res.status} ${text.slice(0, 200)}`);
    }
    return res;
  }

  private async tryGetByExternalUserId(externalUserId: string): Promise<string | undefined> {
    try {
      const path = `/resources/applicants/-;externalUserId=${encodeURIComponent(externalUserId)}/one`;
      const res = await this.signedFetch('GET', path, '');
      const json = (await res.json()) as { id?: string };
      return json.id;
    } catch {
      // 404 from Sumsub means "no such applicant" — fine, caller will create.
      return undefined;
    }
  }
}
