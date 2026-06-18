/**
 * KycProvider — vendor-agnostic interface for KYC integrations
 * (WP-1 of the 2026-06-05 COMPLIANCE-S1 sprint).
 *
 * One adapter ships per supported vendor in this same module
 * (`sumsub.ts`, `clear.ts`, ...). Caller code never imports an adapter
 * directly — it imports {@link selectProvider} from `./index` and binds
 * by env (`KYC_PROVIDER=sumsub|clear|mock`).
 *
 * The interface is honest about what it hides and what it leaks. See
 * `citrate-federation/.agentile/adrs/ADR-2026-06-05-kyc-provider-abstraction.md`
 * for the two named leaks (`levelHint` taxonomy, fat-vs-thin webhooks).
 *
 * Invariants this module enforces (or refuses to enforce):
 *   - **Stores no PII.** The data model only carries vendor identifiers
 *     and lifecycle state. Anything richer than {@link KycStatus} on
 *     this interface is a bug.
 *   - **One unified event vocabulary.** `parseWebhookEvent` returns a
 *     four-state enum ({@link KycEventKind}) regardless of how many
 *     states the vendor lifecycle has. Adapters do the narrowing.
 *   - **Async everywhere on parse**, because CLEAR's parse needs a
 *     follow-up HTTP and Sumsub's does not. Returning `Promise` from
 *     both is the only way to share the signature.
 */

/**
 * Vendor-neutral verification result. Adapters narrow their lifecycle
 * vocabulary into these four states.
 */
export type KycEventKind = 'verified' | 'rejected' | 'pending' | 'reset';

/**
 * An interpreted webhook event. The vendor's raw payload is preserved on
 * `raw` for audit logging.
 */
export interface KycEvent {
  /** The integrator-supplied user id, if the vendor returned it. */
  externalUserId?: string;
  /** The vendor's primary key for the applicant. */
  applicantId: string;
  /** Narrowed lifecycle state. */
  kind: KycEventKind;
  /** Provider clock for the event, Unix milliseconds. */
  occurredAt: number;
  /** Vendor-shaped payload, preserved for audit trails. */
  raw: unknown;
}

/**
 * Vendor-neutral status snapshot. Returned by {@link KycProvider.getApplicantStatus}.
 */
export interface KycStatus {
  /** Vendor-neutral state. `unverified` covers both "never started" and "reset". */
  state: 'unverified' | 'pending' | 'verified' | 'rejected';
  /** Unix ms when the verification was confirmed (verified only). */
  verifiedAt?: number;
  /** Unix ms when the verification expires. */
  expiresAt?: number;
  /** Vendor's full response, preserved for audit. */
  providerRaw: unknown;
}

/**
 * The core abstraction. Every supported vendor implements this.
 *
 * NB: `parseWebhookEvent` is async even when it does not strictly need
 * a network call (Sumsub inlines the verdict, so the Sumsub adapter
 * resolves synchronously inside the Promise). Returning a Promise
 * unconditionally is the price of sharing one signature with CLEAR,
 * whose webhook is a thin pointer requiring a follow-up
 * {@link KycProvider.getApplicantStatus} call.
 */
export interface KycProvider {
  /**
   * Bind one of our users to a provider record. Idempotent on
   * `externalUserId`: a second call with the same id returns the
   * existing `applicantId` without creating a duplicate.
   */
  createApplicant(input: {
    /** Citrate-side stable id. NOT the wallet address. */
    externalUserId: string;
    /** Opaque to this interface; adapters resolve to vendor taxonomy. */
    levelHint: string;
    email?: string;
    phone?: string;
  }): Promise<{ applicantId: string }>;

  /**
   * Mint a short-lived credential the client SDK or OIDC redirect
   * needs. Sumsub returns a token for its WebSDK; CLEAR returns an
   * authorize URL. Both are populated in the return shape; the active
   * adapter populates whichever applies.
   */
  mintClientSession(input: {
    applicantId: string;
    externalUserId: string;
    /** Requested TTL in seconds; vendor may cap. */
    ttlSec: number;
    /**
     * Where to send the user after verification, when the vendor supports a
     * native post-flow redirect (Sumsub external WebSDK link `redirect`). The
     * caller validates this against an allowlist first.
     */
    returnTo?: string;
  }): Promise<{
    /** Embedded-SDK access token. Empty when a hosted `redirectUrl` is used. */
    token: string;
    /** Unix seconds at which the token expires. */
    expiresAt: number;
    /**
     * Hosted-flow redirect URL the browser is 303'd to. Sumsub returns its
     * external WebSDK link here (a real hosted page — NOT the embedded-SDK
     * access token, which cannot be opened as a URL). CLEAR returns its authorize URL.
     */
    redirectUrl?: string;
  }>;

  /**
   * Verify a webhook came from the vendor. **Takes RAW body bytes** —
   * any JSON re-serialisation breaks Sumsub's HMAC. Constant-time
   * comparison is the adapter's responsibility.
   *
   * Returns `true` only if the headers + body authenticate. Returns
   * `false` for every failure mode (missing header, bad algorithm,
   * digest mismatch). Never throws on auth failure — that's the
   * caller's 401 path.
   */
  verifyWebhook(headers: Record<string, string>, rawBody: Buffer): boolean;

  /**
   * Decode a verified webhook into a {@link KycEvent}. Caller MUST
   * have already called {@link verifyWebhook} and confirmed `true`.
   *
   * For vendors whose webhook is a pointer (CLEAR), this method may
   * call {@link getApplicantStatus} internally before resolving.
   */
  parseWebhookEvent(rawBody: Buffer): Promise<KycEvent>;

  /**
   * Pull the current status from the vendor. Used for:
   *   - CLEAR thin-webhook follow-up (required).
   *   - Sumsub reconciliation when a webhook is suspected lost (rare).
   *   - Audit / debug.
   */
  getApplicantStatus(applicantId: string): Promise<KycStatus>;

  /**
   * Delete an applicant at the vendor (right-to-delete passthrough).
   * Citrate's own claim record is removed separately by the caller —
   * this method only deletes the upstream record.
   */
  deleteApplicant(applicantId: string): Promise<void>;
}

/**
 * Adapter construction config common to all providers. Each adapter
 * accepts its own extension of this with vendor-specific fields.
 */
export interface KycProviderBaseConfig {
  /** sandbox or prod. Affects vendor host selection + key validation. */
  mode: 'sandbox' | 'prod';
}
