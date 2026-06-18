/**
 * KYC claim store (IDP-KYC).
 *
 * OIDC ID tokens are immutable once minted: a token issued while a wallet was
 * KYC-verified keeps asserting `verified` forever, and a self-custodied wallet
 * can never be "locked". So KYC MUST NOT live only in the token — it has to be a
 * LIVE, revocable claim that relying parties re-check at `/userinfo` before any
 * high-value action (sell / withdraw / bulk-buy). See
 *   gtm-spine/features/IDP-KYC-claim-revocation.feature
 *   adrs/ADR-2026-06-03-kyc-flow.md
 *
 * DATA-CONTROLLER BOUNDARY (red-team must-fix, ADR-2026-06-03):
 * Citrate is NOT the PII data controller. The KYC vendor (CLEAR primary, Sumsub
 * fallback) holds the documents/SSN and owns retention + erasure. citrate-identity
 * persists ONLY a claim record — {status, verified_at, expires_at, vendor_ref} —
 * and never any PII. `vendor_ref` is an opaque vendor reference / hash that lets
 * us reconcile with the vendor; it is NOT a name, SSN, document, or address.
 * The {@link KycClaim} type is deliberately closed so a PII field cannot be added
 * here by accident.
 */

/** The lifecycle status of a wallet's KYC, as told to us by the vendor webhook. */
export type KycStatus = 'verified' | 'pending' | 'revoked';

/**
 * The ONLY shape Citrate stores per wallet. No PII — see the data-controller note
 * above. Adding a name/SSN/document field here would break the ADR boundary, so
 * the type is intentionally exhaustive.
 */
export interface KycClaim {
  /** Vendor-reported lifecycle state. */
  status: KycStatus;
  /** ISO-8601 instant the vendor verified the user (undefined until verified). */
  verified_at?: string;
  /**
   * ISO-8601 instant the verification lapses. After this instant the claim is
   * treated as NOT verified and re-KYC is required (ADR: expiry → re-verify).
   */
  expires_at?: string;
  /**
   * Opaque vendor reference / hash (e.g. CLEAR/Sumsub applicant id or a hash of
   * it) used only to reconcile with the vendor. NOT PII.
   */
  vendor_ref: string;
}

/**
 * The store abstraction. Reads happen at `/userinfo` (claims) time, so a `get`
 * must always reflect the CURRENT record — a revoke between token issuance and a
 * userinfo call has to be visible immediately.
 *
 * The interface is deliberately small so the in-memory dev implementation is a
 * drop-in swap for the production backing (a database row updated by the vendor
 * webhook). See {@link InMemoryKycStore}.
 */
export interface KycStore {
  /**
   * Current claim for a wallet, or undefined if the wallet never did KYC.
   *
   * The return type is `MaybeAsync` so the SAME interface fits both the
   * single-instance in-memory store (synchronous Map) and the production
   * database-backed store ({@link PgKycStore}, an async round-trip). Every call
   * site `await`s the result — awaiting a plain value is a no-op, so the
   * in-memory path stays synchronous in practice while the DB path is async.
   */
  get(address: string): MaybeAsync<KycClaim | undefined>;
  /** Upsert the claim for a wallet (called by the vendor-webhook handler). */
  set(address: string, claim: KycClaim): MaybeAsync<void>;
  /**
   * Mark a wallet's KYC revoked immediately. Idempotent: revoking an unknown or
   * already-revoked wallet still leaves a `revoked` record so `/userinfo` reports
   * not-verified rather than "never heard of them".
   */
  revoke(address: string): MaybeAsync<void>;
}

/** A value that may be returned directly (in-memory) or via a Promise (DB). */
export type MaybeAsync<T> = T | Promise<T>;

/**
 * Normalize an address key so lookups are case-insensitive. SIWE account ids are
 * EIP-55 checksummed, but a webhook payload might arrive lower/upper-cased; we key
 * on the lowercase form so set/get/revoke always agree.
 */
function key(address: string): string {
  return address.toLowerCase();
}

/**
 * Has this claim lapsed? A claim with an `expires_at` in the past is treated as
 * NOT verified regardless of its stored `status` (ADR: expiry triggers re-KYC).
 */
export function isExpired(claim: KycClaim, now: Date = new Date()): boolean {
  if (!claim.expires_at) return false;
  const expiry = Date.parse(claim.expires_at);
  if (Number.isNaN(expiry)) return false;
  // Degenerate-expiry guard: if expires_at is at or before verified_at, the TTL
  // is zero/negative — a write anomaly, not a real expiry. Treat it as "no
  // meaningful expiry" so a freshly-verified user is never silently locked out
  // by a bad timestamp; genuine re-KYC is driven by a real future expiry.
  if (claim.verified_at) {
    const verified = Date.parse(claim.verified_at);
    if (!Number.isNaN(verified) && expiry <= verified) return false;
  }
  return now.getTime() > expiry;
}

/**
 * The effective, live verification decision for a claim: `verified` ONLY if the
 * stored status is `verified` AND it has not expired. Everything else (pending,
 * revoked, expired, or no claim at all) is not verified. This is the single
 * function `/userinfo` and any RP gate should agree on.
 */
export function effectiveVerified(
  claim: KycClaim | undefined,
  now: Date = new Date(),
): boolean {
  if (!claim) return false;
  if (claim.status !== 'verified') return false;
  return !isExpired(claim, now);
}

/**
 * In-memory KYC claim store.
 *
 * DESIGN CHOICE (not a TODO): a Map is correct for the single-instance dev /
 * test authority. In production the store is the database-backed `PgKycStore`
 * (src/kyc-pg.ts), selected by {@link initKycStoreFromEnv} when `DATABASE_URL` is
 * set — that row is the data-controller boundary: it holds ONLY the
 * {@link KycClaim} record, never PII (the vendor holds PII). The {@link KycStore}
 * interface is small (and `MaybeAsync`) so the swap is a true drop-in, exactly
 * like {@link InMemoryNonceStore}. TD-2 (Wave-2) discharged by that swap.
 */
export class InMemoryKycStore implements KycStore {
  private readonly claims = new Map<string, KycClaim>();

  get(address: string): KycClaim | undefined {
    return this.claims.get(key(address));
  }

  set(address: string, claim: KycClaim): void {
    this.claims.set(key(address), claim);
  }

  revoke(address: string): void {
    const existing = this.claims.get(key(address));
    this.claims.set(key(address), {
      // Preserve the vendor reference if we have one so the revoked record stays
      // reconcilable with the vendor; otherwise mark it explicitly revoked.
      vendor_ref: existing?.vendor_ref ?? 'revoked',
      verified_at: existing?.verified_at,
      // A revoke clears any forward-dated expiry — the record is dead now.
      status: 'revoked',
    });
  }
}

/**
 * Process-wide KYC store singleton. `findAccount` (config.ts) reads from this at
 * `claims()` time so `/userinfo` always reflects the CURRENT record. Tests can
 * swap it via {@link setKycStore} to drive verification / revocation / expiry.
 *
 * It is a module singleton (rather than threaded through every call) because
 * panva constructs the account through the configured `findAccount` with no place
 * to inject per-request dependencies; the nonce store uses the same pattern at the
 * route layer. In production this singleton is the DB-backed store.
 */
let kycStore: KycStore = new InMemoryKycStore();

/** The live KYC store the authority reads at claims/userinfo time. */
export function getKycStore(): KycStore {
  return kycStore;
}

/** Swap the live KYC store (production wiring / tests). */
export function setKycStore(store: KycStore): void {
  kycStore = store;
}

/**
 * Install the right KYC store for the running environment (TD-2). Called once at
 * server boot (see {@link createProvider} → server.ts).
 *
 *   - `DATABASE_URL` set  → a {@link PgKycStore}: the claim record survives
 *     restarts and is shared across instances (the data-loss / multi-instance gap
 *     TD-2 names). `ensureSchema()` runs idempotently so the table exists.
 *   - `DATABASE_URL` unset → the in-memory dev store, with a one-line warning so a
 *     developer running locally knows persistence is off. In PRODUCTION an unset
 *     `DATABASE_URL` never reaches here: {@link assertProductionConfig} throws
 *     first (fail-closed, same posture as COOKIE_KEYS) so we cannot silently boot
 *     production on a volatile Map.
 *
 * Imported lazily so the `pg` driver is only pulled in when a database is actually
 * configured — dev/test paths that use the in-memory store never touch `pg`.
 */
export async function initKycStoreFromEnv(
  env: { DATABASE_URL?: string } = process.env,
): Promise<KycStore> {
  const databaseUrl = env.DATABASE_URL;
  if (databaseUrl && databaseUrl.trim() !== '') {
    const { PgKycStore } = await import('./kyc-pg.js');
    const store = await PgKycStore.connect(databaseUrl);
    setKycStore(store);
    return store;
  }
  // eslint-disable-next-line no-console
  console.warn(
    '[citrate-identity] DATABASE_URL unset — using the in-memory KYC store ' +
      '(claims are lost on restart and not shared across instances). Set ' +
      'DATABASE_URL to back KYC with Postgres (required in production).',
  );
  const store = new InMemoryKycStore();
  setKycStore(store);
  return store;
}
