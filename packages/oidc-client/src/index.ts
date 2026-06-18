/**
 * @citrate/oidc-client — the shared Citrate entitlement/KYC claim contract + RBAC
 * helpers (AUTHSPINE S2-WP1). Framework-agnostic, dependency-free. EVERY Citrate
 * relying party reads authorization through these helpers so the tier ladder, the
 * role model, and the claim shape are identical across the ecosystem.
 *
 * Canonical contract: ADR-2026-06-18-rbac-entitlement-claim-contract.
 *
 * The two claims (both already minted by auth.citrate.ai):
 *   - `kyc_status` (+ kyc_verified_at/expires_at), scope `kyc`, read LIVE from /me.
 *   - `https://citrate.ai/entitlement`, rides scope `openid` (always present when on
 *     the roster + past the KYC gate); ABSENT ⇒ treat as Public (fail-safe).
 */

export const ENTITLEMENT_CLAIM = 'https://citrate.ai/entitlement';

export type KycStatus = 'verified' | 'pending' | 'revoked' | 'expired' | 'none';

export type Tier = 'public' | 'commercial' | 'commercial.kyc' | 'academic' | 'confidential';

/**
 * Tier rank for `requireTier` comparisons. NOTE this is an ACCESS-LEVEL ordering for
 * gating; `commercial.kyc` (the KYC baseline) ranks above bare `commercial` because
 * it denotes a verified member. Roles are orthogonal (see requireRole).
 */
export const TIER_ORDER: Record<Tier, number> = {
  public: 0,
  commercial: 1,
  'commercial.kyc': 2,
  academic: 3,
  confidential: 4,
};

export interface Entitlement {
  tier: Tier;
  orgId: string | null;
  citrateRole?: string;
  milestone?: string;
  /** epoch-ms; access past this collapses to Public. */
  expiresAt?: number | null;
}

/** The normalized authorization view an RP holds for a signed-in principal. */
export interface Access {
  sub?: string;
  email?: string;
  emailVerified?: boolean;
  walletAddress?: string;
  kycStatus: KycStatus;
  kycVerifiedAt?: string;
  kycExpiresAt?: string;
  /** null ⇒ Public (no entitlement claim / not on roster). */
  entitlement: Entitlement | null;
}

const TIERS = new Set<string>(Object.keys(TIER_ORDER));
function asTier(v: unknown): Tier | null {
  return typeof v === 'string' && TIERS.has(v) ? (v as Tier) : null;
}

/**
 * Normalize raw OIDC claims (from an id_token payload OR a /userinfo response) into
 * {@link Access}. Unknown/absent claims fail safe (kyc `none`, entitlement `null`).
 */
export function parseClaims(raw: Record<string, unknown> | null | undefined): Access {
  const c = raw ?? {};
  const kyc = (typeof c.kyc_status === 'string' ? c.kyc_status : 'none') as KycStatus;
  const kycStatus: KycStatus =
    kyc === 'verified' || kyc === 'pending' || kyc === 'revoked' || kyc === 'expired' ? kyc : 'none';

  let entitlement: Entitlement | null = null;
  const e = c[ENTITLEMENT_CLAIM];
  if (e && typeof e === 'object') {
    const o = e as Record<string, unknown>;
    const tier = asTier(o.tier);
    if (tier) {
      entitlement = {
        tier,
        orgId: typeof o.orgId === 'string' ? o.orgId : null,
        citrateRole: typeof o.citrateRole === 'string' ? o.citrateRole : undefined,
        milestone: typeof o.milestone === 'string' ? o.milestone : undefined,
        expiresAt: typeof o.expiresAt === 'number' ? o.expiresAt : null,
      };
    }
  }
  return {
    sub: typeof c.sub === 'string' ? c.sub : undefined,
    email: typeof c.email === 'string' ? c.email : undefined,
    emailVerified: typeof c.email_verified === 'boolean' ? c.email_verified : undefined,
    walletAddress: typeof c.wallet_address === 'string' ? c.wallet_address : undefined,
    kycStatus,
    kycVerifiedAt: typeof c.kyc_verified_at === 'string' ? c.kyc_verified_at : undefined,
    kycExpiresAt: typeof c.kyc_expires_at === 'string' ? c.kyc_expires_at : undefined,
    entitlement,
  };
}

/** Is the live KYC effectively verified (verified AND not past expiry)? */
export function isKycVerified(a: Access, now: number = Date.now()): boolean {
  if (a.kycStatus !== 'verified') return false;
  if (a.kycExpiresAt) {
    const exp = Date.parse(a.kycExpiresAt);
    if (!Number.isNaN(exp) && exp <= now) return false;
  }
  return true;
}

/** The effective tier (entitlement tier, honoring expiry; absent ⇒ public). */
export function effectiveTier(a: Access, now: number = Date.now()): Tier {
  const e = a.entitlement;
  if (!e) return 'public';
  if (e.expiresAt != null && now > e.expiresAt) return 'public';
  return e.tier;
}

/** RBAC: does the principal meet `min` tier? (absent ⇒ public ⇒ only meets `public`.) */
export function requireTier(a: Access, min: Tier, now: number = Date.now()): boolean {
  return TIER_ORDER[effectiveTier(a, now)] >= TIER_ORDER[min];
}

/** RBAC: does the principal carry `role` (e.g. admin/auditor/exec)? */
export function requireRole(a: Access, role: string): boolean {
  return a.entitlement?.citrateRole === role;
}

/**
 * The Account Hub URL an RP links to ("Manage account / Upgrade"). Pass the issuer
 * origin (e.g. https://auth.citrate.ai) and this RP's origin as `returnTo`.
 */
export function accountHubUrl(issuer: string, returnTo?: string): string {
  const base = issuer.replace(/\/+$/, '') + '/account';
  return returnTo ? `${base}?return_to=${encodeURIComponent(returnTo)}` : base;
}

/**
 * The KYC kickoff URL ("Start / finish verification"). `returnTo` is where Sumsub
 * sends the user back (an allowlisted https origin). level T3 = individual KYC.
 */
export function kycStartUrl(issuer: string, returnTo?: string, level: 'T3' | 'T4' = 'T3'): string {
  const u = new URL(issuer.replace(/\/+$/, '') + '/kyc/start');
  u.searchParams.set('level', level);
  if (returnTo) u.searchParams.set('return_to', returnTo);
  return u.toString();
}
