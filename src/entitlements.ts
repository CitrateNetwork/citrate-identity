/**
 * Entitlements — the authority-side source for the `https://citrate.ai/entitlement`
 * claim (DGX_AUTHSPINE §3). Maps a verified identity (sub / email / wallet) to a
 * Citrate access tier so RPs (Atlas, memrizz, …) get a single, signed, centralized
 * entitlement instead of each resolving it themselves.
 *
 * Resolution is fail-safe and KYC-gated, mirroring the RP rule:
 *   - no record / expired           → no claim minted (RP falls back to Public)
 *   - non-public tier, NOT a role,
 *     and KYC not verified           → downgraded to Public (customers must KYC)
 *   - a role-bearing principal
 *     (admin/auditor/exec/…)         → authorized by the roster, KYC not required
 *
 * Backed by Postgres (`DATABASE_URL`, same store as KYC). When no DB is configured
 * (dev), resolution returns `null` and every token simply carries no entitlement
 * claim — exactly the current behaviour.
 */

import type { KycStatus } from './kyc.js';

/** The claim body, matching the RP `Entitlement` shape Atlas consumes. */
export interface EntitlementClaim {
  tier: 'public' | 'commercial' | 'commercial.kyc' | 'academic' | 'confidential';
  orgId: string | null;
  citrateRole?: string;
  milestone?: string;
  /** epoch-ms; access past this instant collapses to Public RP-side. */
  expiresAt?: number | null;
}

export const ENTITLEMENT_CLAIM = 'https://citrate.ai/entitlement';

/** Minimal `pg.Pool`-compatible surface (also satisfied by pg-mem in tests). */
export interface PgLike {
  query(text: string, params?: unknown[]): Promise<{ rows: Record<string, unknown>[] }>;
}

const CREATE_TABLE_SQL = `
CREATE TABLE IF NOT EXISTS entitlements (
  id            bigserial PRIMARY KEY,
  sub           text,
  email         text,
  wallet        text,
  tier          text NOT NULL,
  org_id        text,
  citrate_role  text,
  milestone     text,
  expires_at    timestamptz,
  created_at    timestamptz NOT NULL DEFAULT now()
)`;
const CREATE_IDX_SQL = [
  `CREATE INDEX IF NOT EXISTS entitlements_sub_idx ON entitlements (sub)`,
  `CREATE INDEX IF NOT EXISTS entitlements_email_idx ON entitlements (lower(email))`,
  `CREATE INDEX IF NOT EXISTS entitlements_wallet_idx ON entitlements (lower(wallet))`,
];
const TABLE_EXISTS_SQL = `SELECT 1 AS present FROM information_schema.tables WHERE table_name = 'entitlements' LIMIT 1`;

const INSERT_BASELINE_SQL = `INSERT INTO entitlements (sub, tier) VALUES ($1, $2)`;
const INSERT_FULL_SQL = `INSERT INTO entitlements
  (sub, email, wallet, tier, org_id, citrate_role, milestone, expires_at)
  VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`;

/** The tiers the authority recognizes (the RBAC ADR pins their meaning). */
export const TIERS: readonly EntitlementClaim['tier'][] = [
  'public', 'commercial', 'commercial.kyc', 'academic', 'confidential',
];

/** A full entitlement grant (admin API). At least one of sub/email/wallet is required. */
export interface EntitlementGrant {
  sub?: string | null;
  email?: string | null;
  wallet?: string | null;
  tier: EntitlementClaim['tier'];
  orgId?: string | null;
  citrateRole?: string | null;
  milestone?: string | null;
  /** ISO-8601 or null (no expiry). */
  expiresAt?: string | null;
}

/**
 * The tier a freshly KYC-verified principal is auto-granted (AUTHSPINE S1-WP2 / D2):
 * passing KYC OPENS ecosystem access. `commercial.kyc` = a verified, transacting
 * member (T1 actions: sell / withdraw / bulk-buy). Higher tiers (academic /
 * confidential) and roles remain explicit grants. Tunable via the RBAC ADR (S1-WP5).
 */
export const KYC_BASELINE_TIER: EntitlementClaim['tier'] = 'commercial.kyc';

/** Most specific match wins: sub, then wallet, then email; freshest row first. */
const LOOKUP_SQL = `
SELECT tier, org_id, citrate_role, milestone, expires_at
FROM entitlements
WHERE ($1::text IS NOT NULL AND sub = $1)
   OR ($2::text IS NOT NULL AND lower(wallet) = lower($2))
   OR ($3::text IS NOT NULL AND lower(email) = lower($3))
ORDER BY (sub = $1) DESC, (lower(wallet) = lower($2)) DESC, created_at DESC
LIMIT 1`;

export class EntitlementStore {
  constructor(private readonly pool: PgLike) {}

  /** Connect to `databaseUrl`, ensure the schema, return a ready store. */
  static async connect(databaseUrl: string): Promise<EntitlementStore> {
    const { Pool } = await import('pg');
    const pool = new Pool({ connectionString: databaseUrl }) as unknown as PgLike;
    const store = new EntitlementStore(pool);
    await store.ensureSchema();
    return store;
  }

  /** Idempotent — safe on every boot. */
  async ensureSchema(): Promise<void> {
    const exists = await this.pool.query(TABLE_EXISTS_SQL);
    if (exists.rows.length === 0) {
      await this.pool.query(CREATE_TABLE_SQL);
    }
    for (const sql of CREATE_IDX_SQL) {
      await this.pool.query(sql);
    }
  }

  async lookup(
    sub: string | null,
    wallet: string | null,
    email: string | null,
  ): Promise<EntitlementClaim | null> {
    const res = await this.pool.query(LOOKUP_SQL, [sub, wallet, email]);
    const row = res.rows[0];
    if (!row) return null;
    const expiresAt = row.expires_at ? new Date(row.expires_at as string).getTime() : null;
    return {
      tier: row.tier as EntitlementClaim['tier'],
      orgId: (row.org_id as string | null) ?? null,
      citrateRole: (row.citrate_role as string | null) ?? undefined,
      milestone: (row.milestone as string | null) ?? undefined,
      expiresAt,
    };
  }

  /**
   * Grant `tier` to `sub` ONLY if the principal has NO entitlement yet (by sub /
   * wallet / email). This never shadows or downgrades an existing — possibly
   * higher or role-bearing — grant (e.g. an owner's email-keyed `confidential`).
   * Returns true iff a baseline row was inserted. Idempotent across repeated
   * verified webhooks for the same principal.
   */
  async grantBaselineIfAbsent(
    sub: string,
    wallet: string | null,
    email: string | null,
    tier: EntitlementClaim['tier'],
  ): Promise<boolean> {
    const existing = await this.lookup(sub, wallet, email);
    if (existing) return false;
    await this.pool.query(INSERT_BASELINE_SQL, [sub, tier]);
    return true;
  }

  /**
   * Append a full entitlement row (admin grant/raise/revoke). The roster is
   * append-only and {@link lookup} takes the freshest matching row, so this both
   * grants and supersedes prior grants (revoke = grant `public`). The insert IS the
   * audit record (created_at). Higher tiers / roles are issued only through here.
   */
  async grant(g: EntitlementGrant): Promise<void> {
    await this.pool.query(INSERT_FULL_SQL, [
      g.sub ?? null,
      g.email ?? null,
      g.wallet ?? null,
      g.tier,
      g.orgId ?? null,
      g.citrateRole ?? null,
      g.milestone ?? null,
      g.expiresAt ?? null,
    ]);
  }
}

// --- lazy singleton over DATABASE_URL (mirrors the KYC store) ---------------
let storePromise: Promise<EntitlementStore | null> | null = null;

function getStore(): Promise<EntitlementStore | null> {
  if (storePromise) return storePromise;
  const url = process.env.DATABASE_URL;
  storePromise = url
    ? EntitlementStore.connect(url).catch((err) => {
        console.error('[entitlements] store unavailable; minting no entitlement claim:', err);
        return null;
      })
    : Promise.resolve(null);
  return storePromise;
}

/** Test seam: inject a store (e.g. pg-mem) and bypass the DATABASE_URL singleton. */
export function _setEntitlementStoreForTests(store: EntitlementStore | null): void {
  storePromise = Promise.resolve(store);
}

/**
 * Resolve the entitlement claim to mint for a principal, or `null` to mint none.
 * Applies expiry + the KYC gate (role-bearing principals bypass KYC).
 */
export async function resolveEntitlementClaim(
  sub: string | null,
  wallet: string | null,
  email: string | null,
  kycStatus: KycStatus | 'none' | 'expired' | undefined,
): Promise<EntitlementClaim | null> {
  const store = await getStore();
  if (!store) return null;
  const ent = await store.lookup(sub, wallet, email);
  if (!ent) return null;

  // Expired engagement → no entitlement (RP resolves Public).
  if (ent.expiresAt != null && Date.now() > ent.expiresAt) return null;

  // KYC gate: customer tiers require verified KYC; role-bearing principals
  // (admin/auditor/exec) are authorized by the roster, not consumer KYC.
  if (ent.tier !== 'public' && !ent.citrateRole && kycStatus !== 'verified') {
    return { tier: 'public', orgId: null, expiresAt: null };
  }
  return ent;
}

/**
 * On verified KYC, ensure the principal has at least the baseline tier so passing
 * KYC OPENS ecosystem access (AUTHSPINE S1-WP2 / D2). No-op when no store is
 * configured (dev) or the principal already has an entitlement (their explicit
 * grant stands; the KYC gate in {@link resolveEntitlementClaim} keeps it effective).
 * Returns true iff a baseline row was granted. Best-effort: callers should not fail
 * the KYC webhook if this throws (the claim is already persisted).
 */
export async function grantKycBaseline(
  sub: string,
  wallet: string | null,
  email: string | null,
): Promise<boolean> {
  const store = await getStore();
  if (!store) return false;
  return store.grantBaselineIfAbsent(sub, wallet, email, KYC_BASELINE_TIER);
}

/**
 * Append an admin-issued entitlement grant. Returns false when no store is
 * configured (dev). Throws on a DB error so the admin caller sees the failure.
 */
export async function grantEntitlement(g: EntitlementGrant): Promise<boolean> {
  const store = await getStore();
  if (!store) return false;
  await store.grant(g);
  return true;
}
