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
