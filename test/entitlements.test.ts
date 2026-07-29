import { describe, it, expect } from 'vitest';
import {
  EntitlementStore,
  resolveEntitlementClaim,
  _setEntitlementStoreForTests,
  type PgLike,
} from '../src/entitlements.js';

/** A fake pg.Pool that returns fixed rows regardless of the query. */
function poolReturning(rows: Record<string, unknown>[]): PgLike {
  return { async query() { return { rows }; } };
}

function withRows(rows: Record<string, unknown>[]): void {
  _setEntitlementStoreForTests(new EntitlementStore(poolReturning(rows)));
}

describe('entitlements — resolveEntitlementClaim', () => {
  it('mints a role-bearing entitlement without requiring KYC', async () => {
    withRows([{ tier: 'confidential', org_id: null, citrate_role: 'admin', milestone: null, expires_at: null }]);
    const ent = await resolveEntitlementClaim('sub-1', null, 'a@b.c', 'none');
    expect(ent).toEqual({ tier: 'confidential', orgId: null, citrateRole: 'admin', milestone: undefined, expiresAt: null });
  });

  it('KEEPS a paid `commercial` tier WITHOUT KYC (ADR-2026-07-25 payment-as-sybil)', async () => {
    // A paid-but-unverified member gets ACCESS — payment authorizes `commercial`.
    // KYC is enforced only at the KYC-gated actions (withdrawal, commissary), not here.
    withRows([{ tier: 'commercial', org_id: 'boeing', citrate_role: null, milestone: null, expires_at: null }]);
    const ent = await resolveEntitlementClaim('sub-2', null, 'x@y.z', 'pending');
    expect(ent?.tier).toBe('commercial');
    expect(ent?.orgId).toBe('boeing');
  });

  it('collapses an unverified `commercial.kyc` to `commercial` — keeps PAID access, never Public', async () => {
    withRows([{ tier: 'commercial.kyc', org_id: null, citrate_role: null, milestone: null, expires_at: null }]);
    const ent = await resolveEntitlementClaim('sub-2b', null, 'x@y.z', 'pending');
    expect(ent?.tier).toBe('commercial');
  });

  it('STILL downgrades a non-paid consumer tier (academic/confidential) to Public without KYC', async () => {
    withRows([{ tier: 'academic', org_id: null, citrate_role: null, milestone: null, expires_at: null }]);
    const ent = await resolveEntitlementClaim('sub-2c', null, 'x@y.z', 'pending');
    expect(ent).toEqual({ tier: 'public', orgId: null, expiresAt: null });
  });

  it('keeps a customer tier once KYC is verified', async () => {
    withRows([{ tier: 'commercial', org_id: 'boeing', citrate_role: null, milestone: 'production', expires_at: null }]);
    const ent = await resolveEntitlementClaim('sub-3', null, 'x@y.z', 'verified');
    expect(ent?.tier).toBe('commercial');
    expect(ent?.orgId).toBe('boeing');
  });

  it('drops an expired entitlement (→ null, RP resolves Public)', async () => {
    withRows([{ tier: 'confidential', org_id: 'audit', citrate_role: 'auditor_tob', milestone: null, expires_at: new Date(Date.now() - 1000).toISOString() }]);
    const ent = await resolveEntitlementClaim('sub-4', null, null, 'verified');
    expect(ent).toBeNull();
  });

  it('no record on file → null (never escalate an unknown principal)', async () => {
    withRows([]);
    const ent = await resolveEntitlementClaim('nobody', null, null, 'none');
    expect(ent).toBeNull();
  });

  it('no store configured (no DATABASE_URL) → null', async () => {
    _setEntitlementStoreForTests(null);
    const ent = await resolveEntitlementClaim('sub', null, null, 'verified');
    expect(ent).toBeNull();
  });
});

/** A pool that returns `lookupRows` for SELECTs and records every query. */
function recordingPool(lookupRows: Record<string, unknown>[]) {
  const calls: { text: string; params?: unknown[] }[] = [];
  const pool: PgLike & { calls: typeof calls } = {
    calls,
    async query(text: string, params?: unknown[]) {
      calls.push({ text, params });
      return { rows: /^\s*SELECT/i.test(text) ? lookupRows : [] };
    },
  };
  return pool;
}

describe('entitlements — grantBaselineIfAbsent (AUTHSPINE S1-WP2)', () => {
  it('inserts the baseline tier when the principal has NO entitlement', async () => {
    const pool = recordingPool([]);
    const store = new EntitlementStore(pool);
    const granted = await store.grantBaselineIfAbsent('sub-new', null, 'new@x.io', 'commercial.kyc');
    expect(granted).toBe(true);
    const insert = pool.calls.find((c) => /INSERT/i.test(c.text));
    expect(insert).toBeDefined();
    expect(insert!.params).toEqual(['sub-new', 'commercial.kyc']);
  });

  it('does NOT shadow an existing (e.g. confidential/admin) grant', async () => {
    const pool = recordingPool([
      { tier: 'confidential', org_id: null, citrate_role: 'admin', milestone: null, expires_at: null },
    ]);
    const store = new EntitlementStore(pool);
    const granted = await store.grantBaselineIfAbsent('owner-sub', null, 'owner@x.io', 'commercial.kyc');
    expect(granted).toBe(false);
    expect(pool.calls.some((c) => /INSERT/i.test(c.text))).toBe(false);
  });
});
