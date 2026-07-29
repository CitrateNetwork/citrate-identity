/**
 * AUTHSPINE S4-WP4 — adversarial hardening of the authority's entitlement
 * resolution (`resolveEntitlementClaim`), the single trust decision behind every
 * RP's access. These probe the boundaries that matter for the revocation cascade
 * and privilege escalation:
 *   - revoke = append a `public` row → the freshest row wins → access collapses;
 *   - a KYC that is revoked/expired downgrades a customer tier to Public;
 *   - expiry is applied BEFORE the KYC gate (an expired role grant can't ride a
 *     verified KYC back to life);
 *   - a customer (no roster role) can NEVER reach a higher tier without verified
 *     KYC, and the resolver never invents a role.
 *
 * `lookup()` is SQL (`ORDER BY ... created_at DESC LIMIT 1`), so "freshest wins"
 * is exercised by feeding the resolver the row the DB would return after a revoke.
 */
import { describe, it, expect } from 'vitest';
import {
  EntitlementStore,
  resolveEntitlementClaim,
  _setEntitlementStoreForTests,
  type PgLike,
} from '../src/entitlements.js';

function poolReturning(rows: Record<string, unknown>[]): PgLike {
  return { async query() { return { rows }; } };
}
/** The single row `lookup()` would return as freshest for this principal. */
function freshest(row: Record<string, unknown> | null): void {
  _setEntitlementStoreForTests(new EntitlementStore(poolReturning(row ? [row] : [])));
}
const row = (o: Partial<Record<string, unknown>>) => ({
  tier: 'public', org_id: null, citrate_role: null, milestone: null, expires_at: null, ...o,
});

describe('entitlements adversarial — revocation cascade', () => {
  it('revoke (freshest row = public) collapses a once-confidential principal to Public', async () => {
    // Admin appended a `public` row; lookup returns it as freshest.
    freshest(row({ tier: 'public' }));
    const ent = await resolveEntitlementClaim('sub-revoked', null, null, 'verified');
    expect(ent).toEqual({ tier: 'public', orgId: null, expiresAt: null });
  });

  it('KYC "revoked" collapses a VERIFIED tier to paid `commercial` — keeps paid access, never escalates', async () => {
    // ADR-2026-07-25: losing KYC drops the verified-only `commercial.kyc` to the paid
    // baseline `commercial` (payment still stands), NOT to Public. The no-escalation
    // invariant holds — reaching `commercial.kyc` again still requires verified KYC.
    freshest(row({ tier: 'commercial.kyc', org_id: 'acme' }));
    const ent = await resolveEntitlementClaim('sub-x', null, null, 'revoked');
    expect(ent?.tier).toBe('commercial');
  });

  it('a paid `commercial` tier SURVIVES an expired/unverified KYC (payment-as-sybil access)', async () => {
    freshest(row({ tier: 'commercial' }));
    const ent = await resolveEntitlementClaim('sub-x', null, null, 'expired');
    expect(ent?.tier).toBe('commercial');
  });

  it('a customer STILL cannot reach commercial.kyc without verified KYC (no escalation)', async () => {
    // The load-bearing security invariant: unverified never yields the VERIFIED tier.
    freshest(row({ tier: 'commercial.kyc' }));
    const ent = await resolveEntitlementClaim('sub-x', null, null, 'pending');
    expect(ent?.tier).not.toBe('commercial.kyc');
    expect(ent?.tier).toBe('commercial');
  });
});

describe('entitlements adversarial — expiry beats the KYC gate (no resurrection)', () => {
  it('an expired role grant is dropped (→ null) even with verified KYC — not kept as a role', async () => {
    freshest(row({ tier: 'confidential', citrate_role: 'auditor', expires_at: new Date(Date.now() - 1).toISOString() }));
    const ent = await resolveEntitlementClaim('sub-auditor', null, null, 'verified');
    expect(ent).toBeNull();
  });

  it('a not-yet-expired grant (future expiry) is honored', async () => {
    const future = new Date(Date.now() + 60_000).toISOString();
    freshest(row({ tier: 'commercial.kyc', expires_at: future }));
    const ent = await resolveEntitlementClaim('sub-ok', null, null, 'verified');
    expect(ent?.tier).toBe('commercial.kyc');
  });
});

describe('entitlements adversarial — no privilege escalation', () => {
  it('a customer (no roster role) cannot reach confidential without verified KYC', async () => {
    freshest(row({ tier: 'confidential' })); // role-less confidential row + unverified
    const ent = await resolveEntitlementClaim('sub-climber', null, null, 'pending');
    expect(ent).toEqual({ tier: 'public', orgId: null, expiresAt: null });
  });

  it('the resolver never invents a role: role bypass requires a roster citrate_role', async () => {
    // Same tier, but WITH a roster-issued role → KYC not required (authorized by roster).
    freshest(row({ tier: 'confidential', citrate_role: 'admin' }));
    const ent = await resolveEntitlementClaim('sub-admin', null, null, 'none');
    expect(ent?.tier).toBe('confidential');
    expect(ent?.citrateRole).toBe('admin');
  });

  it('undefined KYC status is treated as not-verified (no escalation to the verified tier)', async () => {
    // Fail-safe: an unknown KYC status must NOT yield the VERIFIED tier. Under
    // ADR-2026-07-25 it collapses `commercial.kyc` to the paid baseline `commercial`
    // (payment stands), never escalating to `commercial.kyc`.
    freshest(row({ tier: 'commercial.kyc' }));
    const ent = await resolveEntitlementClaim('sub-x', null, null, undefined);
    expect(ent?.tier).toBe('commercial');
    expect(ent?.tier).not.toBe('commercial.kyc');
  });
});
