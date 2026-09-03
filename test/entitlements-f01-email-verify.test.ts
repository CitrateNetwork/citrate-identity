/**
 * WP-I1 — F-01 (ID-B-001, CRITICAL) + ID-B-003 (HIGH) regression tripwires.
 *
 * F-01: entitlement resolution matched on a self-asserted, UNVERIFIED email, and
 * role grants bypass the KYC gate — so registering a victim's email minted an
 * authority id_token carrying that email's tier AND role, with zero proof of
 * ownership. Fix: the email arm of the lookup fires only when emailVerified===true.
 *
 * ID-B-003: LOOKUP_SQL `ORDER BY (sub=$1) DESC ...` let a NULL comparison (an
 * email-keyed row, whose sub IS NULL) sort ABOVE a real sub match under Postgres
 * NULLS-FIRST/DESC, so a sub-keyed revoke silently failed to override an older
 * email/wallet grant. Fix: `((sub=$1) IS TRUE) DESC ...` so real matches win.
 */
import { describe, it, expect } from 'vitest';
import {
  EntitlementStore,
  resolveEntitlementClaim,
  _setEntitlementStoreForTests,
  type PgLike,
} from '../src/entitlements.js';

// A pool that returns a privileged, email-keyed grant ONLY when the lookup's
// email parameter ($3) is non-null — i.e. it models "there is a grant on this
// email." So whether the attacker inherits it is decided purely by whether the
// resolver forwarded the (unverified) email into the query.
function emailKeyedGrantPool(grant: Record<string, unknown>): PgLike {
  return {
    async query(text: string, params?: unknown[]) {
      if (!/^\s*SELECT/i.test(text)) return { rows: [] as Record<string, unknown>[] };
      const email = params?.[2] ?? null;
      return { rows: email != null ? [grant] : [] };
    },
  };
}
const AUDITOR_GRANT = {
  tier: 'confidential', org_id: null, citrate_role: 'auditor', milestone: null, expires_at: null,
};

describe('F-01 — unverified email must not inherit a grant (tier or role)', () => {
  it('UNVERIFIED email → no entitlement, even for a role-bearing grant (bypass closed)', async () => {
    _setEntitlementStoreForTests(new EntitlementStore(emailKeyedGrantPool(AUDITOR_GRANT)));
    // Attacker: brand-new sub, no wallet, victim's email, no KYC, email NOT verified.
    const ent = await resolveEntitlementClaim('attacker-sub', null, 'victim@corp.com', 'none', false);
    expect(ent).toBeNull(); // RED before the fix: returns { confidential, auditor }
  });

  it('VERIFIED email → the grant resolves as before (no regression for real users)', async () => {
    _setEntitlementStoreForTests(new EntitlementStore(emailKeyedGrantPool(AUDITOR_GRANT)));
    const ent = await resolveEntitlementClaim('legit-sub', null, 'owner@corp.com', 'none', true);
    expect(ent).toMatchObject({ tier: 'confidential', citrateRole: 'auditor' });
  });

  it('emailVerified defaults to false (fail-closed) when a caller omits it', async () => {
    _setEntitlementStoreForTests(new EntitlementStore(emailKeyedGrantPool(AUDITOR_GRANT)));
    // 4-arg legacy call shape — must NOT trust the email.
    const ent = await resolveEntitlementClaim('some-sub', null, 'x@corp.com', 'none');
    expect(ent).toBeNull();
  });
});

describe('ID-B-003 — a sub-keyed revoke outranks an older email-keyed grant (real SQL)', () => {
  it('lookup() returns the sub-keyed `public` revoke, not the older email `confidential`', async () => {
    const { newDb } = await import('pg-mem');
    const db = newDb();
    const { Pool } = db.adapters.createPg();
    const store = new EntitlementStore(new Pool() as unknown as PgLike);
    await store.ensureSchema();
    // older: a role/tier grant keyed on the (now verified) email
    await store.grant({ sub: null, email: 'user@corp.com', wallet: null, tier: 'confidential', citrateRole: 'auditor' });
    await new Promise((r) => setTimeout(r, 10)); // distinct created_at
    // newer: the revoke, keyed on the principal's sub (revoke = grant `public`)
    await store.grant({ sub: 'user-sub', email: null, wallet: null, tier: 'public' });
    const ent = await store.lookup('user-sub', null, 'user@corp.com');
    expect(ent?.tier).toBe('public'); // the sub match must win; RED if NULL sorts first
  });
});
