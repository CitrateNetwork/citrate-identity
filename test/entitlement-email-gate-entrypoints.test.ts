/**
 * Entitlement email gate, pinned at the two places that mint or show a tier:
 * the OIDC `findAccount` claims (what every relying party reads) and the
 * Account Hub (`GET /account`).
 *
 * `resolveEntitlementClaim` only lets an email match a grant when the caller
 * passes `emailVerified === true`. The unit test in
 * `entitlements-f01-email-verify.test.ts` covers the resolver itself; these tests
 * cover the callers, which must forward the stored verification flag rather than
 * a constant. Each test uses a store that returns a role-bearing grant only when
 * the lookup is handed an email, so the result is decided purely by whether the
 * caller forwarded the (unverified) address.
 */
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type Provider from 'oidc-provider';

import { findAccount } from '../src/config.js';
import { mountAccountRoute } from '../src/account-routes.js';
import {
  ENTITLEMENT_CLAIM,
  EntitlementStore,
  _setEntitlementStoreForTests,
  type PgLike,
} from '../src/entitlements.js';
import { InMemoryUserStore, getUserStore, setUserStore } from '../src/auth/stores.js';
import { InMemoryKycStore, setKycStore } from '../src/kyc.js';

function emailKeyedGrantPool(grant: Record<string, unknown>): PgLike {
  return {
    async query(text: string, params?: unknown[]) {
      if (!/^\s*SELECT/i.test(text)) return { rows: [] as Record<string, unknown>[] };
      const email = params?.[2] ?? null;
      return { rows: email != null ? [grant] : [] };
    },
  };
}
const ROLE_GRANT = {
  tier: 'confidential', org_id: null, citrate_role: 'auditor', milestone: null, expires_at: null,
};

beforeEach(() => {
  setUserStore(new InMemoryUserStore());
  setKycStore(new InMemoryKycStore());
  _setEntitlementStoreForTests(new EntitlementStore(emailKeyedGrantPool(ROLE_GRANT)));
});
afterEach(() => {
  _setEntitlementStoreForTests(null);
});

async function emailUser(verified: boolean): Promise<string> {
  const store = getUserStore();
  const rec = await store.createWithEmailPassword({ email: 'holder@corp.example', passwordHash: 'x' });
  if (verified) await store.markEmailVerified(rec.id);
  return rec.id;
}

describe('findAccount claims: entitlement needs a verified email', () => {
  it('an unverified email account gets no entitlement claim', async () => {
    const id = await emailUser(false);
    const account = await findAccount(undefined as never, id);
    const claims = (await account!.claims('id_token', 'openid profile', {} as never, [] as never)) as Record<string, unknown>;
    expect(claims.email_verified).toBe(false);
    expect(claims[ENTITLEMENT_CLAIM]).toBeUndefined();
  });

  it('a verified email account gets the grant (control)', async () => {
    const id = await emailUser(true);
    const account = await findAccount(undefined as never, id);
    const claims = (await account!.claims('id_token', 'openid profile', {} as never, [] as never)) as Record<string, unknown>;
    expect(claims[ENTITLEMENT_CLAIM]).toMatchObject({ tier: 'confidential', citrateRole: 'auditor' });
  });
});

describe('GET /account: tier shown needs a verified email', () => {
  async function renderHub(accountId: string): Promise<string> {
    let mw: ((ctx: unknown, next: () => Promise<void>) => Promise<void>) | null = null;
    const provider = {
      use: (fn: typeof mw) => {
        mw = fn;
      },
      Session: { get: async () => undefined },
    } as unknown as Provider;
    mountAccountRoute(provider, {
      handoffStore: { issue: async () => 'n', consume: async (n: string) => (n === 'n' ? accountId : null) },
    });
    let body = '';
    const ctx = {
      method: 'GET',
      path: '/account',
      query: { handoff: 'n' },
      res: { writeHead: () => undefined, end: (b: string) => { body = b; } },
    };
    await mw!(ctx, async () => undefined);
    return body;
  }

  it('an unverified email account is shown the Public tier', async () => {
    const html = await renderHub(await emailUser(false));
    expect(html).toContain('holder@corp.example');
    expect(html).not.toContain('auditor');
    expect(html).toContain('Public');
  });

  it('a verified email account is shown its granted tier (control)', async () => {
    const html = await renderHub(await emailUser(true));
    expect(html).toContain('Confidential · auditor');
  });
});
