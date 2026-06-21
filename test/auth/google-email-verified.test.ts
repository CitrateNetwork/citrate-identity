/**
 * FWA-C6-01 regression — Google federation must NOT trust an UNVERIFIED email.
 *
 * Threat (Class F, cross-tenant identity confusion): a signed Google id_token
 * proves Google ISSUED it, not that the subject owns the `email` it carries.
 * Google emits `email_verified: false` for unverified mailboxes (e.g. a
 * domain-unverified Workspace / Cloud Identity tenant an attacker can
 * provision). If the callback links the attacker's `google_sub` onto — or
 * creates an `emailVerified` account bound to — a victim's email purely on the
 * email string, the attacker takes over the victim's Citrate identity (and its
 * UUID-keyed smart wallet, KYC status, and entitlement tier).
 *
 * The link/create decision lives in {@link resolveGoogleUser}; these tests
 * drive it directly with crafted (already signature-verified) payloads, so no
 * Google token-endpoint / JWKS mock is needed. The audit's NEEDS-REPRO note was
 * about a *live e2e*; the defect itself is in this pure decision and is covered
 * here.
 *
 * RED on pre-fix code: the unverified-email payloads below linked/created on the
 * victim's email. GREEN post-fix: only `email_verified === true` is trusted.
 */
import { beforeEach, describe, expect, it } from 'vitest';
import type { JWTPayload } from 'jose';

import {
  resolveGoogleUser,
  trustedEmailFromIdToken,
} from '../../src/auth/google-routes.js';
import { InMemoryUserStore, type UserStore } from '../../src/auth/stores.js';
import type { UserRecord } from '../../src/auth/users-pg.js';

const VICTIM_EMAIL = 'victim@example.com';
const ATTACKER_SUB = 'attacker-google-sub-0001';

async function seedVictimPasswordAccount(store: UserStore): Promise<UserRecord> {
  // A pre-existing email/password account — the takeover target. Note its own
  // emailVerified is false (no party proved ownership of the mailbox), exactly
  // as InMemoryUserStore.createWithEmailPassword records it.
  return store.createWithEmailPassword({
    email: VICTIM_EMAIL,
    passwordHash: 'argon2id$dummy',
  });
}

function payload(over: Partial<JWTPayload>): JWTPayload {
  return { sub: ATTACKER_SUB, ...over } as JWTPayload;
}

describe('FWA-C6-01: trustedEmailFromIdToken', () => {
  it('trusts a boolean-true email_verified', () => {
    expect(
      trustedEmailFromIdToken(payload({ email: VICTIM_EMAIL, email_verified: true })),
    ).toBe(VICTIM_EMAIL);
  });

  it('trusts Google\'s legacy string "true" spelling', () => {
    expect(
      trustedEmailFromIdToken(
        payload({ email: VICTIM_EMAIL, email_verified: 'true' }),
      ),
    ).toBe(VICTIM_EMAIL);
  });

  it('REJECTS email_verified:false', () => {
    expect(
      trustedEmailFromIdToken(payload({ email: VICTIM_EMAIL, email_verified: false })),
    ).toBeUndefined();
  });

  it('REJECTS the string "false"', () => {
    expect(
      trustedEmailFromIdToken(
        payload({ email: VICTIM_EMAIL, email_verified: 'false' }),
      ),
    ).toBeUndefined();
  });

  it('REJECTS a missing email_verified claim', () => {
    expect(
      trustedEmailFromIdToken(payload({ email: VICTIM_EMAIL })),
    ).toBeUndefined();
  });

  it('REJECTS a non-boolean/non-"true" email_verified (e.g. 1)', () => {
    expect(
      trustedEmailFromIdToken(
        payload({ email: VICTIM_EMAIL, email_verified: 1 as unknown as boolean }),
      ),
    ).toBeUndefined();
  });

  it('returns undefined when there is no email at all', () => {
    expect(
      trustedEmailFromIdToken(payload({ email_verified: true })),
    ).toBeUndefined();
  });
});

describe('FWA-C6-01: resolveGoogleUser must not take over via unverified email', () => {
  let store: UserStore;

  beforeEach(() => {
    store = new InMemoryUserStore();
  });

  it('does NOT link the google_sub onto a victim account on email_verified:false', async () => {
    const victim = await seedVictimPasswordAccount(store);

    const user = await resolveGoogleUser(
      payload({ email: VICTIM_EMAIL, email_verified: false }),
      store,
    );

    // The victim account must be untouched: no google_sub merged onto it.
    const victimAfter = await store.findById(victim.id);
    expect(victimAfter?.googleSub).toBeUndefined();

    // The resolved account must NOT be the victim's.
    expect(user).toBeDefined();
    expect(user!.id).not.toBe(victim.id);
    // The freshly-created account must carry NO email binding (unverified).
    expect(user!.email).toBeUndefined();
    expect(user!.emailVerified).toBe(false);
    // findByEmail must still resolve to the original victim, not the attacker.
    expect((await store.findByEmail(VICTIM_EMAIL))?.id).toBe(victim.id);
  });

  it('does NOT link when email_verified is absent', async () => {
    const victim = await seedVictimPasswordAccount(store);

    const user = await resolveGoogleUser(
      payload({ email: VICTIM_EMAIL }),
      store,
    );

    expect((await store.findById(victim.id))?.googleSub).toBeUndefined();
    expect(user!.id).not.toBe(victim.id);
    expect(user!.email).toBeUndefined();
  });

  it('does NOT create an email-bound, emailVerified account on email_verified:false', async () => {
    // No pre-existing victim — pure create path.
    const user = await resolveGoogleUser(
      payload({ email: VICTIM_EMAIL, email_verified: false }),
      store,
    );

    expect(user!.email).toBeUndefined();
    expect(user!.emailVerified).toBe(false);
    // No email index entry was created for the asserted address.
    expect(await store.findByEmail(VICTIM_EMAIL)).toBeUndefined();
  });

  it('DOES link the google_sub when email_verified:true (happy path preserved)', async () => {
    const victim = await seedVictimPasswordAccount(store);

    const user = await resolveGoogleUser(
      payload({ email: VICTIM_EMAIL, email_verified: true }),
      store,
    );

    // Legitimately verified: the same person proving the same email links.
    expect(user!.id).toBe(victim.id);
    expect(user!.googleSub).toBe(ATTACKER_SUB);
    expect((await store.findById(victim.id))?.googleSub).toBe(ATTACKER_SUB);
  });

  it('DOES create an email-bound verified account when email_verified:true and no match', async () => {
    const user = await resolveGoogleUser(
      payload({ sub: 'fresh-sub', email: 'new@example.com', email_verified: true }),
      store,
    );

    expect(user!.email).toBe('new@example.com');
    expect(user!.emailVerified).toBe(true);
    expect((await store.findByEmail('new@example.com'))?.id).toBe(user!.id);
  });

  it('returns a returning google_sub user directly, ignoring any email claim', async () => {
    const existing = await resolveGoogleUser(
      payload({ sub: 'returning-sub', email: 'a@example.com', email_verified: true }),
      store,
    );
    // Second sign-in: even an unverified/changed email claim must not relink.
    const again = await resolveGoogleUser(
      payload({ sub: 'returning-sub', email: VICTIM_EMAIL, email_verified: false }),
      store,
    );
    expect(again!.id).toBe(existing!.id);
  });

  it('a matched google_sub short-circuits BEFORE the email path (no relink)', async () => {
    // Mutation guard (kills the "drop findByGoogleSub-first" mutant): an
    // already-linked Google user must be returned directly, even when the
    // id_token also carries a verified email belonging to a DIFFERENT account.
    const other = await store.createWithEmailPassword({
      email: 'other@example.com',
      passwordHash: 'argon2id$dummy',
    });
    const linked = await resolveGoogleUser(
      payload({ sub: 'linked-sub', email: 'mine@example.com', email_verified: true }),
      store,
    );
    // Second call: same sub, but a verified email that maps to `other`.
    const again = await resolveGoogleUser(
      payload({ sub: 'linked-sub', email: 'other@example.com', email_verified: true }),
      store,
    );
    expect(again!.id).toBe(linked!.id);
    expect(again!.id).not.toBe(other.id);
    // `other` must NOT have had linked-sub merged onto it.
    expect((await store.findById(other.id))?.googleSub).toBeUndefined();
  });

  it('returns undefined for a missing sub (caller 401s)', async () => {
    expect(
      await resolveGoogleUser(
        { email: VICTIM_EMAIL, email_verified: true } as JWTPayload,
        store,
      ),
    ).toBeUndefined();
  });
});
