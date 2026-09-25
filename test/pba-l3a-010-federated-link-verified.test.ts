/**
 * PBA-L3a-010 (LOW) — Google / GitHub / Discord login linked the provider identity
 * onto an existing local account by email WITHOUT checking that the local
 * account's email was verified (and linking then marked it verified). Whoever
 * pre-registered the victim's address unverified (legacy rows; the verify-first
 * flow no longer creates them) owned the account the victim signs into.
 *
 * Fix under test: link by email only when BOTH sides are verified; otherwise the
 * provider identity gets its own account and the unverified row is untouched.
 */
import { afterAll, describe, expect, it, beforeEach } from 'vitest';
import { InMemoryUserStore, type UserStore } from '../src/auth/stores.js';
import { resolveGoogleUser } from '../src/auth/google-routes.js';
import { resolveFederatedUser } from '../src/auth/oauth2-provider.js';
import { testPg } from './helpers/pg.js';
import { PgUserStore } from '../src/auth/users-pg.js';

const db = testPg();
afterAll(async () => { await db.close(); });
const stores: Array<[string, () => Promise<UserStore>]> = [
  ['in-memory', async () => new InMemoryUserStore()],
  ['postgres', async () => {
    await db.reset(['federated_identities', 'users']);
    const s = new PgUserStore(db.pool as never);
    await s.ensureSchema();
    return s;
  }],
];

for (const [name, make] of stores) {
  describe(`PBA-L3a-010 federated login never links onto an unverified email (${name})`, () => {
    let store: UserStore;
    beforeEach(async () => { store = await make(); });

    it('Google: an unverified squatter row is not linked or verified', async () => {
      const squatter = await store.createWithEmailPassword({ email: 'victim@example.com', passwordHash: 'attacker-hash' });
      const u = await resolveGoogleUser({ sub: 'g-123', email: 'victim@example.com', email_verified: true }, store);
      expect(u).toBeDefined();
      expect(u!.id).not.toBe(squatter.id);
      const after = await store.findById(squatter.id);
      expect(after?.emailVerified).toBe(false);
      expect(after?.googleSub ?? null).toBeNull();
    });

    it('GitHub/Discord: same rule', async () => {
      const squatter = await store.createWithEmailPassword({ email: 'v2@example.com', passwordHash: 'attacker-hash' });
      const u = await resolveFederatedUser('github', { providerSub: 'gh-9', email: 'v2@example.com' }, store);
      expect(u!.id).not.toBe(squatter.id);
      expect((await store.findById(squatter.id))?.emailVerified).toBe(false);
      expect(await store.findByFederated('github', 'gh-9')).toMatchObject({ id: u!.id });
    });

    it('a VERIFIED local account is still linked (the legitimate returning user)', async () => {
      const owner = await store.createWithEmailPassword({ email: 'owner@example.com', passwordHash: 'h' });
      await store.markEmailVerified(owner.id);
      expect((await resolveGoogleUser({ sub: 'g-777', email: 'owner@example.com', email_verified: true }, store))!.id).toBe(owner.id);
      expect((await resolveFederatedUser('discord', { providerSub: 'd-1', email: 'owner@example.com' }, store))!.id).toBe(owner.id);
    });
  });
}
