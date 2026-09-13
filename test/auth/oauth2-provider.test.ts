/**
 * OAuth2 federation (FWA #87.3): the proven-email rules per provider, the
 * link/create resolver, and mount gating. The HTTP start/callback plumbing
 * mirrors the (already tested) Google routes; these cover the security core —
 * WHICH email is allowed to bind.
 */
import { describe, expect, it, vi, afterEach } from 'vitest';
import {
  resolveFederatedUser,
  githubIdentity,
  discordIdentity,
  xIdentity,
  mountConfiguredOAuth2Providers,
} from '../../src/auth/oauth2-provider.js';
import { InMemoryUserStore } from '../../src/auth/stores.js';

afterEach(() => vi.unstubAllGlobals());

function stubFetchSequence(responses: Array<{ ok: boolean; json: unknown }>) {
  const fn = vi.fn();
  for (const r of responses) {
    fn.mockResolvedValueOnce({
      ok: r.ok,
      json: async () => r.json,
      text: async () => JSON.stringify(r.json),
    });
  }
  vi.stubGlobal('fetch', fn);
  return fn;
}

describe('provider identity extractors (proven-email rules)', () => {
  it('GitHub binds ONLY a verified primary email', async () => {
    stubFetchSequence([
      { ok: true, json: { id: 12345 } },
      {
        ok: true,
        json: [
          { email: 'secondary@x.com', primary: false, verified: true },
          { email: 'primary@x.com', primary: true, verified: true },
          { email: 'unverified@x.com', primary: false, verified: false },
        ],
      },
    ]);
    expect(await githubIdentity('tok')).toEqual({
      providerSub: '12345',
      email: 'primary@x.com',
    });
  });

  it('GitHub yields NO email when the primary is unverified', async () => {
    stubFetchSequence([
      { ok: true, json: { id: 9 } },
      { ok: true, json: [{ email: 'p@x.com', primary: true, verified: false }] },
    ]);
    expect(await githubIdentity('tok')).toEqual({ providerSub: '9' });
  });

  it('Discord binds the email ONLY when verified===true', async () => {
    stubFetchSequence([{ ok: true, json: { id: 'd1', email: 'd@x.com', verified: true } }]);
    expect(await discordIdentity('tok')).toEqual({ providerSub: 'd1', email: 'd@x.com' });
  });

  it('Discord yields NO email when unverified', async () => {
    stubFetchSequence([{ ok: true, json: { id: 'd2', email: 'd@x.com', verified: false } }]);
    expect(await discordIdentity('tok')).toEqual({ providerSub: 'd2' });
  });

  it('X is handle-only — never asserts an email', async () => {
    stubFetchSequence([{ ok: true, json: { data: { id: 'x1', username: 'someone' } } }]);
    expect(await xIdentity('tok')).toEqual({ providerSub: 'x1' });
  });
});

describe('resolveFederatedUser (link/create)', () => {
  it('returns the existing user for a known (provider, sub)', async () => {
    const store = new InMemoryUserStore();
    const created = await store.createWithFederated({ provider: 'github', providerSub: 's1', email: 'a@b.co' });
    const got = await resolveFederatedUser('github', { providerSub: 's1', email: 'a@b.co' }, store);
    expect(got?.id).toBe(created.id);
  });

  it('links a NEW federated sub onto an existing account by VERIFIED email', async () => {
    const store = new InMemoryUserStore();
    const existing = await store.createWithEmailPassword({ email: 'a@b.co', passwordHash: 'h' });
    await store.markEmailVerified(existing.id);
    const got = await resolveFederatedUser('discord', { providerSub: 'd9', email: 'a@b.co' }, store);
    expect(got?.id).toBe(existing.id); // linked, not a second account
    expect((await store.findByFederated('discord', 'd9'))?.id).toBe(existing.id);
  });

  it('creates an email-bound account when a verified email has no match', async () => {
    const store = new InMemoryUserStore();
    const got = await resolveFederatedUser('github', { providerSub: 'g1', email: 'new@b.co' }, store);
    expect(got?.email).toBe('new@b.co');
    expect(got?.emailVerified).toBe(true);
  });

  it('creates an EMAIL-LESS, UNVERIFIED account for a handle-only provider (X)', async () => {
    const store = new InMemoryUserStore();
    const got = await resolveFederatedUser('x', { providerSub: 'x1' }, store);
    expect(got?.email).toBeUndefined();
    expect(got?.emailVerified).toBe(false);
    // A second X user is a distinct account (no email collision at ''/null).
    const got2 = await resolveFederatedUser('x', { providerSub: 'x2' }, store);
    expect(got2?.id).not.toBe(got?.id);
  });
});

describe('mountConfiguredOAuth2Providers (env gating)', () => {
  const provider = { use() {} } as unknown as Parameters<typeof mountConfiguredOAuth2Providers>[0];

  it('mounts only providers with BOTH id + secret', () => {
    const mounted = mountConfiguredOAuth2Providers(
      provider,
      {
        CITRATE_AA_GITHUB_CLIENT_ID: 'gid',
        CITRATE_AA_GITHUB_CLIENT_SECRET: 'gsec',
        CITRATE_AA_DISCORD_CLIENT_ID: 'did', // secret missing → skipped
        CITRATE_AA_X_CLIENT_ID: 'xid',
        CITRATE_AA_X_CLIENT_SECRET: 'xsec',
      },
      'https://auth.citrate.ai/',
    );
    expect(mounted.sort()).toEqual(['github', 'x']);
  });

  it('mounts nothing when no creds are set', () => {
    expect(mountConfiguredOAuth2Providers(provider, {}, 'https://auth.citrate.ai')).toEqual([]);
  });
});
