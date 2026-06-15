/**
 * EW-S1 WP-4 slice B (item 12) — `bk_` bundler API-key minting.
 *
 * Pins the cross-repo contract with citrate-bundler/gate/src/apikeys.ts
 * (set name, key shape, SHA-256 hash) and the admin-gated fail-closed
 * authorization. The HTTP wrapper is a thin shell over these; the live
 * mint path is exercised end-to-end against the bundler's Redis in ops.
 */
import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';

import {
  BUNDLER_API_KEY_SET,
  hashBundlerApiKey,
  looksLikeBundlerApiKey,
  mintBundlerApiKey,
  parseAdminSubs,
  authorizeBundlerKeyMint,
} from '../../src/aa/bundler-keys.js';

describe('bundler API-key contract (must match citrate-bundler gate)', () => {
  it('hash is plain SHA-256 hex of the key string', () => {
    const k = 'bk_test';
    expect(hashBundlerApiKey(k)).toBe(
      createHash('sha256').update(k, 'utf8').digest('hex'),
    );
    expect(hashBundlerApiKey('bk_test')).toHaveLength(64);
  });

  it('set name is the gate-shared `bundler:apikeys`', () => {
    expect(BUNDLER_API_KEY_SET).toBe('bundler:apikeys');
  });

  it('looksLike accepts a real key shape, rejects junk', () => {
    expect(looksLikeBundlerApiKey('bk_' + 'a'.repeat(43))).toBe(true);
    expect(looksLikeBundlerApiKey('nope')).toBe(false);
    expect(looksLikeBundlerApiKey('bk_short')).toBe(false);
    expect(looksLikeBundlerApiKey('bk_has space wahh')).toBe(false);
  });
});

describe('mintBundlerApiKey', () => {
  it('mints a bk_ key, stores ONLY its SHA-256 in the gate set', async () => {
    const calls: Array<{ set: string; member: string }> = [];
    const redis = {
      async sadd(set: string, ...members: string[]) {
        members.forEach((m) => calls.push({ set, member: m }));
        return members.length;
      },
    };
    const key = await mintBundlerApiKey(redis);

    expect(looksLikeBundlerApiKey(key)).toBe(true);
    expect(key.startsWith('bk_')).toBe(true);
    expect(calls).toHaveLength(1);
    expect(calls[0].set).toBe(BUNDLER_API_KEY_SET);
    // The stored member is the HASH, never the plaintext.
    expect(calls[0].member).toBe(hashBundlerApiKey(key));
    expect(calls[0].member).not.toContain(key);
  });

  it('mints distinct keys', async () => {
    const redis = { async sadd() { return 1; } };
    const a = await mintBundlerApiKey(redis);
    const b = await mintBundlerApiKey(redis);
    expect(a).not.toBe(b);
  });
});

describe('parseAdminSubs', () => {
  it('splits, trims, drops empties', () => {
    expect(parseAdminSubs('a, b ,,c')).toEqual(['a', 'b', 'c']);
    expect(parseAdminSubs(undefined)).toEqual([]);
    expect(parseAdminSubs('   ')).toEqual([]);
  });
});

describe('authorizeBundlerKeyMint (fail-closed)', () => {
  const admins = ['op-1', 'op-2'];

  it('503 when unconfigured (regardless of who is calling)', () => {
    expect(
      authorizeBundlerKeyMint({ configured: false, accountId: 'op-1', adminSubs: admins }),
    ).toEqual({ ok: false, status: 503, error: 'bundler key minting not configured' });
  });

  it('401 when configured but no authenticated subject', () => {
    expect(
      authorizeBundlerKeyMint({ configured: true, accountId: null, adminSubs: admins }).ok,
    ).toBe(false);
    expect(
      (authorizeBundlerKeyMint({ configured: true, accountId: null, adminSubs: admins }) as { status: number }).status,
    ).toBe(401);
  });

  it('403 when authenticated but not an allowlisted operator', () => {
    expect(
      (authorizeBundlerKeyMint({ configured: true, accountId: 'rando', adminSubs: admins }) as { status: number }).status,
    ).toBe(403);
  });

  it('ok for an allowlisted operator', () => {
    expect(
      authorizeBundlerKeyMint({ configured: true, accountId: 'op-2', adminSubs: admins }),
    ).toEqual({ ok: true });
  });
});
