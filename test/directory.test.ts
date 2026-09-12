/**
 * Self-published bindings directory — unit level (citrate-core#61).
 *
 * Covers the two verifiers (reusing the app's social-ownership attestation +
 * the directory-intent signature), the last-writer/tombstone store semantics,
 * and body validation — without spinning the full OIDC server (that is the job
 * of directory-http.test.ts).
 */
import { describe, expect, it } from 'vitest';
import { privateKeyToAccount } from 'viem/accounts';
import { type Hex } from 'viem';

import {
  InMemoryDirectoryStore,
  buildSocialBindingMessage,
  buildDirectoryPublishStatement,
  buildDirectoryRevokeStatement,
  verifyOwnershipProof,
  parsePublishBody,
  handleKeyOf,
  signedHandle,
} from '../src/directory.js';

const wallet = privateKeyToAccount(`0x${'c3'.repeat(32)}` as Hex);
const other = privateKeyToAccount(`0x${'d4'.repeat(32)}` as Hex);
const NOW = 1_760_000_000;

/** Build a fully-signed, valid publish body the way the desktop app would. */
async function signedPublish(opts: {
  platform?: 'x' | 'discord';
  handle?: string;
  address?: string;
  boundAt?: number;
  displayName?: string;
  signer?: typeof wallet;
  ownershipSigner?: typeof wallet;
} = {}): Promise<Record<string, unknown>> {
  const platform = opts.platform ?? 'x';
  const handle = opts.handle ?? 'satoshi';
  const address = opts.address ?? wallet.address;
  const boundAt = opts.boundAt ?? NOW;
  const signer = opts.signer ?? wallet;
  const ownershipSigner = opts.ownershipSigner ?? wallet;
  const nonce = 'device-nonce-abc123';

  const ownershipSig = await ownershipSigner.signMessage({
    message: buildSocialBindingMessage(platform, signedHandle(handle), address, nonce),
  });
  const sig = await signer.signMessage({
    message: buildDirectoryPublishStatement({ platform, handleKey: handleKeyOf(handle), address, boundAt }),
  });
  return {
    platform,
    handle,
    address,
    bound_at: boundAt,
    ...(opts.displayName ? { display_name: opts.displayName } : {}),
    ownership_proof: { nonce, signature: ownershipSig },
    sig,
  };
}

describe('directory — social-ownership proof (reuses social.rs binding_message)', () => {
  it('accepts a proof signed by the address over the exact app message', async () => {
    const nonce = 'n1';
    const signature = await wallet.signMessage({
      message: buildSocialBindingMessage('x', 'satoshi', wallet.address, nonce),
    });
    expect(
      verifyOwnershipProof({ platform: 'x', handle: 'satoshi', address: wallet.address, nonce, signature }),
    ).toBe(true);
  });

  it('rejects a proof signed by a different key', async () => {
    const nonce = 'n1';
    const signature = await other.signMessage({
      message: buildSocialBindingMessage('x', 'satoshi', wallet.address, nonce),
    });
    expect(
      verifyOwnershipProof({ platform: 'x', handle: 'satoshi', address: wallet.address, nonce, signature }),
    ).toBe(false);
  });

  it('rejects a proof bound to a different handle', async () => {
    const nonce = 'n1';
    const signature = await wallet.signMessage({
      message: buildSocialBindingMessage('x', 'someoneelse', wallet.address, nonce),
    });
    expect(
      verifyOwnershipProof({ platform: 'x', handle: 'satoshi', address: wallet.address, nonce, signature }),
    ).toBe(false);
  });
});

describe('directory — parsePublishBody validation', () => {
  it('accepts a well-formed body', async () => {
    const parsed = parsePublishBody(await signedPublish(), NOW);
    expect('error' in parsed).toBe(false);
  });

  it('strips a leading @ and lowercases the handle key', () => {
    expect(signedHandle('@Satoshi')).toBe('Satoshi');
    expect(handleKeyOf('@Satoshi')).toBe('satoshi');
  });

  for (const [name, mutate] of [
    ['bad platform', (b: Record<string, unknown>) => ({ ...b, platform: 'myspace' })],
    ['empty handle', (b: Record<string, unknown>) => ({ ...b, handle: '' })],
    ['bad address', (b: Record<string, unknown>) => ({ ...b, address: '0x123' })],
    ['garbage bound_at', (b: Record<string, unknown>) => ({ ...b, bound_at: 5 })],
    ['future bound_at', (b: Record<string, unknown>) => ({ ...b, bound_at: NOW + 10_000 })],
    ['missing ownership_proof', (b: Record<string, unknown>) => ({ ...b, ownership_proof: undefined })],
    ['non-hex sig', (b: Record<string, unknown>) => ({ ...b, sig: 'nope' })],
  ] as const) {
    it(`rejects: ${name}`, async () => {
      const parsed = parsePublishBody(mutate(await signedPublish()), NOW);
      expect('error' in parsed).toBe(true);
    });
  }
});

describe('directory store — last-writer + tombstone semantics', () => {
  const rec = (over: Partial<Parameters<InMemoryDirectoryStore['upsert']>[0]> = {}) => ({
    platform: 'x' as const,
    handleKey: 'satoshi',
    handle: 'satoshi',
    address: wallet.address.toLowerCase(),
    boundAt: NOW,
    ...over,
  });

  it('stores, looks up, and searches by prefix', async () => {
    const s = new InMemoryDirectoryStore();
    expect(await s.upsert(rec())).toBe('stored');
    const hit = await s.lookup('x', 'satoshi');
    expect(hit?.address).toBe(wallet.address.toLowerCase());
    expect(hit?.boundAt).toBe(NOW);
    const found = await s.search('x', 'sat', 20);
    expect(found.map((h) => h.handle)).toEqual(['satoshi']);
  });

  it('lookup of an unpublished handle is null (never a guess)', async () => {
    const s = new InMemoryDirectoryStore();
    expect(await s.lookup('x', 'nobody')).toBeNull();
  });

  it('re-publish with a newer bound_at wins; identical is unchanged; older is stale', async () => {
    const s = new InMemoryDirectoryStore();
    await s.upsert(rec());
    expect(await s.upsert(rec())).toBe('unchanged');
    expect(await s.upsert(rec({ boundAt: NOW + 100, displayName: 'Sat' }))).toBe('stored');
    expect((await s.lookup('x', 'satoshi'))?.boundAt).toBe(NOW + 100);
    expect(await s.upsert(rec({ boundAt: NOW - 100 }))).toBe('stale');
  });

  it('revoke tombstones; lookup + search then return nothing', async () => {
    const s = new InMemoryDirectoryStore();
    await s.upsert(rec());
    expect(await s.revoke('x', 'satoshi', wallet.address)).toBe(true);
    expect(await s.lookup('x', 'satoshi')).toBeNull();
    expect(await s.search('x', 'sat', 20)).toEqual([]);
  });

  it('a stranger cannot revoke a binding they are not bound to', async () => {
    const s = new InMemoryDirectoryStore();
    await s.upsert(rec());
    expect(await s.revoke('x', 'satoshi', other.address)).toBe(false);
    expect(await s.lookup('x', 'satoshi')).not.toBeNull();
  });

  it('a replayed publish (same bound_at) cannot un-revoke a tombstone', async () => {
    const s = new InMemoryDirectoryStore();
    await s.upsert(rec());
    await s.revoke('x', 'satoshi', wallet.address);
    // Replaying the original publish (identical bound_at) is stale, not a resurrection.
    expect(await s.upsert(rec())).toBe('stale');
    expect(await s.lookup('x', 'satoshi')).toBeNull();
    // A genuine re-publish with a fresh (newer) bound_at brings it back.
    expect(await s.upsert(rec({ boundAt: NOW + 1 }))).toBe('stored');
    expect(await s.lookup('x', 'satoshi')).not.toBeNull();
  });

  it('search is capped', async () => {
    const s = new InMemoryDirectoryStore();
    for (let i = 0; i < 25; i++) {
      await s.upsert(rec({ handleKey: `user${i.toString().padStart(2, '0')}`, handle: `user${i}` }));
    }
    expect((await s.search('x', 'user', 20)).length).toBe(20);
  });
});

describe('directory — canonical statements are deterministic + case-folded', () => {
  it('publish statement folds address case + handle key', () => {
    const a = buildDirectoryPublishStatement({ platform: 'x', handleKey: 'satoshi', address: wallet.address, boundAt: NOW });
    const b = buildDirectoryPublishStatement({ platform: 'x', handleKey: 'satoshi', address: wallet.address.toLowerCase(), boundAt: NOW });
    expect(a).toBe(b);
    expect(a).toBe(`citrate-directory-binding:v1:x:satoshi:${wallet.address.toLowerCase()}:${NOW}`);
  });

  it('revoke statement has no timestamp', () => {
    expect(buildDirectoryRevokeStatement({ platform: 'discord', handleKey: 'dana', address: wallet.address })).toBe(
      `citrate-directory-revoke:v1:discord:dana:${wallet.address.toLowerCase()}`,
    );
  });
});
