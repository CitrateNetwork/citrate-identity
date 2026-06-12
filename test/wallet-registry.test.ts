/**
 * IDP-S3 — identity ↔ wallet registry (`/identity/:sub/wallets`).
 *
 * Planset gate: "link a 2nd wallet w/ proof; earnings attribute to the
 * linked wallet" — canonical = first wallet (ADR), proof = the WALLET's
 * own signature over a server-issued one-time challenge binding
 * (authority, sub, address, nonce), so neither a bearer token thief nor
 * a replayed proof can attach someone else's wallet.
 *
 * Red-test-first per the SECREM WP protocol: authored before the
 * implementation; the store layer is exercised directly, the proof
 * message + verification through the exported helpers.
 */

import { beforeEach, describe, expect, it } from 'vitest';
import { Wallet, getBytes } from 'ethers';

import {
  InMemoryWalletRegistry,
  buildWalletLinkMessage,
  verifyWalletLinkProof,
  setWalletRegistry,
  getWalletRegistry,
  WalletRegistryError,
} from '../src/identity-registry.js';

const SUB = '0d1f02f1-1f5a-4f5e-9c2e-7b8d1a2b3c4d';
const AUTHORITY = 'auth.citrate.ai';
const CHAIN_ID = 40204;

describe('wallet link proof', () => {
  it('builds a canonical message binding authority, sub, address, nonce', () => {
    const msg = buildWalletLinkMessage({
      authority: AUTHORITY,
      sub: SUB,
      address: '0x8ba1f109551bD432803012645Ac136ddd64DBA72',
      nonce: 'n-123',
      chainId: CHAIN_ID,
    });
    expect(msg).toContain(AUTHORITY);
    expect(msg).toContain(SUB);
    expect(msg).toContain('0x8ba1f109551bd432803012645ac136ddd64dba72');
    expect(msg).toContain('n-123');
    expect(msg).toContain('40204');
  });

  it('accepts the wallet’s own EIP-191 signature and rejects others', async () => {
    const wallet = Wallet.createRandom();
    const msg = buildWalletLinkMessage({
      authority: AUTHORITY,
      sub: SUB,
      address: wallet.address,
      nonce: 'n-1',
      chainId: CHAIN_ID,
    });
    const sig = await wallet.signMessage(msg);
    expect(
      await verifyWalletLinkProof({ message: msg, signature: sig, address: wallet.address }),
    ).toBe(true);

    const stranger = Wallet.createRandom();
    const bad = await stranger.signMessage(msg);
    expect(
      await verifyWalletLinkProof({ message: msg, signature: bad, address: wallet.address }),
    ).toBe(false);
  });
});

describe('InMemoryWalletRegistry', () => {
  beforeEach(() => {
    setWalletRegistry(new InMemoryWalletRegistry());
  });

  it('links wallets in order; the FIRST is canonical', async () => {
    const reg = getWalletRegistry();
    await reg.link(SUB, '0x1111111111111111111111111111111111111111');
    await reg.link(SUB, '0x2222222222222222222222222222222222222222');
    const wallets = await reg.list(SUB);
    expect(wallets.map((w) => w.address)).toEqual([
      '0x1111111111111111111111111111111111111111',
      '0x2222222222222222222222222222222222222222',
    ]);
    expect(wallets[0]?.canonical).toBe(true);
    expect(wallets[1]?.canonical).toBe(false);
  });

  it('one wallet belongs to ONE identity (cross-sub steal rejected)', async () => {
    const reg = getWalletRegistry();
    await reg.link(SUB, '0x1111111111111111111111111111111111111111');
    await expect(
      reg.link('another-sub', '0x1111111111111111111111111111111111111111'),
    ).rejects.toThrow(WalletRegistryError);
  });

  it('re-linking the same wallet to the same sub is idempotent', async () => {
    const reg = getWalletRegistry();
    await reg.link(SUB, '0x1111111111111111111111111111111111111111');
    await reg.link(SUB, '0x1111111111111111111111111111111111111111');
    expect((await reg.list(SUB)).length).toBe(1);
  });

  it('unlinking the canonical wallet promotes the next-oldest', async () => {
    const reg = getWalletRegistry();
    await reg.link(SUB, '0x1111111111111111111111111111111111111111');
    await reg.link(SUB, '0x2222222222222222222222222222222222222222');
    await reg.unlink(SUB, '0x1111111111111111111111111111111111111111');
    const wallets = await reg.list(SUB);
    expect(wallets.length).toBe(1);
    expect(wallets[0]?.address).toBe('0x2222222222222222222222222222222222222222');
    expect(wallets[0]?.canonical).toBe(true);
  });

  it('caps the number of linked wallets', async () => {
    const reg = getWalletRegistry();
    for (let i = 1; i <= 10; i++) {
      await reg.link(SUB, `0x${i.toString(16).padStart(40, '0')}`);
    }
    await expect(
      reg.link(SUB, '0x' + 'ff'.repeat(20)),
    ).rejects.toThrow(WalletRegistryError);
  });

  it('canonicalFor resolves the settlement-attribution wallet', async () => {
    const reg = getWalletRegistry();
    expect(await reg.canonicalFor(SUB)).toBeNull();
    await reg.link(SUB, '0x1111111111111111111111111111111111111111');
    await reg.link(SUB, '0x2222222222222222222222222222222222222222');
    expect(await reg.canonicalFor(SUB)).toBe(
      '0x1111111111111111111111111111111111111111',
    );
  });
});
