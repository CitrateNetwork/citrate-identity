/**
 * Explicit canonical-wallet rebinding (`setCanonical`).
 *
 * WHY THIS EXISTS
 *
 * Canonical defaults to FIRST-linked (the ADR rule) so that a restart or a stray
 * second link can never silently move a member's pay-to address. That default is
 * correct and these tests pin it. What it lacked was any deliberate way OUT.
 *
 * Observed live 2026-08-04 (sub a22d6f95): the member's device custody vault was
 * replaced, so the desktop minted a NEW custody EOA and linked it. The claim
 * stayed pinned to the wallet linked on 07-29. The desktop requires
 * `wallet_address == this device's custody address`, so it blocked — with no
 * error anywhere, because the link itself succeeded and the hook it triggers is
 * logged-not-thrown by design.
 *
 * Production was NOT missing the rebind wire (it shipped 07-28 and demonstrably
 * promotes on a first link). The gap was that first-linked is immutable.
 *
 * The safety property under test: rebinding may only ever CHOOSE AMONG wallets
 * already proven for that sub. It can never introduce an address, so the
 * promotion cannot outrun the EIP-191 proof.
 */

import { beforeEach, describe, expect, it } from 'vitest';

import {
  InMemoryWalletRegistry,
  setWalletRegistry,
  getWalletRegistry,
  WalletRegistryError,
} from '../src/identity-registry.js';

const SUB = 'a22d6f95-123c-420e-b917-a190a912d28b';
const OTHER_SUB = '4925a564-ac4d-4bc3-bbb1-68a84dfdefc3';
// The two real addresses from the live incident, lowercased as the store keeps them.
const FIRST = '0x354f337c1c60e58081bb0adca536e7fb636a16c6';
const SECOND = '0xc18485627622aed02c6c721b2c4946daa9cfdb2d';

describe('setCanonical', () => {
  beforeEach(() => {
    setWalletRegistry(new InMemoryWalletRegistry());
  });

  it('defaults to first-linked, and a second link does NOT move it', async () => {
    const r = getWalletRegistry();
    await r.link(SUB, FIRST);
    await r.link(SUB, SECOND);
    expect(await r.canonicalFor(SUB)).toBe(FIRST);
  });

  it('promotes an already-linked wallet when asked explicitly', async () => {
    const r = getWalletRegistry();
    await r.link(SUB, FIRST);
    await r.link(SUB, SECOND);

    await r.setCanonical(SUB, SECOND);

    expect(await r.canonicalFor(SUB)).toBe(SECOND);
  });

  it('refuses a wallet that is not linked to this identity', async () => {
    const r = getWalletRegistry();
    await r.link(SUB, FIRST);
    // SECOND is proven for nobody here — promoting it would let the claim name an
    // address whose ownership was never established.
    await expect(r.setCanonical(SUB, SECOND)).rejects.toBeInstanceOf(WalletRegistryError);
    expect(await r.canonicalFor(SUB)).toBe(FIRST);
  });

  it("refuses another identity's wallet", async () => {
    const r = getWalletRegistry();
    await r.link(SUB, FIRST);
    await r.link(OTHER_SUB, SECOND);
    // Proven — but proven for someone ELSE. This is the theft shape.
    await expect(r.setCanonical(SUB, SECOND)).rejects.toBeInstanceOf(WalletRegistryError);
    expect(await r.canonicalFor(SUB)).toBe(FIRST);
    expect(await r.canonicalFor(OTHER_SUB)).toBe(SECOND);
  });

  it('is case-insensitive on the address, like link()', async () => {
    const r = getWalletRegistry();
    await r.link(SUB, FIRST);
    await r.link(SUB, SECOND);
    await r.setCanonical(SUB, SECOND.toUpperCase().replace('0X', '0x'));
    expect(await r.canonicalFor(SUB)).toBe(SECOND);
  });

  it('is idempotent', async () => {
    const r = getWalletRegistry();
    await r.link(SUB, FIRST);
    await r.link(SUB, SECOND);
    await r.setCanonical(SUB, SECOND);
    await r.setCanonical(SUB, SECOND);
    expect(await r.canonicalFor(SUB)).toBe(SECOND);
  });

  it('can be pointed back at the original first-linked wallet', async () => {
    const r = getWalletRegistry();
    await r.link(SUB, FIRST);
    await r.link(SUB, SECOND);
    await r.setCanonical(SUB, SECOND);
    await r.setCanonical(SUB, FIRST);
    expect(await r.canonicalFor(SUB)).toBe(FIRST);
  });

  it('list() reports the OVERRIDE as canonical, not the first-linked row', async () => {
    // The desktop decides whether the member is blocked from this flag, so a
    // list that still said "first is canonical" would leave them stuck even
    // after a successful rebind.
    const r = getWalletRegistry();
    await r.link(SUB, FIRST);
    await r.link(SUB, SECOND);
    await r.setCanonical(SUB, SECOND);

    const wallets = await r.list(SUB);
    expect(wallets.find((w) => w.address === SECOND)?.canonical).toBe(true);
    expect(wallets.find((w) => w.address === FIRST)?.canonical).toBe(false);
    expect(wallets.filter((w) => w.canonical)).toHaveLength(1);
  });

  it('falls back to first-linked when the chosen wallet is unlinked', async () => {
    // Otherwise canonical would dangle at an address that is no longer proven —
    // the exact "stale pay-to address outliving its link" failure the unlink
    // route already guards against.
    const r = getWalletRegistry();
    await r.link(SUB, FIRST);
    await r.link(SUB, SECOND);
    await r.setCanonical(SUB, SECOND);
    expect(await r.canonicalFor(SUB)).toBe(SECOND);

    await r.unlink(SUB, SECOND);

    expect(await r.canonicalFor(SUB)).toBe(FIRST);
  });

  it('leaves other identities untouched', async () => {
    const r = getWalletRegistry();
    await r.link(SUB, FIRST);
    await r.link(SUB, SECOND);
    const otherWallet = '0xce03882c20beb0193feeba3e81cbcbfcf19f03e3';
    await r.link(OTHER_SUB, otherWallet);

    await r.setCanonical(SUB, SECOND);

    expect(await r.canonicalFor(OTHER_SUB)).toBe(otherWallet);
  });
});
