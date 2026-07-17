import { describe, it, expect } from 'vitest';
import { keccak256, recoverMessageAddress, type Hex } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';

import {
  sponsorDigest,
  computeSponsorWindow,
  buildSponsorship,
  SponsorCategory,
  MAX_SPONSOR_WINDOW_SECONDS,
  MIN_SPONSOR_WINDOW_SECONDS,
  SponsorSigningError,
} from '../../src/aa/sponsor.js';

// FROZEN WS-3 paymaster the reroll will deploy.
const PAYMASTER = '0xF14F56e812cE93544e75E841Ac6316F2d7E561b0' as const;
const CHAIN_ID = 40204n;
const ACCOUNT = '0x00000000000000000000000000000000000000ab' as const;
// Deterministic test key. Not used in production.
const SPONSOR_KEY =
  '0x59c699dc09c5f1216c2d5a728dfb95d5dc2b67d5d6d34e7651cf0f0c8a30c1d2' as const;

/**
 * Independent, hand-rolled ABI encoding of the paymaster's sponsorDigest
 * pre-image: keccak256(abi.encode(uint256, address, address, uint8, uint48,
 * uint48)). Each field is a 32-byte big-endian word (address left-padded to
 * 20 bytes within the low 20 bytes of the word; small ints right-aligned).
 */
function handEncodedDigest(
  chainId: bigint,
  paymaster: string,
  account: string,
  category: number,
  validUntil: bigint,
  validAfter: bigint,
): Hex {
  const word = (hex: string) => hex.replace(/^0x/, '').toLowerCase().padStart(64, '0');
  const addrWord = (addr: string) => word(addr); // 20 bytes → padded left to 32
  const preimage =
    '0x' +
    word(chainId.toString(16)) +
    addrWord(paymaster) +
    addrWord(account) +
    word(category.toString(16)) +
    word(validUntil.toString(16)) +
    word(validAfter.toString(16));
  // 6 words = 192 bytes = 384 hex chars + 2 for 0x
  if (preimage.length !== 2 + 6 * 64) {
    throw new Error(`bad preimage length ${preimage.length}`);
  }
  return keccak256(preimage as Hex);
}

describe('sponsorDigest', () => {
  it('matches an independent hand-encoded ABI vector', () => {
    const validUntil = 1_800_000_900n;
    const validAfter = 1_800_000_000n;
    const got = sponsorDigest(
      CHAIN_ID,
      PAYMASTER,
      ACCOUNT,
      SponsorCategory.FirstOp,
      validUntil,
      validAfter,
    );
    const expected = handEncodedDigest(
      CHAIN_ID,
      PAYMASTER,
      ACCOUNT,
      SponsorCategory.FirstOp,
      validUntil,
      validAfter,
    );
    expect(got).toBe(expected);
  });

  it('is deterministic for fixed inputs', () => {
    const a = sponsorDigest(CHAIN_ID, PAYMASTER, ACCOUNT, 2, 1000n, 100n);
    const b = sponsorDigest(CHAIN_ID, PAYMASTER, ACCOUNT, 2, 1000n, 100n);
    expect(b).toBe(a);
  });

  it('changes with every bound field (chain, paymaster, account, category, window)', () => {
    const base = sponsorDigest(CHAIN_ID, PAYMASTER, ACCOUNT, 2, 1000n, 100n);
    expect(base).not.toBe(sponsorDigest(CHAIN_ID + 1n, PAYMASTER, ACCOUNT, 2, 1000n, 100n));
    expect(base).not.toBe(
      sponsorDigest(CHAIN_ID, '0x0000000000000000000000000000000000000001', ACCOUNT, 2, 1000n, 100n),
    );
    expect(base).not.toBe(
      sponsorDigest(CHAIN_ID, PAYMASTER, '0x0000000000000000000000000000000000000002', 2, 1000n, 100n),
    );
    // category 1 vs 2 — a standard grant must not be spendable as first-op.
    expect(base).not.toBe(sponsorDigest(CHAIN_ID, PAYMASTER, ACCOUNT, 1, 1000n, 100n));
    expect(base).not.toBe(sponsorDigest(CHAIN_ID, PAYMASTER, ACCOUNT, 2, 1001n, 100n));
    expect(base).not.toBe(sponsorDigest(CHAIN_ID, PAYMASTER, ACCOUNT, 2, 1000n, 101n));
  });

  it('rejects an out-of-domain category', () => {
    expect(() => sponsorDigest(CHAIN_ID, PAYMASTER, ACCOUNT, 3, 1000n, 100n)).toThrow(
      SponsorSigningError,
    );
  });

  it('rejects a uint48 overflow on the window', () => {
    const tooBig = 2n ** 48n;
    expect(() => sponsorDigest(CHAIN_ID, PAYMASTER, ACCOUNT, 2, tooBig, 100n)).toThrow(/uint48/);
  });
});

describe('computeSponsorWindow', () => {
  const now = 1_800_000_000n;

  it('clamps an over-long TTL to the 15-minute ceiling', () => {
    const w = computeSponsorWindow(now, 3600); // 1h requested
    const width = w.validUntil - w.validAfter;
    expect(width).toBe(BigInt(MAX_SPONSOR_WINDOW_SECONDS));
    expect(width <= 900n).toBe(true);
  });

  it('clamps a too-short TTL up to the floor', () => {
    const w = computeSponsorWindow(now, 1);
    const width = w.validUntil - w.validAfter;
    expect(width).toBe(BigInt(MIN_SPONSOR_WINDOW_SECONDS));
  });

  it('backdates validAfter by the clock-skew allowance', () => {
    const w = computeSponsorWindow(now, 300, 30);
    expect(w.validAfter).toBe(now - 30n);
    expect(w.validUntil).toBe(now - 30n + 300n);
  });

  it('never emits a window wider than 15 minutes for any requested TTL', () => {
    for (const ttl of [0, 30, 60, 300, 900, 901, 100000]) {
      const w = computeSponsorWindow(now, ttl);
      expect(w.validUntil - w.validAfter <= 900n).toBe(true);
    }
  });

  it('rejects a non-finite TTL', () => {
    expect(() => computeSponsorWindow(now, Number.NaN)).toThrow(SponsorSigningError);
  });
});

describe('buildSponsorship', () => {
  it('produces a 65-byte signature that recovers to the sponsor signer', async () => {
    const w = computeSponsorWindow(1_800_000_000n, 600);
    const s = await buildSponsorship({
      chainId: CHAIN_ID,
      paymaster: PAYMASTER,
      account: ACCOUNT,
      category: SponsorCategory.FirstOp,
      validUntil: w.validUntil,
      validAfter: w.validAfter,
      sponsorSignerHex: SPONSOR_KEY,
    });
    expect(s.signature).toMatch(/^0x[0-9a-fA-F]{130}$/);
    const v = parseInt(s.signature.slice(-2), 16);
    expect(v === 27 || v === 28).toBe(true);

    // EIP-191 envelope over the raw digest — same primitive the paymaster's
    // ECDSA.tryRecover(digest.toEthSignedMessageHash(), sig) verifies.
    const signer = privateKeyToAccount(SPONSOR_KEY);
    const recovered = await recoverMessageAddress({
      message: { raw: s.digest },
      signature: s.signature,
    });
    expect(recovered.toLowerCase()).toBe(signer.address.toLowerCase());
  });

  it('digest returned equals sponsorDigest of the same inputs', async () => {
    const s = await buildSponsorship({
      chainId: CHAIN_ID,
      paymaster: PAYMASTER,
      account: ACCOUNT,
      category: SponsorCategory.FirstOp,
      validUntil: 1_800_000_600n,
      validAfter: 1_800_000_000n,
      sponsorSignerHex: SPONSOR_KEY,
    });
    expect(s.digest).toBe(
      sponsorDigest(CHAIN_ID, PAYMASTER, ACCOUNT, 2, 1_800_000_600n, 1_800_000_000n),
    );
  });
});
