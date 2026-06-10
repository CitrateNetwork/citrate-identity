import { describe, it, expect } from 'vitest';
import { recoverMessageAddress } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';

import {
  permitDigest,
  signPermit,
  buildPermit,
  ethSignedMessageHash,
} from '../../src/aa/permit.js';

const FACTORY = '0x1111111111111111111111111111111111111111' as const;
const CHAIN_ID = 40204n;
const USER_ID =
  '0x000000000000000000000000000000000000000000000000000000000000007b' as const;
const INIT_DATA = '0xdeadbeef' as const;
// Deterministic test key. Not used in production.
const SIGNER_KEY =
  '0x59c699dc09c5f1216c2d5a728dfb95d5dc2b67d5d6d34e7651cf0f0c8a30c1d2' as const;

describe('permitDigest', () => {
  it('is deterministic for fixed inputs', () => {
    const a = permitDigest(FACTORY, CHAIN_ID, USER_ID, INIT_DATA, 1_700_000_000n);
    const b = permitDigest(FACTORY, CHAIN_ID, USER_ID, INIT_DATA, 1_700_000_000n);
    expect(b).toBe(a);
  });

  it('changes with each input parameter', () => {
    const base = permitDigest(FACTORY, CHAIN_ID, USER_ID, INIT_DATA, 1n);
    expect(base).not.toBe(
      permitDigest('0x1111111111111111111111111111111111111112', CHAIN_ID, USER_ID, INIT_DATA, 1n),
    );
    expect(base).not.toBe(permitDigest(FACTORY, CHAIN_ID + 1n, USER_ID, INIT_DATA, 1n));
    expect(base).not.toBe(
      permitDigest(
        FACTORY,
        CHAIN_ID,
        '0x000000000000000000000000000000000000000000000000000000000000007c',
        INIT_DATA,
        1n,
      ),
    );
    expect(base).not.toBe(permitDigest(FACTORY, CHAIN_ID, USER_ID, '0xff', 1n));
    expect(base).not.toBe(permitDigest(FACTORY, CHAIN_ID, USER_ID, INIT_DATA, 2n));
  });

  it('rejects a wrongly-sized userId', () => {
    expect(() =>
      permitDigest(FACTORY, CHAIN_ID, '0x1234' as `0x${string}`, INIT_DATA, 1n),
    ).toThrow(/userId/);
  });
});

describe('signPermit / buildPermit', () => {
  it('signPermit produces a 65-byte signature with valid v', async () => {
    const digest = permitDigest(FACTORY, CHAIN_ID, USER_ID, INIT_DATA, 1_700_000_000n);
    const sig = await signPermit(SIGNER_KEY, digest);
    expect(sig).toMatch(/^0x[0-9a-fA-F]{130}$/);
    const v = parseInt(sig.slice(-2), 16);
    expect(v === 27 || v === 28).toBe(true);
  });

  it('signature recovers to the signer address (EIP-191 envelope)', async () => {
    const digest = permitDigest(FACTORY, CHAIN_ID, USER_ID, INIT_DATA, 1_700_000_000n);
    const sig = await signPermit(SIGNER_KEY, digest);

    const signer = privateKeyToAccount(SIGNER_KEY);
    const recovered = await recoverMessageAddress({
      message: { raw: digest },
      signature: sig,
    });
    expect(recovered.toLowerCase()).toBe(signer.address.toLowerCase());
  });

  it('buildPermit returns matching digest + signature', async () => {
    const { digest, signature } = await buildPermit({
      factory: FACTORY,
      chainId: CHAIN_ID,
      userId: USER_ID,
      initData: INIT_DATA,
      expiresAt: 1_700_000_000n,
      identitySignerHex: SIGNER_KEY,
    });
    expect(digest).toBe(permitDigest(FACTORY, CHAIN_ID, USER_ID, INIT_DATA, 1_700_000_000n));
    const signer = privateKeyToAccount(SIGNER_KEY);
    const recovered = await recoverMessageAddress({
      message: { raw: digest },
      signature,
    });
    expect(recovered.toLowerCase()).toBe(signer.address.toLowerCase());
  });
});

describe('ethSignedMessageHash', () => {
  it('is deterministic and distinct from the raw digest', () => {
    const digest = permitDigest(FACTORY, CHAIN_ID, USER_ID, INIT_DATA, 1n);
    const eth1 = ethSignedMessageHash(digest);
    const eth2 = ethSignedMessageHash(digest);
    expect(eth1).toBe(eth2);
    expect(eth1).not.toBe(digest);
  });
});
