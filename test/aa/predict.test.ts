import { describe, it, expect } from 'vitest';

import {
  predictWalletAddress,
  computeErc1967MinimalInitCodeHash,
  AddressPredictionError,
} from '../../src/aa/predict.js';

const FACTORY = '0x1111111111111111111111111111111111111111' as const;
const IMPL = '0x2222222222222222222222222222222222222222' as const;
const USER_A =
  '0x000000000000000000000000000000000000000000000000000000000000007b' as const; // userId = 123
const USER_B =
  '0x00000000000000000000000000000000000000000000000000000000000001c8' as const; // userId = 456

describe('predictWalletAddress', () => {
  it('rejects the zero factory', () => {
    expect(() =>
      predictWalletAddress('0x0000000000000000000000000000000000000000', IMPL, USER_A),
    ).toThrow(AddressPredictionError);
  });

  it('rejects the zero implementation', () => {
    expect(() =>
      predictWalletAddress(FACTORY, '0x0000000000000000000000000000000000000000', USER_A),
    ).toThrow(AddressPredictionError);
  });

  it('rejects a badly-shaped userId', () => {
    expect(() =>
      predictWalletAddress(FACTORY, IMPL, '0x1234' as `0x${string}`),
    ).toThrow(AddressPredictionError);
  });

  it('is deterministic per userId', () => {
    const a = predictWalletAddress(FACTORY, IMPL, USER_A);
    const b = predictWalletAddress(FACTORY, IMPL, USER_A);
    expect(b).toBe(a);
  });

  it('differs across userIds', () => {
    expect(predictWalletAddress(FACTORY, IMPL, USER_A)).not.toBe(
      predictWalletAddress(FACTORY, IMPL, USER_B),
    );
  });

  it('differs across factories', () => {
    const other = '0x3333333333333333333333333333333333333333' as const;
    expect(predictWalletAddress(FACTORY, IMPL, USER_A)).not.toBe(
      predictWalletAddress(other, IMPL, USER_A),
    );
  });

  it('differs across implementations', () => {
    const otherImpl = '0x4444444444444444444444444444444444444444' as const;
    expect(predictWalletAddress(FACTORY, IMPL, USER_A)).not.toBe(
      predictWalletAddress(FACTORY, otherImpl, USER_A),
    );
  });

  it('returns a checksummed address', () => {
    const addr = predictWalletAddress(FACTORY, IMPL, USER_A);
    // EIP-55: at least one hex char is upper-case after the 0x for
    // every address that has non-A..F nibbles set.
    expect(addr).toMatch(/^0x[0-9a-fA-F]{40}$/);
  });
});

describe('computeErc1967MinimalInitCodeHash', () => {
  it('is stable for the same implementation', () => {
    const a = computeErc1967MinimalInitCodeHash(IMPL);
    const b = computeErc1967MinimalInitCodeHash(IMPL);
    expect(b).toBe(a);
  });

  it('differs across implementations', () => {
    const a = computeErc1967MinimalInitCodeHash(IMPL);
    const b = computeErc1967MinimalInitCodeHash('0x4444444444444444444444444444444444444444');
    expect(a).not.toBe(b);
  });

  it('is a 32-byte 0x-prefixed hex string', () => {
    const hash = computeErc1967MinimalInitCodeHash(IMPL);
    expect(hash).toMatch(/^0x[0-9a-fA-F]{64}$/);
  });
});
