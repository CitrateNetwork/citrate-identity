/**
 * Off-chain prediction of the Citrate smart-wallet address for a
 * given Citrate user id (WP-5 of EW-S1).
 *
 * Mirrors Solady's `LibClone::predictDeterministicAddressERC1967`
 * byte-for-byte — the same function the on-chain
 * `CitrateWalletFactory.predictAddress` uses. The Rust counterpart
 * lives at `citrate-chain/wallet-aa/src/address.rs`; both must produce
 * identical addresses for any (factory, implementation, userId)
 * triple.
 *
 * Implementation strategy: build the 95-byte ERC-1967 minimal proxy
 * init code with the implementation embedded, hash it, then CREATE2.
 */

import {
  getAddress,
  keccak256,
  encodePacked,
  type Hex,
  type Address,
} from 'viem';

/** Errors thrown by address-prediction helpers. */
export class AddressPredictionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AddressPredictionError';
  }
}

/**
 * Compute the deterministic CREATE2 address the
 * `CitrateWalletFactory` will deploy a Kernel proxy to, for the given
 * Citrate user id.
 *
 * @param factory         the CitrateWalletFactory address
 * @param implementation  the Kernel v3 implementation address
 * @param userId          a 32-byte (0x-prefixed) hex string the
 *                        factory uses as `salt = keccak256(userId)`
 */
export function predictWalletAddress(
  factory: Address,
  implementation: Address,
  userId: Hex,
): Address {
  if (factory === '0x0000000000000000000000000000000000000000') {
    throw new AddressPredictionError('factory cannot be the zero address');
  }
  if (implementation === '0x0000000000000000000000000000000000000000') {
    throw new AddressPredictionError(
      'implementation cannot be the zero address',
    );
  }
  if (!userId.startsWith('0x') || userId.length !== 66) {
    throw new AddressPredictionError(
      `userId must be a 0x-prefixed 32-byte hex string (got length ${userId.length})`,
    );
  }

  const salt = keccak256(userId);
  const initCodeHash = computeErc1967MinimalInitCodeHash(implementation);

  // CREATE2: address = keccak256(0xff || factory || salt || initCodeHash)[12..32]
  const packed = encodePacked(
    ['bytes1', 'address', 'bytes32', 'bytes32'],
    ['0xff', factory, salt, initCodeHash],
  );
  const hash = keccak256(packed);
  // Take the last 20 bytes of the 32-byte hash.
  // hash is 0x + 64 hex chars; last 40 = bytes 12..32.
  const addr = `0x${hash.slice(-40)}` as Address;
  return getAddress(addr);
}

/**
 * `keccak256(initCode)` for Solady's minimal ERC-1967 clone with the
 * given implementation embedded at bytes 9..29 of the layout. Layout
 * (95 bytes total, pinned to the upstream library's `mstore` constants):
 *
 *   0..9   prefix       0x603d3d8160223d3973
 *   9..29  impl address (20 bytes)
 *   29..31 separator    0x6009
 *   31..63 body         0x5155f3363d3d373d3d363d7f360894a13ba1a3210667c828492db98dca3e2076
 *   63..95 tail         0xcc3735a920a3ca505d382bbc545af43d6000803e6038573d6000fd5b3d6000f3
 */
export function computeErc1967MinimalInitCodeHash(
  implementation: Address,
): Hex {
  const prefix = '603d3d8160223d3973';
  const impl = implementation.slice(2).toLowerCase();
  if (impl.length !== 40) {
    throw new AddressPredictionError(
      `implementation address must be 20 bytes (got ${impl.length / 2})`,
    );
  }
  const separator = '6009';
  const body =
    '5155f3363d3d373d3d363d7f360894a13ba1a3210667c828492db98dca3e2076';
  const tail =
    'cc3735a920a3ca505d382bbc545af43d6000803e6038573d6000fd5b3d6000f3';

  const initCodeHex = `0x${prefix}${impl}${separator}${body}${tail}` as Hex;
  // Sanity: 95 bytes = 190 hex chars + 2 for the 0x prefix.
  if (initCodeHex.length !== 2 + 95 * 2) {
    throw new AddressPredictionError(
      `init code length mismatch: ${initCodeHex.length} chars (expected ${2 + 95 * 2})`,
    );
  }
  return keccak256(initCodeHex);
}
