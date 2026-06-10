/**
 * Sign the deploy permit the `CitrateWalletFactory` verifies before
 * deploying a smart wallet for a user (WP-5 of EW-S1).
 *
 * Counterpart to `citrate-chain/wallet-aa/src/permit.rs`. The digest
 * computation here MUST produce the same 32-byte hash as the Rust
 * crate and the on-chain `CitrateWalletFactory.permitDigest`.
 *
 * The operator key signing the permit lives in the
 * `auth.citrate.ai` droplet's `.env` per the
 * `ADR-2026-06-05-ew-wallet-stack` §"What we accept" call-out — same
 * posture as the gateway + KYC webhook secrets.
 */

import {
  encodeAbiParameters,
  hashMessage,
  keccak256,
  toHex,
  type Address,
  type Hex,
} from 'viem';
import { privateKeyToAccount, type PrivateKeyAccount } from 'viem/accounts';

export class PermitSigningError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PermitSigningError';
  }
}

/**
 * Compute the permit digest the factory's `identitySigner` signs over.
 * Matches:
 *
 * ```solidity
 * keccak256(abi.encode(
 *   address(factory),
 *   block.chainid,
 *   userId,                 // bytes32
 *   keccak256(initData),
 *   expiresAt               // uint256
 * ))
 * ```
 *
 * @param factory     the CitrateWalletFactory address
 * @param chainId     the chain id (40204 on Citrate testnet)
 * @param userId      32-byte (0x-prefixed) hex string
 * @param initData    raw init-data bytes (the calldata the factory will
 *                    delegatecall into the proxy)
 * @param expiresAt   Unix-seconds expiry the factory rejects past
 */
export function permitDigest(
  factory: Address,
  chainId: bigint,
  userId: Hex,
  initData: Hex,
  expiresAt: bigint,
): Hex {
  if (!userId.startsWith('0x') || userId.length !== 66) {
    throw new PermitSigningError(
      `userId must be a 0x-prefixed 32-byte hex string (got length ${userId.length})`,
    );
  }
  const initDataHash = keccak256(initData);
  const encoded = encodeAbiParameters(
    [
      { type: 'address' },
      { type: 'uint256' },
      { type: 'bytes32' },
      { type: 'bytes32' },
      { type: 'uint256' },
    ],
    [factory, chainId, userId, initDataHash, expiresAt],
  );
  return keccak256(encoded);
}

/**
 * Sign a permit digest with the identity-signer key. Produces a
 * standard EIP-191 ("personal_sign") wrapped 65-byte secp256k1
 * signature `(r, s, v)` — exactly what OpenZeppelin's `ECDSA.recover`
 * verifies on chain, and what the Rust `sign_permit` produces.
 *
 * @param identitySignerHex  the operator key as a 0x-prefixed
 *                           32-byte hex string
 * @param digest             the permit digest from `permitDigest`
 * @returns 65-byte signature as a 0x-prefixed hex string
 */
export async function signPermit(
  identitySignerHex: Hex,
  digest: Hex,
): Promise<Hex> {
  const account: PrivateKeyAccount = privateKeyToAccount(identitySignerHex);
  // viem's signMessage with `raw: <bytes>` wraps in EIP-191 internally
  // exactly the way OpenZeppelin's `toEthSignedMessageHash` does. We
  // pass the digest as raw bytes (not a string) so the prefix is
  // applied to the 32-byte hash, not to a hex representation of it.
  const sig = await account.signMessage({
    message: { raw: digest },
  });
  return sig;
}

/**
 * Build a one-shot permit: compute the digest, sign it, return both
 * for downstream embedding in the HTTP response. The caller does not
 * need to know the digest format — it's there for debug + client
 * verification only.
 */
export async function buildPermit(args: {
  factory: Address;
  chainId: bigint;
  userId: Hex;
  initData: Hex;
  expiresAt: bigint;
  identitySignerHex: Hex;
}): Promise<{ digest: Hex; signature: Hex }> {
  const digest = permitDigest(
    args.factory,
    args.chainId,
    args.userId,
    args.initData,
    args.expiresAt,
  );
  const signature = await signPermit(args.identitySignerHex, digest);
  return { digest, signature };
}

/**
 * EIP-191 envelope helper. Exposed for tests and clients that want to
 * verify a permit signature offline.
 */
export function ethSignedMessageHash(digest: Hex): Hex {
  return hashMessage({ raw: digest });
}

/** toHex wrapper for consistency with the Rust crate's docs. */
export const u64Hex = (n: bigint): Hex => toHex(n);
