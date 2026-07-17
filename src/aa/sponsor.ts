/**
 * WS-6 (Wave-2 Track G) — gasless-membership sponsorship signing.
 *
 * The authority holds the CitratePaymaster `sponsorSigner` key and, on
 * request from a trusted machine caller (core-membership), signs the
 * paymaster's sponsorship digest so a member's UserOp can be gas-sponsored.
 *
 * The digest, the EIP-191 envelope, and the recovery target are pinned to
 * `citrate-chain/contracts/src/aa/paymaster/CitratePaymaster.sol`:
 *
 * ```solidity
 * function sponsorDigest(address account, uint8 category,
 *                        uint48 validUntil, uint48 validAfter)
 *   returns (bytes32)
 * { return keccak256(abi.encode(
 *       block.chainid,        // uint256
 *       address(this),        // address paymaster
 *       account,              // address
 *       category,             // uint8
 *       validUntil,           // uint48
 *       validAfter));         // uint48
 * }
 * // verified as: ECDSA.recover(digest.toEthSignedMessageHash(), sig) == sponsorSigner
 * ```
 *
 * REPLAY DEFENSE. The digest does NOT bind the userOpHash or the account
 * nonce, so a signature is reusable for ANY UserOp from `account` in the
 * `category` while the signed `[validAfter, validUntil]` window is open.
 * The defenses are therefore (1) a SHORT bounded window (<= 15 min here)
 * and (2) the paymaster's own per-account caps (`firstOpCap` +
 * `hasUsedFirstOp` for CAT_FIRST_OP; daily WEI caps for standard). We keep
 * the window as tight as the caller allows and never exceed 15 minutes.
 *
 * The signing primitive is the SAME one `permit.ts::signPermit` uses —
 * `account.signMessage({ message: { raw: digest } })` — so the EIP-191
 * envelope matches OpenZeppelin's `MessageHashUtils.toEthSignedMessageHash`
 * byte-for-byte, exactly as the paymaster's `ECDSA.tryRecover` expects.
 */

import {
  encodeAbiParameters,
  keccak256,
  type Address,
  type Hex,
} from 'viem';

import { signPermit } from './permit.js';

/** Sponsorship categories — MUST match CitratePaymaster's CAT_* constants. */
export enum SponsorCategory {
  Standard = 0,
  Recovery = 1,
  FirstOp = 2,
}

/**
 * Hard ceiling on the signed window width, in seconds. The digest does not
 * bind the userOpHash/nonce, so a signature is replayable within its
 * window; a short window bounds that exposure. 15 minutes.
 */
export const MAX_SPONSOR_WINDOW_SECONDS = 900;

/** Minimum window width — below this a legitimate op may not land in time. */
export const MIN_SPONSOR_WINDOW_SECONDS = 60;

/**
 * Default backdate applied to `validAfter` to tolerate clock skew between
 * this signer, the bundler, and the sealing node. The paymaster reverts
 * `SponsorshipExpired` when `block.timestamp < validAfter`, so a small
 * backdate avoids a spurious "not yet valid" rejection. Counts toward the
 * window width (validUntil - validAfter), which stays <= MAX.
 */
export const DEFAULT_CLOCK_SKEW_SECONDS = 30;

export class SponsorSigningError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SponsorSigningError';
  }
}

/** uint48 domain guard — validUntil/validAfter must fit 6 bytes. */
const UINT48_MAX = 2n ** 48n - 1n;

function assertUint48(name: string, v: bigint): void {
  if (v < 0n || v > UINT48_MAX) {
    throw new SponsorSigningError(`${name} must fit in uint48 (got ${v})`);
  }
}

function assertCategory(category: number): void {
  if (
    category !== SponsorCategory.Standard &&
    category !== SponsorCategory.Recovery &&
    category !== SponsorCategory.FirstOp
  ) {
    throw new SponsorSigningError(
      `category must be one of 0 (standard) / 1 (recovery) / 2 (first-op), got ${category}`,
    );
  }
}

/**
 * Compute the `sponsorDigest` the paymaster's `sponsorSigner` signs over.
 * Byte-identical to the on-chain `CitratePaymaster.sponsorDigest`.
 *
 * @param chainId    the chain id (40204 on Citrate testnet)
 * @param paymaster  THIS paymaster's address (domain separation)
 * @param account    the UserOp `sender` (the member smart-wallet address)
 * @param category   0 standard / 1 recovery / 2 first-op
 * @param validUntil uint48 unix-seconds the sponsorship expires (0 = never)
 * @param validAfter uint48 unix-seconds the sponsorship becomes valid
 */
export function sponsorDigest(
  chainId: bigint,
  paymaster: Address,
  account: Address,
  category: number,
  validUntil: bigint,
  validAfter: bigint,
): Hex {
  assertCategory(category);
  assertUint48('validUntil', validUntil);
  assertUint48('validAfter', validAfter);
  const encoded = encodeAbiParameters(
    [
      { type: 'uint256' }, // block.chainid
      { type: 'address' }, // address(this) — paymaster
      { type: 'address' }, // account
      { type: 'uint8' }, // category
      { type: 'uint48' }, // validUntil
      { type: 'uint48' }, // validAfter
    ],
    // viem maps uint48 to `number`; validUntil/validAfter fit uint48
    // (< 2^48 < Number.MAX_SAFE_INTEGER), so Number() is lossless here.
    [chainId, paymaster, account, category, Number(validUntil), Number(validAfter)],
  );
  return keccak256(encoded);
}

export interface SponsorWindow {
  validUntil: bigint;
  validAfter: bigint;
}

/**
 * Compute a bounded `[validAfter, validUntil]` window. Clamps the requested
 * TTL to `[MIN, MAX]` (never exceeds 15 minutes), backdates `validAfter` by
 * `clockSkewSeconds` for skew tolerance, and returns uint48-domain values.
 *
 * @param nowSeconds        current unix seconds (bigint)
 * @param ttlSeconds        requested window width; clamped to [MIN, MAX]
 * @param clockSkewSeconds  backdate applied to validAfter (default 30)
 */
export function computeSponsorWindow(
  nowSeconds: bigint,
  ttlSeconds: number,
  clockSkewSeconds: number = DEFAULT_CLOCK_SKEW_SECONDS,
): SponsorWindow {
  if (!Number.isFinite(ttlSeconds)) {
    throw new SponsorSigningError('ttlSeconds must be a finite number');
  }
  if (!Number.isFinite(clockSkewSeconds) || clockSkewSeconds < 0) {
    throw new SponsorSigningError('clockSkewSeconds must be a non-negative finite number');
  }
  // Clamp TTL into the bounded band. This is the replay-window ceiling.
  const ttl = Math.min(
    MAX_SPONSOR_WINDOW_SECONDS,
    Math.max(MIN_SPONSOR_WINDOW_SECONDS, Math.floor(ttlSeconds)),
  );
  const skew = BigInt(Math.floor(clockSkewSeconds));
  // Backdate validAfter for skew tolerance, but never below 0.
  const validAfter = nowSeconds > skew ? nowSeconds - skew : 0n;
  const validUntil = validAfter + BigInt(ttl);
  // Defense in depth: reject if the effective window ever exceeds the ceiling.
  if (validUntil - validAfter > BigInt(MAX_SPONSOR_WINDOW_SECONDS)) {
    throw new SponsorSigningError(
      `computed window ${validUntil - validAfter}s exceeds ceiling ${MAX_SPONSOR_WINDOW_SECONDS}s`,
    );
  }
  assertUint48('validUntil', validUntil);
  assertUint48('validAfter', validAfter);
  return { validUntil, validAfter };
}

export interface BuildSponsorshipArgs {
  chainId: bigint;
  paymaster: Address;
  account: Address;
  category: number;
  validUntil: bigint;
  validAfter: bigint;
  /** The paymaster sponsor-signer key (0x 32-byte hex). NEVER logged. */
  sponsorSignerHex: Hex;
}

export interface Sponsorship {
  digest: Hex;
  /** 65-byte r||s||v EIP-191 signature to pack into paymasterAndData. */
  signature: Hex;
  category: number;
  validUntil: bigint;
  validAfter: bigint;
}

/**
 * Compute the sponsor digest and sign it with the paymaster sponsor-signer
 * key, reusing `signPermit`'s exact EIP-191 primitive. Returns the digest
 * (for client verification / debug) and the 65-byte signature.
 */
export async function buildSponsorship(
  args: BuildSponsorshipArgs,
): Promise<Sponsorship> {
  const digest = sponsorDigest(
    args.chainId,
    args.paymaster,
    args.account,
    args.category,
    args.validUntil,
    args.validAfter,
  );
  // Same primitive as permit signing: account.signMessage({message:{raw}}).
  const signature = await signPermit(args.sponsorSignerHex, digest);
  return {
    digest,
    signature,
    category: args.category,
    validUntil: args.validUntil,
    validAfter: args.validAfter,
  };
}
