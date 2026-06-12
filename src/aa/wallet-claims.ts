/**
 * Wallet-claims seam (EW-S1 WP-6, Lane C 2026-06-11).
 *
 * Every Citrate identity — UUID-keyed (passkey / email-pw / Google) or
 * SIWE EOA-keyed — has exactly one smart-wallet address, derivable
 * offline. This module owns:
 *
 *   1. The UUID → 32-byte AA userId mapping:
 *      `userId = keccak256(utf8(lowercase uuid))`. The factory then
 *      salts CREATE2 with `keccak256(userId)` (see
 *      CitrateWalletFactory.predictAddress + src/aa/predict.ts). The
 *      SDK (citrate-sdk-js) and the Rust `wallet-aa` crate MUST
 *      reproduce this byte-for-byte — it is the cross-surface seam
 *      `ADR-2026-06-05-ew-surface-interop` pins ("one wallet address
 *      per user, derived from the Citrate user id").
 *
 *   2. The process-wide wallet-claims config (factory + kernel impl)
 *      `server.ts` installs at boot when the `CITRATE_AA_*` env is
 *      present, so `findAccount` can populate the `wallet_address`
 *      claim for UUID-keyed users without threading config through
 *      panva. When unset (dev without AA env) the claim is simply
 *      omitted — same fail-soft posture as before this change.
 */

import type { Address, Hex } from 'viem';
import { keccak256, stringToBytes } from 'viem';

import { predictWalletAddress } from './predict.js';

/** Canonical lowercase UUID (the shape `users.id` takes). */
const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/**
 * Map a Citrate user UUID to the 32-byte AA userId the wallet factory
 * is salted with: `keccak256(utf8(lowercase uuid))`.
 *
 * Case-normalized so that no matter how a caller round-trips the UUID
 * (Postgres `uuid` columns render lowercase; some HTTP clients
 * uppercase), one human maps to one wallet.
 */
export function uuidToUserId(uuid: string): Hex {
  const canonical = uuid.trim().toLowerCase();
  if (!UUID_RE.test(canonical)) {
    throw new Error(`not a canonical UUID: ${uuid}`);
  }
  return keccak256(stringToBytes(canonical));
}

/**
 * Resolve any OIDC accountId shape to the 32-byte AA userId:
 *
 *   - 32-byte 0x-hex            → unchanged (already an AA userId)
 *   - 20-byte 0x-address (SIWE) → left-zero-padded to 32 bytes (the
 *     degenerate form /aa/enroll-validator has always accepted)
 *   - UUID (passkey/email/google users) → {@link uuidToUserId}
 *   - anything else             → null
 */
export function accountIdToAaUserId(accountId: string): Hex | null {
  if (typeof accountId !== 'string') return null;
  if (accountId.startsWith('0x') && accountId.length === 66) {
    return accountId as Hex;
  }
  if (accountId.startsWith('0x') && accountId.length === 42) {
    return ('0x' + accountId.slice(2).padStart(64, '0')) as Hex;
  }
  if (UUID_RE.test(accountId.trim().toLowerCase())) {
    return uuidToUserId(accountId);
  }
  return null;
}

/** What the claims layer needs to predict a smart-wallet address. */
export interface WalletClaimsConfig {
  factory: Address;
  kernelImpl: Address;
}

let walletClaimsConfig: WalletClaimsConfig | undefined;

/**
 * Install (or clear, with `undefined`) the wallet-claims config.
 * Called once at boot by `server.ts` when the AA env is configured;
 * tests use it to exercise both postures.
 */
export function setWalletClaimsConfig(cfg: WalletClaimsConfig | undefined): void {
  walletClaimsConfig = cfg;
}

/** The currently installed wallet-claims config, if any. */
export function getWalletClaimsConfig(): WalletClaimsConfig | undefined {
  return walletClaimsConfig;
}

/**
 * The predicted CREATE2 smart-wallet address for an OIDC accountId, or
 * `undefined` when the wallet-claims config is not installed or the
 * accountId has no AA userId form.
 */
export function predictedWalletForAccount(accountId: string): Address | undefined {
  if (!walletClaimsConfig) return undefined;
  const userId = accountIdToAaUserId(accountId);
  if (!userId) return undefined;
  return predictWalletAddress(
    walletClaimsConfig.factory,
    walletClaimsConfig.kernelImpl,
    userId,
  );
}
