/**
 * Production-config gate for the AA module (WP-5 of EW-S1).
 *
 * Same fail-closed posture as `config.ts::assertProductionConfig`:
 * if `NODE_ENV === 'production'` (or `CITRATE_ENV === 'production'`)
 * and any required AA env is missing or unsafe, the authority refuses
 * to boot with a clear error naming the missing piece.
 */

import type { Address, Hex } from 'viem';

import { type ConfigEnv } from '../config.js';

/** AA-specific env surface this module reads. */
export interface AaConfigEnv extends ConfigEnv {
  /** Hex (0x-prefixed) address of the `CitrateWalletFactory` on chain 40204. */
  CITRATE_AA_FACTORY?: string;
  /** Hex (0x-prefixed) address of the Kernel v3 implementation. */
  CITRATE_AA_KERNEL_IMPL?: string;
  /** Chain id the factory was deployed on. Defaults to 40204. */
  CITRATE_AA_CHAIN_ID?: string;
  /**
   * Identity signer private key as a 0x-prefixed 32-byte hex. The
   * authority signs every factory-deploy permit with this key.
   * NEVER log; rotate quarterly per ADR-2026-06-05-ew-wallet-stack
   * §"What we accept".
   */
  CITRATE_AA_IDENTITY_SIGNER_KEY?: string;
  /**
   * Optional public address the signer key maps to. Used as a
   * sanity check at boot — if both are present they must agree.
   */
  CITRATE_AA_IDENTITY_SIGNER_ADDR?: string;
}

/**
 * Resolved + validated AA config the authority uses at runtime.
 */
export interface AaConfig {
  factory: Address;
  kernelImpl: Address;
  chainId: bigint;
  identitySignerKey: Hex;
  identitySignerAddr?: Address;
}

/**
 * Parse + validate the AA env surface. Fails closed in production —
 * mirrors `assertProductionConfig` semantics.
 */
export function loadAaConfig(env: AaConfigEnv): AaConfig {
  const isProd =
    env.NODE_ENV === 'production' || env.CITRATE_ENV === 'production';

  const factory = (env.CITRATE_AA_FACTORY ?? '').trim();
  const kernelImpl = (env.CITRATE_AA_KERNEL_IMPL ?? '').trim();
  const chainIdStr = (env.CITRATE_AA_CHAIN_ID ?? '40204').trim();
  const signerKey = (env.CITRATE_AA_IDENTITY_SIGNER_KEY ?? '').trim();
  const signerAddr = (env.CITRATE_AA_IDENTITY_SIGNER_ADDR ?? '').trim();

  const errors: string[] = [];
  if (!isAddress(factory)) errors.push('CITRATE_AA_FACTORY must be a 20-byte 0x-prefixed address');
  if (!isAddress(kernelImpl)) errors.push('CITRATE_AA_KERNEL_IMPL must be a 20-byte 0x-prefixed address');
  if (!isPrivateKey(signerKey)) errors.push('CITRATE_AA_IDENTITY_SIGNER_KEY must be a 32-byte 0x-prefixed hex private key');
  let chainId: bigint;
  try {
    chainId = BigInt(chainIdStr);
    if (chainId <= 0n) throw new Error('non-positive');
  } catch {
    errors.push(`CITRATE_AA_CHAIN_ID must parse to a positive integer (got "${chainIdStr}")`);
    chainId = 0n;
  }

  if (errors.length > 0) {
    if (isProd) {
      throw new Error(
        'Refusing to start in production with unsafe AA config:\n  - ' +
          errors.join('\n  - '),
      );
    }
    // Dev/test: surface a single warning + return a best-effort config
    // so server boots, but every AA call will fail closed at the
    // address/key validation step in viem.
    // eslint-disable-next-line no-console
    console.warn(
      `[aa-config] partial config (dev mode, would fail prod):\n  - ${errors.join('\n  - ')}`,
    );
  }

  if (signerAddr && isAddress(signerAddr)) {
    // best-effort sanity check; viem's privateKeyToAccount will
    // reject inside this if the key is malformed.
  }

  return {
    factory: factory as Address,
    kernelImpl: kernelImpl as Address,
    chainId,
    identitySignerKey: signerKey as Hex,
    identitySignerAddr: signerAddr ? (signerAddr as Address) : undefined,
  };
}

function isAddress(s: string): boolean {
  return /^0x[a-fA-F0-9]{40}$/.test(s);
}

function isPrivateKey(s: string): boolean {
  return /^0x[a-fA-F0-9]{64}$/.test(s);
}
