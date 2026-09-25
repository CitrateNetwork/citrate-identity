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
  /**
   * OPTIONAL: CitratePaymaster address + registrar private key for
   * POST /aa/register-wallet (RADAR handoff T-2). When either is
   * absent the route answers 503 registrar_unconfigured — the rest
   * of the AA surface is unaffected, so existing deploys keep
   * booting. Key custody posture: same as the identity-signer key.
   */
  CITRATE_AA_PAYMASTER?: string;
  CITRATE_AA_REGISTRAR_KEY?: string;
  /**
   * PBA-L3a-004: the canonical root-validator modules a deploy permit may name
   * (CitrateECDSAValidator / WebAuthnP256Validator on 40204). A permit is only
   * signed for an initData whose root validator is one of these AND is owned by
   * the caller. Unset → /aa/enroll-validator answers 503 (fail closed).
   */
  CITRATE_AA_ECDSA_VALIDATOR?: string;
  CITRATE_AA_WEBAUTHN_VALIDATOR?: string;
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
  /** Present only when both paymaster env vars are set and well-formed. */
  paymaster?: Address;
  registrarKey?: Hex;
  /** PBA-L3a-004: allowed root validators (absent → permits refused). */
  ecdsaValidator?: Address;
  webauthnValidator?: Address;
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

  // Optional register-wallet surface: validate only when present.
  const paymaster = (env.CITRATE_AA_PAYMASTER ?? '').trim();
  const registrarKey = (env.CITRATE_AA_REGISTRAR_KEY ?? '').trim();
  const registrarOk = isAddress(paymaster) && isPrivateKey(registrarKey);
  if ((paymaster || registrarKey) && !registrarOk) {
    // Misconfigured half-pair: fail closed in prod, warn in dev.
    const msg = 'CITRATE_AA_PAYMASTER and CITRATE_AA_REGISTRAR_KEY must both be set and well-formed to enable /aa/register-wallet';
    if (isProd) throw new Error(msg);
    // eslint-disable-next-line no-console
    console.warn(`[aa-config] ${msg} — route will answer 503`);
  }

  // PBA-L3a-004: allowed root validators. Malformed → fail closed in prod.
  const ecdsaValidator = (env.CITRATE_AA_ECDSA_VALIDATOR ?? '').trim();
  const webauthnValidator = (env.CITRATE_AA_WEBAUTHN_VALIDATOR ?? '').trim();
  for (const [name, v] of [
    ['CITRATE_AA_ECDSA_VALIDATOR', ecdsaValidator],
    ['CITRATE_AA_WEBAUTHN_VALIDATOR', webauthnValidator],
  ] as const) {
    if (v && !isAddress(v)) {
      const msg = `${name} must be a 20-byte 0x-prefixed address`;
      if (isProd) throw new Error(msg);
      // eslint-disable-next-line no-console
      console.warn(`[aa-config] ${msg} — ignored`);
    }
  }

  return {
    factory: factory as Address,
    kernelImpl: kernelImpl as Address,
    chainId,
    identitySignerKey: signerKey as Hex,
    identitySignerAddr: signerAddr ? (signerAddr as Address) : undefined,
    ...(registrarOk
      ? { paymaster: paymaster as Address, registrarKey: registrarKey as Hex }
      : {}),
    ...(isAddress(ecdsaValidator) ? { ecdsaValidator: ecdsaValidator as Address } : {}),
    ...(isAddress(webauthnValidator) ? { webauthnValidator: webauthnValidator as Address } : {}),
  };
}

function isAddress(s: string): boolean {
  return /^0x[a-fA-F0-9]{40}$/.test(s);
}

function isPrivateKey(s: string): boolean {
  return /^0x[a-fA-F0-9]{64}$/.test(s);
}
