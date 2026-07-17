/**
 * VERI master-key custody seam (AV-S7 / HAR-244).
 *
 * Today the KYC master key is a plaintext env var (`masterKeyFromEnv`, `kyc-crypto.ts`).
 * ADR-AV-4 moves it to a KMS/HSM so the server never sources the key from its own env.
 * This module is the provider-agnostic seam that makes that swap a wiring change, not a
 * rewrite: callers depend on `MasterKeySource`, and the concrete backend (AWS KMS, GCP
 * KMS, cloud HSM) implements `KmsKeyUnwrapper`.
 *
 * SCOPE (AV-S7 WP-1): the interface + the env source (unchanged behavior) + a fail-closed
 * resolver + the prod gate. No concrete KMS backend ships here, and this seam is NOT yet
 * wired into the live decrypt path (that is WP-2, gated on a real backend + staging
 * verification) — so selecting `kms` without a backend fails closed rather than silently
 * falling back to the env key.
 */

import { KycCryptoError, masterKeyFromEnv } from './kyc-crypto.js';

/** A concrete KMS/HSM backend implements this (AWS/GCP/HSM). WP-2 supplies one. */
export interface KmsKeyUnwrapper {
  /** Return the 32-byte AES master key, unwrapped inside the KMS/HSM trust boundary. */
  unwrapMasterKey(): Promise<Buffer>;
  /** For logging/audit: which KMS + key this resolves (never the key material). */
  readonly keyRef: string;
}

export interface MasterKeySource {
  readonly kind: 'env' | 'kms';
  getMasterKey(): Promise<Buffer>;
}

/** The current behavior: 32-byte key from `KYC_MASTER_KEY`. Unchanged (WP scope). */
export class EnvMasterKeySource implements MasterKeySource {
  readonly kind = 'env' as const;
  constructor(private readonly env: NodeJS.ProcessEnv = process.env) {}
  async getMasterKey(): Promise<Buffer> {
    return masterKeyFromEnv(this.env); // throws fail-closed if unset / wrong length
  }
}

/** The KMS-backed source: unwraps the master key inside the KMS/HSM boundary. */
export class KmsMasterKeySource implements MasterKeySource {
  readonly kind = 'kms' as const;
  constructor(private readonly kms: KmsKeyUnwrapper) {}
  async getMasterKey(): Promise<Buffer> {
    const key = await this.kms.unwrapMasterKey();
    if (key.length !== 32) {
      throw new KycCryptoError(
        `KMS master key (${this.kms.keyRef}) must be exactly 32 bytes (256-bit AES); got ${key.length}.`,
      );
    }
    return key;
  }
}

/**
 * Resolve the master-key source from config. `KYC_MASTER_KEY_SOURCE` selects it
 * (default `env`); `kms` requires a wired backend (`opts.kms`) or it FAILS CLOSED — it
 * never silently falls back to the env key.
 */
export function resolveMasterKeySource(
  env: NodeJS.ProcessEnv = process.env,
  opts: { kms?: KmsKeyUnwrapper } = {},
): MasterKeySource {
  const source = (env.KYC_MASTER_KEY_SOURCE ?? 'env').trim().toLowerCase();
  if (source === 'kms') {
    if (!opts.kms) {
      throw new KycCryptoError(
        'KYC_MASTER_KEY_SOURCE=kms but no KMS backend is wired (AV-S7 WP-2 not yet ' +
          'deployed). Refusing to fall back to the plaintext env key — fail closed.',
      );
    }
    return new KmsMasterKeySource(opts.kms);
  }
  if (source === 'env') return new EnvMasterKeySource(env);
  throw new KycCryptoError(`KYC_MASTER_KEY_SOURCE must be 'env' or 'kms'; got '${source}'.`);
}
