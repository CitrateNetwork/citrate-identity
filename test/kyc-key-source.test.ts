import { describe, expect, it } from 'vitest';
import { randomBytes } from 'node:crypto';
import {
  EnvMasterKeySource,
  KmsMasterKeySource,
  resolveMasterKeySource,
  type KmsKeyUnwrapper,
} from '../src/kyc-key-source.js';

/**
 * AV-S7 / HAR-244 master-key custody seam. Proves the resolver picks the env source by
 * default (unchanged behavior), fails CLOSED when `kms` is selected without a backend
 * (never silently falls back to the env key), and drives a wired KMS backend through the
 * seam with a test double. The concrete AWS/GCP backend is WP-2 (not shipped here).
 */

const KEY_B64 = randomBytes(32).toString('base64');

/** A test-only KMS backend (WP-2 ships the real AWS/GCP one). */
function fakeKms(bytes: Buffer): KmsKeyUnwrapper {
  return { keyRef: 'test:kms/key-1', async unwrapMasterKey() { return bytes; } };
}

describe('resolveMasterKeySource (AV-S7)', () => {
  it('defaults to the env source and returns the 32-byte env key (unchanged behavior)', async () => {
    const src = resolveMasterKeySource({ KYC_MASTER_KEY: KEY_B64 } as NodeJS.ProcessEnv);
    expect(src.kind).toBe('env');
    expect(src).toBeInstanceOf(EnvMasterKeySource);
    expect((await src.getMasterKey()).length).toBe(32);
  });

  it('FAILS CLOSED: KYC_MASTER_KEY_SOURCE=kms with no backend wired → throws, no env fallback', () => {
    expect(() => resolveMasterKeySource({ KYC_MASTER_KEY_SOURCE: 'kms', KYC_MASTER_KEY: KEY_B64 } as NodeJS.ProcessEnv))
      .toThrow(/no KMS backend|fail closed/i);
  });

  it('drives a wired KMS backend through the seam (kind=kms, key from the unwrapper)', async () => {
    const bytes = randomBytes(32);
    const src = resolveMasterKeySource({ KYC_MASTER_KEY_SOURCE: 'kms' } as NodeJS.ProcessEnv, { kms: fakeKms(bytes) });
    expect(src.kind).toBe('kms');
    expect(src).toBeInstanceOf(KmsMasterKeySource);
    expect(Buffer.compare(await src.getMasterKey(), bytes)).toBe(0);
  });

  it('KMS source validates key length (a non-32-byte unwrap fails closed)', async () => {
    const src = new KmsMasterKeySource(fakeKms(randomBytes(16)));
    await expect(src.getMasterKey()).rejects.toThrow(/32 bytes/);
  });

  it('rejects an unknown KYC_MASTER_KEY_SOURCE value', () => {
    expect(() => resolveMasterKeySource({ KYC_MASTER_KEY_SOURCE: 'vault' } as NodeJS.ProcessEnv))
      .toThrow(/must be 'env' or 'kms'/);
  });
});
