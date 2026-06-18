/**
 * EW-S1 WP-6 — wallet claims for ALL account shapes (the Lane-C seam).
 *
 * The ID token must carry `wallet_address` + `signing_method` for every
 * signed-in user, not just SIWE (wallet-keyed) accounts:
 *
 *   - UUID-keyed users (passkey / email-pw / Google) get the predicted
 *     CREATE2 smart-wallet address. The 32-byte AA userId for a UUID
 *     account is `keccak256(utf8(uuid))` — the deterministic mapping the
 *     SDK + wallet-aa must reproduce; the factory then salts with
 *     `keccak256(userId)` exactly as for any other 32-byte userId.
 *   - SIWE EOA accounts keep `wallet_address = <EOA>` (the wallet IS the
 *     identity) and gain `signing_method: "siwe"`.
 *   - `signing_method` for UUID users is the method of the most recent
 *     successful sign-in, persisted on the user record by the auth
 *     routes (`email-pw` | `passkey` | `google`). Per-session method
 *     remains the standard `amr` claim.
 *
 * Red-test-first per the SECREM WP protocol: these tests were authored
 * before the implementation and MUST fail on the pre-change tree.
 */

import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { keccak256, stringToBytes, getAddress, type Address } from 'viem';

import {
  uuidToUserId,
  accountIdToAaUserId,
  setWalletClaimsConfig,
  predictedWalletForAccount,
} from '../src/aa/wallet-claims.js';
import { predictWalletAddress } from '../src/aa/predict.js';
import { findAccount } from '../src/config.js';
import {
  InMemoryUserStore,
  setUserStore,
  getUserStore,
} from '../src/auth/stores.js';
import { InMemoryKycStore, setKycStore } from '../src/kyc.js';

const FACTORY = '0xd951Cb15495cb6541F7541b9194B2D311E12FD57' as Address;
const KERNEL_IMPL = '0x99b370120E7F0A4EA4F85cfcb86D4B8d41C3239b' as Address;

const UUID = '0d1f02f1-1f5a-4f5e-9c2e-7b8d1a2b3c4d';
const EOA = '0x8ba1f109551bD432803012645Ac136ddd64DBA72';

describe('uuidToUserId — the UUID → 32-byte AA userId mapping', () => {
  it('is keccak256 of the utf8 bytes of the canonical lowercase uuid', () => {
    expect(uuidToUserId(UUID)).toBe(keccak256(stringToBytes(UUID)));
  });

  it('is deterministic and 32 bytes', () => {
    const a = uuidToUserId(UUID);
    const b = uuidToUserId(UUID);
    expect(a).toBe(b);
    expect(a).toMatch(/^0x[0-9a-f]{64}$/);
  });

  it('normalizes case so the same uuid maps to the same userId', () => {
    expect(uuidToUserId(UUID.toUpperCase())).toBe(uuidToUserId(UUID));
  });

  it('rejects a non-uuid input', () => {
    expect(() => uuidToUserId('not-a-uuid')).toThrow();
  });
});

describe('accountIdToAaUserId — all three account shapes', () => {
  it('passes a 32-byte hex userId through unchanged', () => {
    const raw = `0x${'ab'.repeat(32)}`;
    expect(accountIdToAaUserId(raw)).toBe(raw);
  });

  it('zero-pads a 20-byte EOA address (degenerate SIWE form)', () => {
    expect(accountIdToAaUserId(EOA)).toBe(
      ('0x' + EOA.slice(2).padStart(64, '0')) as `0x${string}`,
    );
  });

  it('hashes a UUID account id via uuidToUserId', () => {
    expect(accountIdToAaUserId(UUID)).toBe(uuidToUserId(UUID));
  });

  it('returns null for anything else', () => {
    expect(accountIdToAaUserId('bogus')).toBeNull();
  });
});

describe('predictedWalletForAccount', () => {
  afterEach(() => setWalletClaimsConfig(undefined));

  it('returns undefined when the AA wallet-claims config is not set (dev)', () => {
    setWalletClaimsConfig(undefined);
    expect(predictedWalletForAccount(UUID)).toBeUndefined();
  });

  it('predicts the CREATE2 smart-wallet address for a UUID account', () => {
    setWalletClaimsConfig({ factory: FACTORY, kernelImpl: KERNEL_IMPL });
    const expected = predictWalletAddress(
      FACTORY,
      KERNEL_IMPL,
      uuidToUserId(UUID),
    );
    expect(predictedWalletForAccount(UUID)).toBe(expected);
  });
});

describe('findAccount claims — UUID-keyed users (the seam fix)', () => {
  beforeEach(() => {
    setUserStore(new InMemoryUserStore());
    setWalletClaimsConfig({ factory: FACTORY, kernelImpl: KERNEL_IMPL });
  });
  afterEach(() => {
    setWalletClaimsConfig(undefined);
  });

  it('populates wallet_address + wallets with the predicted smart wallet', async () => {
    const user = await getUserStore().createWithPasskey();
    const account = await findAccount(undefined as never, user.id);
    const claims = await account!.claims('id_token', 'openid wallet', {} as never, [] as never);
    const expected = predictWalletAddress(
      FACTORY,
      KERNEL_IMPL,
      uuidToUserId(user.id),
    );
    expect(claims.wallet_address).toBe(expected);
    expect(claims.wallets).toEqual([expected]);
  });

  it('carries signing_method from the most recent successful sign-in', async () => {
    const user = await getUserStore().createWithPasskey();
    await getUserStore().setLastSigningMethod(user.id, 'passkey');
    const account = await findAccount(undefined as never, user.id);
    const claims = await account!.claims('id_token', 'openid wallet', {} as never, [] as never);
    expect(claims.signing_method).toBe('passkey');
  });

  it('prefers an explicitly bound primary_wallet over the prediction', async () => {
    const store = new InMemoryUserStore();
    setUserStore(store);
    const user = await store.createWithPasskey();
    await store.setPrimaryWallet(user.id, EOA.toLowerCase());
    const account = await findAccount(undefined as never, user.id);
    const claims = await account!.claims('id_token', 'openid wallet', {} as never, [] as never);
    expect(claims.wallet_address).toBe(getAddress(EOA));
  });

  it('omits wallet_address when the AA config is absent (dev parity)', async () => {
    setWalletClaimsConfig(undefined);
    const user = await getUserStore().createWithPasskey();
    const account = await findAccount(undefined as never, user.id);
    const claims = await account!.claims('id_token', 'openid wallet', {} as never, [] as never);
    expect(claims.wallet_address).toBeUndefined();
    expect(claims.kyc_status).toBe('none');
  });

  it('emits email + email_verified for an email-keyed account (dataroom C.1)', async () => {
    const store = new InMemoryUserStore();
    setUserStore(store);
    const user = await store.createWithEmailPassword({
      email: 'investor@example.com',
      passwordHash: 'x',
    });
    const account = await findAccount(undefined as never, user.id);
    const claims = await account!.claims('id_token', 'openid profile', {} as never, [] as never);
    expect(claims.email).toBe('investor@example.com');
    expect(claims.email_verified).toBe(false);
  });

  it('surfaces a LIVE kyc_status keyed on the UUID accountId (COMP-S1 seam)', async () => {
    // The store is keyed on the OIDC accountId — exactly the externalUserId
    // /kyc/start hands the vendor and /kyc/_set writes back under. A UUID-keyed
    // user is now as KYC-able as a SIWE one (pre-EW-S1 this was hardcoded 'none').
    const store = new InMemoryUserStore();
    setUserStore(store);
    const user = await store.createWithPasskey();
    const kyc = new InMemoryKycStore();
    setKycStore(kyc);
    try {
      await kyc.set(user.id, {
        status: 'verified',
        vendor_ref: 'sumsub:applicant-xyz',
        verified_at: '2026-06-17T00:00:00.000Z',
      });
      const account = await findAccount(undefined as never, user.id);
      const claims = await account!.claims('id_token', 'openid wallet kyc', {} as never, [] as never);
      expect(claims.kyc_status).toBe('verified');
      expect(claims.kyc_verified_at).toBe('2026-06-17T00:00:00.000Z');
    } finally {
      setKycStore(new InMemoryKycStore());
    }
  });
});

describe('findAccount claims — SIWE EOA accounts keep their shape', () => {
  it('wallet_address stays the EOA and signing_method is "siwe"', async () => {
    const account = await findAccount(undefined as never, EOA);
    const claims = await account!.claims('id_token', 'openid wallet', {} as never, [] as never);
    expect(claims.wallet_address).toBe(getAddress(EOA));
    expect(claims.wallets).toEqual([getAddress(EOA)]);
    expect(claims.signing_method).toBe('siwe');
  });
});
