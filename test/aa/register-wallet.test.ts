import { describe, expect, it } from 'vitest';
import { keccak256, toBytes } from 'viem';

import {
  PAYMASTER_ABI,
  encodeRegisterWalletCalldata,
  planRegistration,
} from '../../src/aa/register-wallet.js';

// RADAR handoff T-2 (handoffs/RADAR_IDENTITY_HANDOFF_2026-07-14.md):
// the authority closes the paymaster-registration gap — the factory
// deploys wallets but never registers them, and unregistered wallets
// revert sponsorship with NotARegisteredCitrateWallet.

describe('encodeRegisterWalletCalldata', () => {
  it('encodes registerWallet(address) with the real selector', () => {
    const data = encodeRegisterWalletCalldata('0x00000000000000000000000000000000000000aa');
    const selector = keccak256(toBytes('registerWallet(address)')).slice(0, 10);
    expect(data.slice(0, 10)).toBe(selector);
    expect(data.length).toBe(2 + 8 + 64); // selector + one 32-byte word
  });

  it('rejects a malformed wallet address', () => {
    expect(() => encodeRegisterWalletCalldata('0x1234' as never)).toThrow();
  });
});

describe('planRegistration', () => {
  it('short-circuits when the wallet is already registered (idempotent)', () => {
    expect(planRegistration({ isRegistered: true, hasCode: true })).toEqual({
      action: 'skip',
      status: 'already-registered',
    });
  });

  it('refuses to register a wallet with no code on-chain (counterfactuals wait for deploy)', () => {
    expect(planRegistration({ isRegistered: false, hasCode: false })).toEqual({
      action: 'reject',
      status: 'not-deployed',
    });
  });

  it('registers a deployed, unregistered wallet', () => {
    expect(planRegistration({ isRegistered: false, hasCode: true })).toEqual({
      action: 'register',
      status: 'register',
    });
  });
});

describe('PAYMASTER_ABI', () => {
  it('exposes exactly the surface the route uses', () => {
    const names = PAYMASTER_ABI.map((e) => e.name);
    expect(names).toContain('registerWallet');
    expect(names).toContain('isRegistered');
  });
});
