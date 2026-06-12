/**
 * EW-S1 WP-10 item 31 — guardian nominations.
 *
 * The on-chain wire shape these helpers produce (Kernel installModule
 * self-call with the execute-selector grant) is proven end-to-end in
 * citrate-chain `test/aa/GuardianRecoveryE2E.t.sol`; here we pin the
 * encoder bytes + the nomination validation + the HTTP gates.
 */

import { beforeEach, describe, expect, it } from 'vitest';
import { decodeFunctionData, type Address } from 'viem';

import {
  InMemoryGuardianStore,
  getGuardianStore,
  setGuardianStore,
  normalizeNomination,
  GuardianNominationError,
} from '../../src/aa/guardians.js';
import {
  guardianInstallData,
  guardianInstallModuleCall,
  kernelInstallModuleCalldata,
  KERNEL_EXECUTE_SELECTOR,
} from '../../src/aa/install-data.js';

const G1 = '0x1111111111111111111111111111111111111111' as Address;
const G2 = '0x2222222222222222222222222222222222222222' as Address;
const RECOVERY = '0x42f3d7842d382d47199533a6bfcceaf483c6c857' as Address;

describe('normalizeNomination', () => {
  it('normalizes + bounds-checks like the on-chain module', () => {
    const n = normalizeNomination({
      sub: 's',
      guardians: [G1, G2.toUpperCase().replace('0X', '0x')],
      threshold: 2,
    });
    expect(n.guardians).toEqual([G1, G2]);
    expect(n.threshold).toBe(2);

    expect(() =>
      normalizeNomination({ sub: 's', guardians: [G1], threshold: 1 }),
    ).toThrow(GuardianNominationError); // < 2 guardians
    expect(() =>
      normalizeNomination({ sub: 's', guardians: [G1, G2], threshold: 3 }),
    ).toThrow(GuardianNominationError); // threshold > count
    expect(() =>
      normalizeNomination({ sub: 's', guardians: [G1, G1], threshold: 1 }),
    ).toThrow(GuardianNominationError); // duplicate
    expect(() =>
      normalizeNomination({ sub: 's', guardians: [G1, 'nope'], threshold: 1 }),
    ).toThrow(GuardianNominationError); // not an address
  });

  it('refuses the authority’s own signer as a guardian (ADR: never Citrate)', () => {
    expect(() =>
      normalizeNomination({
        sub: 's',
        guardians: [G1, G2],
        threshold: 2,
        forbidden: [G2.toUpperCase().replace('0X', '0x')],
      }),
    ).toThrow(/cannot be a guardian/);
  });
});

describe('guardian store', () => {
  beforeEach(() => setGuardianStore(new InMemoryGuardianStore()));

  it('round-trips a nomination per sub', async () => {
    const store = getGuardianStore();
    await store.set(
      normalizeNomination({ sub: 'alice', guardians: [G1, G2], threshold: 2 }),
    );
    const got = await store.get('alice');
    expect(got?.guardians).toEqual([G1, G2]);
    expect(await store.get('bob')).toBeUndefined();
    await store.clear('alice');
    expect(await store.get('alice')).toBeUndefined();
  });
});

describe('kernelInstallModuleCalldata — the initConfig wire shape', () => {
  it('encodes installModule(1, module, hook ++ abi(validatorData, hookData, selector))', () => {
    const calldata = guardianInstallModuleCall({
      recoveryModule: RECOVERY,
      threshold: 2,
      guardians: [G1, G2],
    });
    // installModule(uint256,address,bytes) selector (cast sig): 0x9517e29f
    expect(calldata.slice(0, 10)).toBe('0x9517e29f');

    const decoded = decodeFunctionData({
      abi: [
        {
          type: 'function',
          name: 'installModule',
          inputs: [
            { name: 'moduleType', type: 'uint256' },
            { name: 'module', type: 'address' },
            { name: 'initData', type: 'bytes' },
          ],
          outputs: [],
          stateMutability: 'payable',
        },
      ] as const,
      data: calldata,
    });
    expect(decoded.args[0]).toBe(1n);
    expect((decoded.args[1] as string).toLowerCase()).toBe(RECOVERY);

    const initData = decoded.args[2] as `0x${string}`;
    // First 20 bytes: hook = address(0) (Kernel converts to "no hook").
    expect(initData.slice(2, 42)).toBe('00'.repeat(20));
    // The inner tuple carries the guardian install data + the execute grant.
    const expectedValidatorData = guardianInstallData({ threshold: 2, guardians: [G1, G2] });
    expect(initData).toContain(expectedValidatorData.slice(2));
    expect(initData).toContain(KERNEL_EXECUTE_SELECTOR.slice(2));
  });
});
