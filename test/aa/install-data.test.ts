import { describe, it, expect } from 'vitest';
import {
  decodeFunctionData,
  type Hex,
} from 'viem';

import {
  webauthnInstallData,
  ecdsaInstallData,
  guardianInstallData,
  kernelInitializeCalldata,
  packValidationId,
  EcdsaValidatorSource,
  VALIDATION_TYPE_VALIDATOR,
  InstallDataError,
} from '../../src/aa/install-data.js';

const ZERO32 = '0x'.padEnd(66, '0') as Hex;
const X =
  '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' as Hex;
const Y =
  '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' as Hex;
const CRED = ('0x' + 'de'.repeat(32)) as Hex;

describe('webauthnInstallData', () => {
  it('packs 97 bytes with the requireUv flag set', () => {
    const data = webauthnInstallData({
      credentialIdHash: CRED,
      x: X,
      y: Y,
      requireUserVerification: true,
    });
    expect(data.length).toBe(2 + 97 * 2);
    expect(data.slice(2 + 96 * 2)).toBe('01');
  });

  it('packs 97 bytes with the flag cleared', () => {
    const data = webauthnInstallData({
      credentialIdHash: ZERO32,
      x: X,
      y: Y,
      requireUserVerification: false,
    });
    expect(data.length).toBe(2 + 97 * 2);
    expect(data.slice(2 + 96 * 2)).toBe('00');
  });

  it('rejects wrongly-sized fields', () => {
    expect(() =>
      webauthnInstallData({
        credentialIdHash: '0x1234' as Hex,
        x: X,
        y: Y,
        requireUserVerification: true,
      }),
    ).toThrow(InstallDataError);
  });
});

describe('ecdsaInstallData', () => {
  it('packs 21 bytes with the source enum', () => {
    const data = ecdsaInstallData({
      owner: '0x1111111111111111111111111111111111111111',
      source: EcdsaValidatorSource.WalletExtension,
    });
    expect(data.length).toBe(2 + 21 * 2);
    expect(data.slice(2 + 20 * 2)).toBe('02');
  });

  it('rejects a malformed owner', () => {
    expect(() =>
      ecdsaInstallData({
        owner: '0x12' as `0x${string}`,
        source: EcdsaValidatorSource.GuiNative,
      }),
    ).toThrow(InstallDataError);
  });
});

describe('guardianInstallData', () => {
  const G1 = '0x1111111111111111111111111111111111111111' as const;
  const G2 = '0x2222222222222222222222222222222222222222' as const;
  const G3 = '0x3333333333333333333333333333333333333333' as const;

  it('packs 2 + 20*N bytes', () => {
    const data = guardianInstallData({ threshold: 2, guardians: [G1, G2, G3] });
    expect(data.length).toBe(2 + (2 + 20 * 3) * 2);
    expect(data.slice(2, 4)).toBe('02'); // threshold
    expect(data.slice(4, 6)).toBe('03'); // count
  });

  it('rejects count below MIN_GUARDIANS', () => {
    expect(() => guardianInstallData({ threshold: 1, guardians: [G1] })).toThrow(
      InstallDataError,
    );
  });

  it('rejects count above MAX_GUARDIANS', () => {
    expect(() =>
      guardianInstallData({
        threshold: 4,
        guardians: [G1, G2, G3, G1, G2, G3, G1, G2],
      }),
    ).toThrow(InstallDataError);
  });

  it('rejects threshold > count', () => {
    expect(() => guardianInstallData({ threshold: 4, guardians: [G1, G2, G3] })).toThrow(
      InstallDataError,
    );
  });

  it('rejects threshold = 0', () => {
    expect(() => guardianInstallData({ threshold: 0, guardians: [G1, G2, G3] })).toThrow(
      InstallDataError,
    );
  });

  it('rejects duplicate guardians', () => {
    expect(() => guardianInstallData({ threshold: 2, guardians: [G1, G1, G2] })).toThrow(
      InstallDataError,
    );
  });
});

describe('packValidationId', () => {
  it('produces a 21-byte hex (type byte + address)', () => {
    const id = packValidationId(
      VALIDATION_TYPE_VALIDATOR,
      '0x1111111111111111111111111111111111111111',
    );
    expect(id).toBe('0x011111111111111111111111111111111111111111');
  });

  it('rejects a malformed address', () => {
    expect(() =>
      packValidationId(VALIDATION_TYPE_VALIDATOR, '0x12' as `0x${string}`),
    ).toThrow(InstallDataError);
  });

  it('rejects a type byte that overflows', () => {
    expect(() =>
      packValidationId(0x100, '0x1111111111111111111111111111111111111111'),
    ).toThrow(InstallDataError);
  });
});

describe('kernelInitializeCalldata', () => {
  it('produces calldata that decodes back to its args', () => {
    const validatorAddr = '0x1111111111111111111111111111111111111111' as const;
    const validatorData = '0xdeadbeef' as Hex;
    const data = kernelInitializeCalldata({
      rootValidator: validatorAddr,
      validatorData,
    });
    expect(data.startsWith('0x')).toBe(true);

    const decoded = decodeFunctionData({
      abi: [
        {
          type: 'function',
          name: 'initialize',
          inputs: [
            { name: 'rootValidator', type: 'bytes21' },
            { name: 'hook', type: 'address' },
            { name: 'validatorData', type: 'bytes' },
            { name: 'hookData', type: 'bytes' },
            { name: 'initConfig', type: 'bytes[]' },
          ],
          outputs: [],
          stateMutability: 'payable',
        },
      ],
      data,
    });
    expect(decoded.functionName).toBe('initialize');
    expect(decoded.args[0]).toBe(
      `0x01${validatorAddr.slice(2)}`,
    );
    expect(decoded.args[1]).toBe('0x0000000000000000000000000000000000000000');
    expect(decoded.args[2]).toBe(validatorData);
    expect(decoded.args[3]).toBe('0x');
    expect(decoded.args[4]).toEqual([]);
  });
});
