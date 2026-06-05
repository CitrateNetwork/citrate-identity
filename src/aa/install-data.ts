/**
 * Pack on-install payloads for the Citrate Kernel-fork validators
 * (WP-5 of EW-S1). Counterpart to `citrate-chain/wallet-aa/src/init_data.rs`.
 *
 * Every helper here MUST produce bytes that match the strict-length
 * decoding in the corresponding Solidity contract:
 *
 *   - `WebAuthnP256Validator.onInstall`  → 97 bytes
 *   - `CitrateECDSAValidator.onInstall`  → 21 bytes
 *   - `GuardianRecoveryModule.onInstall` → 2 + 20·N bytes
 *
 * Length mismatches make the on-chain validator's `revert
 * InvalidInstallData()` fire immediately on the install attempt.
 */

import {
  concatHex,
  encodeAbiParameters,
  encodeFunctionData,
  type Address,
  type Hex,
} from 'viem';

export class InstallDataError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'InstallDataError';
  }
}

// ── WebAuthn P-256 validator ────────────────────────────────────────────

/**
 * Pack the WebAuthn validator's `onInstall` payload:
 * `bytes32 credentialIdHash | uint256 x | uint256 y | uint8 requireUv` (97 bytes).
 */
export function webauthnInstallData(args: {
  credentialIdHash: Hex; // 32 bytes
  x: Hex; // 32 bytes
  y: Hex; // 32 bytes
  requireUserVerification: boolean;
}): Hex {
  expectBytes('credentialIdHash', args.credentialIdHash, 32);
  expectBytes('x', args.x, 32);
  expectBytes('y', args.y, 32);
  return concatHex([
    args.credentialIdHash,
    args.x,
    args.y,
    args.requireUserVerification ? '0x01' : '0x00',
  ]);
}

// ── ECDSA validator (gui-native / wallet-extension EOA) ───────────────

/** Source enum on `CitrateECDSAValidator`. Keep in sync with the contract. */
export enum EcdsaValidatorSource {
  Unknown = 0,
  GuiNative = 1,
  WalletExtension = 2,
  Other = 3,
}

/**
 * Pack the ECDSA validator's `onInstall` payload:
 * `address owner | uint8 source` (21 bytes).
 */
export function ecdsaInstallData(args: {
  owner: Address;
  source: EcdsaValidatorSource;
}): Hex {
  const ownerNoPrefix = args.owner.slice(2);
  if (ownerNoPrefix.length !== 40) {
    throw new InstallDataError(
      `owner must be a 20-byte address (got ${ownerNoPrefix.length / 2} bytes)`,
    );
  }
  const sourceByte = args.source.toString(16).padStart(2, '0');
  return `0x${ownerNoPrefix}${sourceByte}` as Hex;
}

// ── Guardian recovery module ─────────────────────────────────────────

/**
 * Pack the recovery module's `onInstall` payload:
 * `uint8 threshold | uint8 count | address[count] guardians`
 * (2 + 20·N bytes).
 *
 * The contract rejects `count < 2 || count > 7` and `threshold == 0 ||
 * threshold > count`, so we mirror those validations client-side for
 * a clearer error rather than letting the on-chain revert speak.
 */
export function guardianInstallData(args: {
  threshold: number;
  guardians: Address[];
}): Hex {
  const count = args.guardians.length;
  if (count < 2 || count > 7) {
    throw new InstallDataError(`guardian count must be in [2, 7] (got ${count})`);
  }
  if (args.threshold < 1 || args.threshold > count) {
    throw new InstallDataError(
      `threshold must be in [1, ${count}] (got ${args.threshold})`,
    );
  }
  const seen = new Set<string>();
  for (const g of args.guardians) {
    const k = g.toLowerCase();
    if (seen.has(k)) {
      throw new InstallDataError(`duplicate guardian: ${g}`);
    }
    seen.add(k);
  }
  let out =
    args.threshold.toString(16).padStart(2, '0') +
    count.toString(16).padStart(2, '0');
  for (const g of args.guardians) {
    out += g.slice(2);
  }
  return `0x${out}` as Hex;
}

// ── Kernel initialize() calldata ──────────────────────────────────────

/**
 * Validation-type prefix on Kernel's `ValidationId`. `0x01` =
 * validator (the type our WebAuthn + ECDSA + Guardian modules report
 * via `isModuleType(MODULE_TYPE_VALIDATOR)`).
 */
export const VALIDATION_TYPE_VALIDATOR = 0x01 as const;

/** Construct the `bytes21 rootValidator` field Kernel's `initialize` expects. */
export function packValidationId(
  validationType: number,
  validatorAddr: Address,
): Hex {
  if (validationType < 0 || validationType > 0xff) {
    throw new InstallDataError(
      `validationType must fit in a byte (got ${validationType})`,
    );
  }
  const typeHex = validationType.toString(16).padStart(2, '0');
  const addrHex = validatorAddr.slice(2);
  if (addrHex.length !== 40) {
    throw new InstallDataError(
      `validator address must be 20 bytes (got ${addrHex.length / 2})`,
    );
  }
  return `0x${typeHex}${addrHex}` as Hex;
}

/**
 * Encode the calldata for Kernel v3's
 * `initialize(bytes21 rootValidator, address hook, bytes validatorData,
 *             bytes hookData, bytes[] initConfig)`.
 *
 * Returns the full 4-byte selector + ABI-encoded args ready to be
 * passed as `initData` to `CitrateWalletFactory.deployFor`.
 */
export function kernelInitializeCalldata(args: {
  rootValidator: Address;
  validationType?: number; // defaults to validator (0x01)
  hook?: Address;
  validatorData: Hex;
  hookData?: Hex;
  initConfig?: Hex[];
}): Hex {
  const validationId = packValidationId(
    args.validationType ?? VALIDATION_TYPE_VALIDATOR,
    args.rootValidator,
  );
  const hook = args.hook ?? '0x0000000000000000000000000000000000000000';
  const hookData = args.hookData ?? '0x';
  const initConfig = args.initConfig ?? [];

  return encodeFunctionData({
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
    functionName: 'initialize',
    args: [validationId, hook, args.validatorData, hookData, initConfig],
  });
}

// ── helpers ───────────────────────────────────────────────────────────

function expectBytes(name: string, hex: Hex, byteCount: number): void {
  if (!hex.startsWith('0x') || hex.length !== 2 + byteCount * 2) {
    throw new InstallDataError(
      `${name} must be a ${byteCount}-byte 0x-prefixed hex (got length ${hex.length})`,
    );
  }
}

// Re-export encodeAbiParameters as a sanity bit so unit tests can
// confirm we're driving the same primitive as the rest of the module.
export { encodeAbiParameters };
