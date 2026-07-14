/**
 * Close the CitratePaymaster registration gap (RADAR handoff T-2,
 * handoffs/RADAR_IDENTITY_HANDOFF_2026-07-14.md).
 *
 * `CitrateWalletFactory.deployFor` deploys wallets but never calls
 * `CitratePaymaster.registerWallet`, and the paymaster reverts
 * `NotARegisteredCitrateWallet` for unregistered accounts — so a
 * freshly deployed wallet cannot get its first op sponsored. The
 * authority holds the paymaster registrar key (same custody posture
 * as the identity-signer key: droplet `.env`, never logged, rotate
 * per ADR-2026-06-05-ew-wallet-stack) and performs the registration
 * on behalf of users it authenticated.
 *
 * Pure pieces (`planRegistration`, `encodeRegisterWalletCalldata`)
 * are exported for tests; the chain IO wrapper stays thin.
 */

import {
  createPublicClient,
  createWalletClient,
  defineChain,
  encodeFunctionData,
  http,
  type Address,
  type Hex,
} from 'viem';
import { privateKeyToAccount } from 'viem/accounts';

export const PAYMASTER_ABI = [
  {
    type: 'function',
    name: 'registerWallet',
    stateMutability: 'nonpayable',
    inputs: [{ name: 'account', type: 'address' }],
    outputs: [],
  },
  {
    type: 'function',
    name: 'isRegistered',
    stateMutability: 'view',
    inputs: [{ name: 'account', type: 'address' }],
    outputs: [{ name: '', type: 'bool' }],
  },
] as const;

export function encodeRegisterWalletCalldata(wallet: Address): Hex {
  if (!/^0x[a-fA-F0-9]{40}$/.test(wallet)) {
    throw new Error('wallet must be a 20-byte 0x-prefixed address');
  }
  return encodeFunctionData({
    abi: PAYMASTER_ABI,
    functionName: 'registerWallet',
    args: [wallet],
  });
}

export type RegistrationPlan =
  | { action: 'skip'; status: 'already-registered' }
  | { action: 'reject'; status: 'not-deployed' }
  | { action: 'register'; status: 'register' };

/**
 * Decide what to do for a wallet, given the two chain reads. Pure —
 * the route reads chain state, this decides, the IO wrapper acts.
 * Counterfactual (no-code) wallets are refused: registration happens
 * after the factory deploy lands, not before.
 */
export function planRegistration(state: {
  isRegistered: boolean;
  hasCode: boolean;
}): RegistrationPlan {
  if (state.isRegistered) return { action: 'skip', status: 'already-registered' };
  if (!state.hasCode) return { action: 'reject', status: 'not-deployed' };
  return { action: 'register', status: 'register' };
}

export interface RegisterWalletDeps {
  rpcUrl: string;
  chainId: bigint;
  paymaster: Address;
  /** Registrar private key; holder must have the paymaster registrar role. */
  registrarKey: Hex;
}

export type RegisterWalletResult =
  | { status: 'already-registered'; wallet: Address }
  | { status: 'registered'; wallet: Address; txHash: Hex };

export class WalletNotDeployedError extends Error {
  constructor(wallet: Address) {
    super(`wallet ${wallet} has no code on-chain; deploy before registering`);
    this.name = 'WalletNotDeployedError';
  }
}

/**
 * Idempotently register `wallet` with the paymaster. Reads first
 * (isRegistered + code), then sends the registrar tx only when the
 * plan says so, and waits for the receipt so callers get a settled
 * answer, not an optimistic one.
 */
export async function registerWalletIfNeeded(
  deps: RegisterWalletDeps,
  wallet: Address,
): Promise<RegisterWalletResult> {
  const chain = defineChain({
    id: Number(deps.chainId),
    name: 'Citrate',
    nativeCurrency: { name: 'SALT', symbol: 'SALT', decimals: 18 },
    rpcUrls: { default: { http: [deps.rpcUrl] } },
  });
  const publicClient = createPublicClient({ chain, transport: http(deps.rpcUrl) });

  const [isRegistered, code] = await Promise.all([
    publicClient.readContract({
      address: deps.paymaster,
      abi: PAYMASTER_ABI,
      functionName: 'isRegistered',
      args: [wallet],
    }),
    publicClient.getBytecode({ address: wallet }),
  ]);

  const plan = planRegistration({
    isRegistered,
    hasCode: code !== undefined && code !== '0x',
  });
  if (plan.action === 'skip') return { status: 'already-registered', wallet };
  if (plan.action === 'reject') throw new WalletNotDeployedError(wallet);

  const registrar = privateKeyToAccount(deps.registrarKey);
  const walletClient = createWalletClient({ account: registrar, chain, transport: http(deps.rpcUrl) });
  const txHash = await walletClient.writeContract({
    address: deps.paymaster,
    abi: PAYMASTER_ABI,
    functionName: 'registerWallet',
    args: [wallet],
  });
  await publicClient.waitForTransactionReceipt({ hash: txHash });
  return { status: 'registered', wallet, txHash };
}
