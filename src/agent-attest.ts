/**
 * KYA attestation — writing agent bindings to the on-chain audit trail
 * (ADR-XA-1 D7).
 *
 * `AgentDecisionRegistry` is live on chain 40204 at
 * `0x728dbe86ce56123a5c1ddc248392940d7d2d30f9` and exposes:
 *
 *   registerDecision(bytes32 agentId, string toolName, bytes32 paramsHash)
 *     external onlyAuthorizedRecorder returns (uint256 decisionId)
 *
 * Two consequences shape this module:
 *
 * 1. **`onlyAuthorizedRecorder`.** The live `governance()` is
 *    `0x4fAB35c8c5033c80b3a0452A873B81e6ED4ED732` (the chain-40204 deployer).
 *    Somebody holding that key must call
 *    `setAuthorizedRecorder(<identity signer>, true)` before this can write.
 *    Until then every call reverts. So attestation is **best-effort and reports
 *    honestly**: a failure returns `null`, registration still succeeds, and the
 *    caller tells the user the attestation is pending. Reporting an attestation
 *    that did not happen would be worse than not having one.
 *
 * 2. **Nothing identifying goes on-chain.** `agentId` is `keccak256(agent_sub)`,
 *    so the subject itself is never published, and `paramsHash` COMMITS to the
 *    binding facts without revealing them. An auditor who is shown the off-chain
 *    binding can verify it against the chain; an observer learns only that some
 *    agent was bound at some block.
 */
import {
  createWalletClient,
  createPublicClient,
  http,
  keccak256,
  stringToBytes,
  encodeAbiParameters,
  parseAbi,
  type Address,
  type Hex,
} from 'viem';
import { privateKeyToAccount } from 'viem/accounts';

import { CITRATE_CHAIN_ID } from './siwe.js';

const REGISTRY_ABI = parseAbi([
  'function registerDecision(bytes32 agentId, string toolName, bytes32 paramsHash) external returns (uint256)',
  'event DecisionRecorded(uint256 indexed decisionId, bytes32 indexed agentId, string toolName, bytes32 paramsHash, uint256 blockNumber)',
]);

/** Tool names written to the registry. Stable strings — auditors filter on them. */
export const KYA_TOOL_BIND = 'kya.bind';
export const KYA_TOOL_REVOKE = 'kya.revoke';

export interface AttestConfig {
  registry: Address;
  signerKey: Hex;
  rpcUrl: string;
  chainId: number;
}

/**
 * Resolve the attestation config, or null when unconfigured.
 *
 * Dormant-by-default: with no registry address or signer key this module is inert
 * and the agent routes still work. That matters because the governance
 * transaction (§D7) is an owner action outside this codebase's control — the
 * feature must not be undeployable while it is pending.
 */
export function loadAttestConfig(
  env: NodeJS.ProcessEnv = process.env,
): AttestConfig | null {
  const registry = (env.CITRATE_AGENT_DECISION_REGISTRY ?? '').trim();
  const signerKey = (env.CITRATE_AA_IDENTITY_SIGNER_KEY ?? '').trim();
  const rpcUrl = (
    env.CITRATE_AA_RPC_URL ??
    env.CITRATE_RPC_URL ??
    ''
  ).trim();
  if (!/^0x[0-9a-fA-F]{40}$/.test(registry)) return null;
  if (!/^0x[0-9a-fA-F]{64}$/.test(signerKey)) return null;
  if (rpcUrl === '') return null;
  return {
    registry: registry as Address,
    signerKey: signerKey as Hex,
    rpcUrl,
    chainId: Number(env.CITRATE_AA_CHAIN_ID ?? CITRATE_CHAIN_ID),
  };
}

/** `agentId` for the registry: keccak256 of the agent subject. */
export function agentIdFor(agentSub: string): Hex {
  return keccak256(stringToBytes(agentSub));
}

/**
 * Commitment to the binding facts. Ordered and typed via abi encoding so the
 * hash is reproducible by an auditor holding the same off-chain record.
 */
export function bindingParamsHash(args: {
  agentSub: string;
  parentSub: string;
  scope: string;
  expiry: number | null;
}): Hex {
  return keccak256(
    encodeAbiParameters(
      [
        { type: 'string' },
        { type: 'string' },
        { type: 'string' },
        { type: 'uint256' },
      ],
      [args.agentSub, args.parentSub, args.scope, BigInt(args.expiry ?? 0)],
    ),
  );
}

async function writeDecision(
  cfg: AttestConfig,
  agentId: Hex,
  toolName: string,
  paramsHash: Hex,
): Promise<string | null> {
  try {
    const account = privateKeyToAccount(cfg.signerKey);
    const transport = http(cfg.rpcUrl);
    const chain = {
      id: cfg.chainId,
      name: 'Citrate',
      nativeCurrency: { name: 'SALT', symbol: 'SALT', decimals: 18 },
      rpcUrls: { default: { http: [cfg.rpcUrl] } },
    } as const;

    const wallet = createWalletClient({ account, chain, transport });
    const pub = createPublicClient({ chain, transport });

    const hash = await wallet.writeContract({
      address: cfg.registry,
      abi: REGISTRY_ABI,
      functionName: 'registerDecision',
      args: [agentId, toolName, paramsHash],
    });
    const receipt = await pub.waitForTransactionReceipt({ hash, timeout: 60_000 });
    if (receipt.status !== 'success') {
      console.error(
        `[kya-attest] ${toolName} tx ${hash} reverted — binding stands off-chain, ` +
          'attestation NOT recorded',
      );
      return null;
    }
    // decisionId is the first indexed topic after the event signature. Read it
    // from the log rather than trusting a local counter, which could race
    // another recorder.
    const log = receipt.logs.find(
      (l) => l.address.toLowerCase() === cfg.registry.toLowerCase() && l.topics.length >= 3,
    );
    if (!log?.topics[1]) {
      console.warn(`[kya-attest] ${toolName} tx ${hash} succeeded but no DecisionRecorded log found`);
      return null;
    }
    return BigInt(log.topics[1]).toString();
  } catch (err) {
    // The expected failure while the governance tx is pending is
    // `NotAuthorizedRecorder`. Log it plainly so an operator can tell "not yet
    // authorized" apart from a real outage.
    console.error(
      `[kya-attest] ${toolName} failed — attestation NOT recorded (is the identity ` +
        'signer an authorized recorder on AgentDecisionRegistry?):',
      err instanceof Error ? err.message : err,
    );
    return null;
  }
}

/**
 * Attest a new binding. Returns the registry decision id, or null when
 * attestation is unconfigured or failed — never throws into the route path.
 */
export async function attestAgentBinding(args: {
  agentSub: string;
  parentSub: string;
  scope: string;
  expiry: number | null;
}): Promise<string | null> {
  const cfg = loadAttestConfig();
  if (!cfg) return null;
  return writeDecision(
    cfg,
    agentIdFor(args.agentSub),
    KYA_TOOL_BIND,
    bindingParamsHash(args),
  );
}

/**
 * Attest a revoke. The registry is append-only, so this ADDS a revoke record
 * rather than erasing the bind — which is what keeps prior actions attributable
 * after revocation (acceptance A4).
 */
export async function attestAgentRevoke(args: {
  agentSub: string;
}): Promise<string | null> {
  const cfg = loadAttestConfig();
  if (!cfg) return null;
  const agentId = agentIdFor(args.agentSub);
  return writeDecision(cfg, agentId, KYA_TOOL_REVOKE, agentId);
}
