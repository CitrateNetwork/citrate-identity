/**
 * Startup parity check: is the configured AA stack the one actually
 * deployed on the configured chain?
 *
 * # Why this exists
 *
 * On 2026-07-25 `auth.citrate.ai` was found predicting embedded-wallet
 * addresses that the `CitrateWalletFactory` will never deploy to. For
 * `userId = 0x4242…` the authority answered
 * `0x918B056118da9b1D1922Ae8Fc49821f5152DF161`; the on-chain factory says
 * `0x1615Af127952c4e4987D7b597bDD7cb8B49aFB89`. A member funding the
 * authority's answer would have lost those funds.
 *
 * The prediction *algorithm* was never wrong — `predict.ts` reproduces the
 * on-chain factory byte-for-byte. The **inputs** were stale: after the
 * 2026-07-23 deployer reroll the droplet's `.env` still carried a
 * `CITRATE_AA_FACTORY` and `CITRATE_AA_KERNEL_IMPL` from a wiped chain, and
 * neither address had any code on 40204.
 *
 * `loadAaConfig` did not catch it because it validates **shape**, not
 * **identity**: `0x5a45B6F8…` is a perfectly well-formed address, so every
 * check passed and the service served wrong money addresses silently for two
 * days. Shape validation cannot detect a stale address — only the chain can.
 *
 * Two details made the drift survive a partial fix, and both are worth
 * remembering:
 *
 *   1. `CITRATE_AA_KERNEL_IMPL` is a legacy alias for
 *      `CITRATE_AA_WALLET_IMPL`, and compose resolves
 *      `KERNEL_IMPL:-${WALLET_IMPL:-}` — so the alias WINS. Someone had
 *      already corrected `WALLET_IMPL` to the right implementation; the stale
 *      `KERNEL_IMPL` silently overrode it.
 *   2. Nothing ever compared the configured implementation against
 *      `factory.implementation()`, which is a single free RPC call.
 *
 * # What this does
 *
 * One `eth_getCode` and one `implementation()` read at startup. If the
 * factory has no code, or the factory's implementation disagrees with the
 * configured one, the caller declines to mount `/aa/*` — see the fail-closed
 * note below.
 */

import {
  createPublicClient,
  http,
  type Address,
  type PublicClient,
} from 'viem';

/** Minimal ABI: the factory view that names its own implementation. */
const FACTORY_ABI = [
  {
    type: 'function',
    name: 'implementation',
    stateMutability: 'view',
    inputs: [],
    outputs: [{ type: 'address' }],
  },
] as const;

/** One reason the configured stack does not match the chain. */
export interface AaStackProblem {
  /** The env var / config field at fault. */
  field: string;
  /** What the chain says it should be (when knowable). */
  expected?: string;
  /** What the config actually carries. */
  actual?: string;
  /** Operator-facing explanation. */
  message: string;
}

export interface VerifyAaStackOpts {
  factory: Address;
  /** The Kernel implementation the factory is expected to clone. */
  walletImpl: Address;
  rpcUrl: string;
  /** When set, the chain must report this id. */
  chainId?: bigint;
  /** Injectable for tests; defaults to a viem HTTP client over `rpcUrl`. */
  client?: Pick<PublicClient, 'getBytecode' | 'readContract' | 'getChainId'>;
}

/**
 * Compare the configured AA stack against the chain.
 *
 * Returns an empty array when the config matches. Never throws for a
 * *mismatch* — the caller decides the policy. It DOES surface an unreachable
 * RPC as a problem rather than swallowing it, because "we could not check"
 * must not be silently treated as "it is fine": that is precisely the
 * failure mode that let the stale config serve wrong addresses.
 */
export async function verifyAaStackOnChain(
  opts: VerifyAaStackOpts,
): Promise<AaStackProblem[]> {
  const client =
    opts.client ??
    (createPublicClient({ transport: http(opts.rpcUrl) }) as PublicClient);
  const problems: AaStackProblem[] = [];

  if (opts.chainId !== undefined) {
    try {
      const actual = BigInt(await client.getChainId());
      if (actual !== opts.chainId) {
        // Return immediately. Every address check below is meaningless against
        // the wrong chain and would bury the real cause under a cascade of
        // "no code at ..." noise. One root cause beats five symptoms.
        return [
          {
            field: 'CITRATE_AA_CHAIN_ID',
            expected: actual.toString(),
            actual: opts.chainId.toString(),
            message:
              `configured chain id ${opts.chainId} but ${opts.rpcUrl} reports ` +
              `${actual} — the AA stack addresses belong to a different chain`,
          },
        ];
      }
    } catch (e) {
      problems.push({
        field: 'CITRATE_AA_RPC_URL',
        message: `could not read chain id from ${opts.rpcUrl}: ${(e as Error).message}`,
      });
      // No chain reachable → the remaining checks cannot be trusted either.
      return problems;
    }
  }

  // 1. The factory must exist. A stale address from a wiped chain has no
  //    code, which is exactly what the 2026-07-25 incident looked like.
  let factoryHasCode = false;
  try {
    const code = await client.getBytecode({ address: opts.factory });
    factoryHasCode = !!code && code !== '0x';
    if (!factoryHasCode) {
      problems.push({
        field: 'CITRATE_AA_FACTORY',
        actual: opts.factory,
        message:
          `no contract code at ${opts.factory} — this address is not deployed on ` +
          `this chain (typically a stale value left over from a reroll)`,
      });
    }
  } catch (e) {
    problems.push({
      field: 'CITRATE_AA_FACTORY',
      actual: opts.factory,
      message: `could not read code at ${opts.factory}: ${(e as Error).message}`,
    });
    return problems;
  }

  if (!factoryHasCode) return problems;

  // 2. The factory's own implementation must be the one we predict against.
  //    This is the check whose absence let a corrected WALLET_IMPL be
  //    silently overridden by a stale KERNEL_IMPL alias.
  try {
    const onChainImpl = (await client.readContract({
      address: opts.factory,
      abi: FACTORY_ABI,
      functionName: 'implementation',
    })) as Address;
    if (onChainImpl.toLowerCase() !== opts.walletImpl.toLowerCase()) {
      problems.push({
        field: 'CITRATE_AA_KERNEL_IMPL / CITRATE_AA_WALLET_IMPL',
        expected: onChainImpl,
        actual: opts.walletImpl,
        message:
          `factory ${opts.factory} clones implementation ${onChainImpl}, but the ` +
          `config predicts against ${opts.walletImpl} — every predicted address ` +
          `will be wrong. NOTE: CITRATE_AA_KERNEL_IMPL overrides ` +
          `CITRATE_AA_WALLET_IMPL in docker-compose, so check BOTH.`,
      });
    }
  } catch (e) {
    problems.push({
      field: 'CITRATE_AA_FACTORY',
      actual: opts.factory,
      message:
        `factory ${opts.factory} did not answer implementation(): ` +
        `${(e as Error).message} — is this really a CitrateWalletFactory?`,
    });
  }

  return problems;
}

/** Render problems as an operator-readable block for the startup log. */
export function formatAaStackProblems(problems: AaStackProblem[]): string {
  return problems
    .map((p) => {
      const detail =
        p.expected !== undefined && p.actual !== undefined
          ? ` (chain says ${p.expected}, config has ${p.actual})`
          : p.actual !== undefined
            ? ` (config has ${p.actual})`
            : '';
      return `  - ${p.field}: ${p.message}${detail}`;
    })
    .join('\n');
}
