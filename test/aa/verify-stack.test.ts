/**
 * Regression tests for the 2026-07-25 wrong-embedded-wallet-address incident.
 *
 * The authority predicted `0x918B056118da9b1D1922Ae8Fc49821f5152DF161` for
 * `userId = 0x4242…` while the on-chain factory deploys to
 * `0x1615Af127952c4e4987D7b597bDD7cb8B49aFB89`. Nothing in the service caught
 * it, because the stale addresses were well-formed and shape validation is all
 * `loadAaConfig` does.
 *
 * These tests use the REAL addresses from the incident, so they assert the
 * guard fires on the exact configuration that shipped — not on a synthetic
 * mismatch that might not resemble it.
 */

import { describe, it, expect } from 'vitest';
import {
  verifyAaStackOnChain,
  formatAaStackProblems,
  type AaStackProblem,
} from '../../src/aa/verify-stack.js';

// The values that were live on auth.citrate.ai on 2026-07-25 (both since
// confirmed to have NO code on chain 40204 — they are from a wiped chain).
const STALE_FACTORY = '0x5a45B6F83050a76A81D0F2E6c857F16B37B2693b' as const;
const STALE_IMPL = '0xe641A41b02F1ff114481D357D148bE4519830087' as const;
// The canonical 40204 stack (contracts/addresses/40204.json).
const GOOD_FACTORY = '0xc9c7b3d3fe28012ab5f2583a4f58531e9f26d3f5' as const;
const GOOD_IMPL = '0x79c4a8367d2d65b162de841ff678db4875490b2e' as const;

/** A stub chain: `code` maps address→bytecode, `impl` is factory.implementation(). */
function stubClient(opts: {
  code?: Record<string, string>;
  impl?: string;
  chainId?: number;
  throwOnRead?: boolean;
}) {
  return {
    getChainId: async () => opts.chainId ?? 40204,
    getBytecode: async ({ address }: { address: string }) =>
      opts.code?.[address.toLowerCase()] ?? '0x',
    readContract: async () => {
      if (opts.throwOnRead) throw new Error('execution reverted');
      return opts.impl as `0x${string}`;
    },
  } as never;
}

describe('verifyAaStackOnChain', () => {
  it('accepts the canonical 40204 stack', async () => {
    const problems = await verifyAaStackOnChain({
      factory: GOOD_FACTORY,
      walletImpl: GOOD_IMPL,
      rpcUrl: 'stub',
      chainId: 40204n,
      client: stubClient({
        code: { [GOOD_FACTORY.toLowerCase()]: '0xdeadbeef' },
        impl: GOOD_IMPL,
      }),
    });
    expect(problems).toEqual([]);
  });

  it('catches the exact stale factory that shipped (no code on chain)', async () => {
    const problems = await verifyAaStackOnChain({
      factory: STALE_FACTORY,
      walletImpl: STALE_IMPL,
      rpcUrl: 'stub',
      chainId: 40204n,
      // Nothing deployed at the stale address — the incident's real state.
      client: stubClient({ code: {}, impl: GOOD_IMPL }),
    });
    expect(problems).toHaveLength(1);
    expect(problems[0]!.field).toBe('CITRATE_AA_FACTORY');
    expect(problems[0]!.message).toMatch(/no contract code/i);
    expect(problems[0]!.actual).toBe(STALE_FACTORY);
  });

  /**
   * The subtle half of the incident: `CITRATE_AA_WALLET_IMPL` had already been
   * corrected, but the legacy `CITRATE_AA_KERNEL_IMPL` alias — which wins in
   * docker-compose — was still stale. A deployed factory plus a wrong
   * implementation silently yields wrong addresses forever.
   */
  it('catches a live factory whose implementation disagrees with the config', async () => {
    const problems = await verifyAaStackOnChain({
      factory: GOOD_FACTORY,
      walletImpl: STALE_IMPL, // the stale KERNEL_IMPL alias overriding WALLET_IMPL
      rpcUrl: 'stub',
      chainId: 40204n,
      client: stubClient({
        code: { [GOOD_FACTORY.toLowerCase()]: '0xdeadbeef' },
        impl: GOOD_IMPL,
      }),
    });
    expect(problems).toHaveLength(1);
    expect(problems[0]!.expected).toBe(GOOD_IMPL);
    expect(problems[0]!.actual).toBe(STALE_IMPL);
    // The operator must be told about the alias precedence, or they will
    // "fix" WALLET_IMPL and see no change — exactly what happened.
    expect(problems[0]!.message).toMatch(/KERNEL_IMPL/);
  });

  it('is case-insensitive about the implementation address', async () => {
    const problems = await verifyAaStackOnChain({
      factory: GOOD_FACTORY,
      walletImpl: GOOD_IMPL.toUpperCase().replace('0X', '0x') as `0x${string}`,
      rpcUrl: 'stub',
      chainId: 40204n,
      client: stubClient({
        code: { [GOOD_FACTORY.toLowerCase()]: '0xdeadbeef' },
        impl: GOOD_IMPL,
      }),
    });
    expect(problems).toEqual([]);
  });

  it('flags a chain-id mismatch and stops (addresses belong to another chain)', async () => {
    const problems = await verifyAaStackOnChain({
      factory: GOOD_FACTORY,
      walletImpl: GOOD_IMPL,
      rpcUrl: 'stub',
      chainId: 40204n,
      client: stubClient({ chainId: 1, impl: GOOD_IMPL }),
    });
    expect(problems).toHaveLength(1);
    expect(problems[0]!.field).toBe('CITRATE_AA_CHAIN_ID');
  });

  /**
   * "We could not check" must never be reported as "it is fine" — that is the
   * failure mode that let the stale config serve wrong addresses unnoticed.
   */
  it('treats an unreachable RPC as a problem, not as success', async () => {
    const problems = await verifyAaStackOnChain({
      factory: GOOD_FACTORY,
      walletImpl: GOOD_IMPL,
      rpcUrl: 'stub',
      chainId: 40204n,
      client: {
        getChainId: async () => {
          throw new Error('ECONNREFUSED');
        },
        getBytecode: async () => '0x',
        readContract: async () => GOOD_IMPL,
      } as never,
    });
    expect(problems).toHaveLength(1);
    expect(problems[0]!.field).toBe('CITRATE_AA_RPC_URL');
  });

  it('flags a factory that does not answer implementation()', async () => {
    const problems = await verifyAaStackOnChain({
      factory: GOOD_FACTORY,
      walletImpl: GOOD_IMPL,
      rpcUrl: 'stub',
      chainId: 40204n,
      client: stubClient({
        code: { [GOOD_FACTORY.toLowerCase()]: '0xdeadbeef' },
        throwOnRead: true,
      }),
    });
    expect(problems).toHaveLength(1);
    expect(problems[0]!.message).toMatch(/implementation\(\)/);
  });
});

describe('formatAaStackProblems', () => {
  it('renders expected-vs-actual for an operator', () => {
    const problems: AaStackProblem[] = [
      {
        field: 'CITRATE_AA_FACTORY',
        expected: GOOD_FACTORY,
        actual: STALE_FACTORY,
        message: 'stale',
      },
    ];
    const out = formatAaStackProblems(problems);
    expect(out).toContain('CITRATE_AA_FACTORY');
    expect(out).toContain(GOOD_FACTORY);
    expect(out).toContain(STALE_FACTORY);
  });
});
