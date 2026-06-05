/**
 * KycProvider selection + factory.
 *
 * Caller code never imports a concrete adapter. It imports
 * {@link selectKycProvider} from this module and binds by env.
 *
 * The factory enforces three invariants:
 *
 *   1. `KYC_PROVIDER` env names the adapter. Unknown name → error.
 *   2. The `mock` adapter refuses to load in production (NODE_ENV ===
 *      'production' or CITRATE_ENV === 'production').
 *   3. The `clear` adapter refuses to load in production until the
 *      partnership closes and the stub is replaced.
 *
 * See `ADR-2026-06-05-kyc-vendor-order` and
 * `ADR-2026-06-05-kyc-provider-abstraction`.
 */

import { ClearKycProvider, type ClearKycProviderConfig } from './clear.js';
import { MockKycProvider, type MockKycProviderConfig } from './mock.js';
import { SumsubKycProvider, type SumsubKycProviderConfig } from './sumsub.js';
import type { KycProvider } from './types.js';

export * from './types.js';
export { KYC_LEVELS, type KycLevel, isKycLevel } from './level-hints.js';
export { SumsubKycProvider } from './sumsub.js';
export { ClearKycProvider, ClearAdapterNotImplementedError } from './clear.js';
export { MockKycProvider } from './mock.js';

export type KycProviderName = 'sumsub' | 'clear' | 'mock';

/**
 * Per-provider config bag the factory accepts. Production callers populate
 * only the field for the active provider; the rest can be omitted.
 */
export interface KycProviderFactoryEnv {
  provider: KycProviderName | string | undefined;
  isProduction: boolean;
  sumsub?: SumsubKycProviderConfig;
  clear?: ClearKycProviderConfig;
  mock?: MockKycProviderConfig;
}

/**
 * Build a {@link KycProvider} instance for the active env. Throws with a
 * clear, fail-closed message on any misconfiguration — caller is
 * `assertProductionConfig` style code in `server.ts`.
 */
export function selectKycProvider(env: KycProviderFactoryEnv): KycProvider {
  const name = env.provider;
  if (!name) {
    throw new Error(
      'KYC_PROVIDER is not set. Set KYC_PROVIDER=sumsub (production) or =mock (dev/test).',
    );
  }

  switch (name as KycProviderName) {
    case 'sumsub': {
      if (!env.sumsub) {
        throw new Error('KYC_PROVIDER=sumsub but Sumsub config is missing');
      }
      return new SumsubKycProvider(env.sumsub);
    }

    case 'clear': {
      if (env.isProduction) {
        throw new Error(
          'KYC_PROVIDER=clear refuses to boot in production until the CLEAR adapter ' +
            'is implemented (see ADR-2026-06-05-kyc-vendor-order). Use KYC_PROVIDER=sumsub.',
        );
      }
      if (!env.clear) {
        throw new Error('KYC_PROVIDER=clear but CLEAR config is missing');
      }
      return new ClearKycProvider(env.clear);
    }

    case 'mock': {
      if (env.isProduction) {
        throw new Error(
          'KYC_PROVIDER=mock refuses to boot in production. The mock provider is ' +
            'dev/test only.',
        );
      }
      return new MockKycProvider(env.mock);
    }

    default:
      throw new Error(
        `KYC_PROVIDER="${name}" is not a recognised provider. ` +
          'Expected one of: sumsub, clear, mock.',
      );
  }
}
