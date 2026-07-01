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
import { InhouseKycProvider, type InhouseKycProviderConfig } from './inhouse.js';
import { MockKycProvider, type MockKycProviderConfig } from './mock.js';
import { SumsubKycProvider, type SumsubKycProviderConfig } from './sumsub.js';
import type { KycProvider } from './types.js';
import { masterKeyFromEnv } from '../kyc-crypto.js';
import { KycCaseStore } from '../kyc-cases-pg.js';
import { startRetentionScheduler } from '../kyc-retention.js';

export * from './types.js';
export { KYC_LEVELS, type KycLevel, isKycLevel } from './level-hints.js';
export { SumsubKycProvider } from './sumsub.js';
export { ClearKycProvider, ClearAdapterNotImplementedError } from './clear.js';
export { MockKycProvider } from './mock.js';
export { InhouseKycProvider } from './inhouse.js';

export type KycProviderName = 'sumsub' | 'clear' | 'mock' | 'inhouse';

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
  inhouse?: InhouseKycProviderConfig;
}

/**
 * Process-wide KycProvider singleton. The `/kyc/start` route reads from
 * this at request time. Tests can swap via {@link setKycProvider} to
 * drive a deterministic mock without touching env. Mirrors the
 * `getKycStore` / `setKycStore` pattern in src/kyc.ts.
 *
 * Undefined until {@link initKycProviderFromEnv} runs; that's how the
 * route can tell KYC is unconfigured and return a fail-closed 503.
 */
let liveKycProvider: KycProvider | undefined;

/** The live KYC vendor adapter the user-facing routes call. */
export function getKycProvider(): KycProvider | undefined {
  return liveKycProvider;
}

/** Swap the live KYC vendor adapter (production wiring / tests). */
export function setKycProvider(provider: KycProvider | undefined): void {
  liveKycProvider = provider;
}

/**
 * Install the right KycProvider for the running environment, called
 * once at server boot. Mirrors {@link initKycStoreFromEnv}:
 *
 *   - `KYC_PROVIDER=sumsub` → build a {@link SumsubKycProvider} from
 *     `SUMSUB_APP_TOKEN`, `SUMSUB_SECRET_KEY`, `SUMSUB_WEBHOOK_SECRET`,
 *     and `SUMSUB_LEVEL_NAME` (the dashboard-configured level name for
 *     `KYC_LEVELS.BASIC_INDIVIDUAL`). `SUMSUB_BASE_URL` is optional and
 *     defaults to `https://api.sumsub.com`.
 *   - `KYC_PROVIDER=mock` → install a {@link MockKycProvider}. Refuses
 *     in production via the factory.
 *   - `KYC_PROVIDER` unset → leave the singleton undefined; the
 *     `/kyc/start` route returns 503 with a clear "KYC not configured"
 *     reason. In production the upstream config gate refuses to boot
 *     before reaching here.
 *
 * Each adapter is imported lazily, so the dev/test path never pulls
 * Sumsub's HTTP code in.
 */
export async function initKycProviderFromEnv(
  env: NodeJS.ProcessEnv = process.env,
): Promise<KycProvider | undefined> {
  const name = env.KYC_PROVIDER?.trim();
  if (!name) {
    // eslint-disable-next-line no-console
    console.warn(
      '[citrate-identity] KYC_PROVIDER unset — /kyc/start will return 503 ' +
        '(KYC not configured). Set KYC_PROVIDER=sumsub for production or ' +
        '=mock for dev/test to enable user-facing identity verification.',
    );
    setKycProvider(undefined);
    return undefined;
  }
  const isProduction =
    env.NODE_ENV === 'production' || env.CITRATE_ENV === 'production';

  const factoryEnv: KycProviderFactoryEnv = {
    provider: name,
    isProduction,
  };

  if (name === 'sumsub') {
    const appToken = env.SUMSUB_APP_TOKEN;
    const secretKey = env.SUMSUB_SECRET_KEY;
    const webhookSecret = env.SUMSUB_WEBHOOK_SECRET;
    const basicLevelName = env.SUMSUB_LEVEL_NAME;
    if (!appToken || !secretKey || !webhookSecret || !basicLevelName) {
      throw new Error(
        'KYC_PROVIDER=sumsub requires SUMSUB_APP_TOKEN, SUMSUB_SECRET_KEY, ' +
          'SUMSUB_WEBHOOK_SECRET, and SUMSUB_LEVEL_NAME.',
      );
    }
    factoryEnv.sumsub = {
      mode: isProduction ? 'prod' : 'sandbox',
      appToken,
      secretKey,
      webhookSecret,
      basicLevelName,
      ...(env.SUMSUB_BASE_URL ? { baseUrl: env.SUMSUB_BASE_URL } : {}),
    };
  } else if (name === 'mock') {
    factoryEnv.mock = { mode: 'sandbox' };
  } else if (name === 'clear') {
    factoryEnv.clear = { mode: isProduction ? 'prod' : 'sandbox' };
  } else if (name === 'inhouse') {
    const databaseUrl = env.DATABASE_URL;
    const sessionSecret = env.KYC_SESSION_SECRET;
    const webhookSecret = env.KYC_INHOUSE_WEBHOOK_SECRET;
    if (!databaseUrl || !sessionSecret || !webhookSecret) {
      throw new Error(
        'KYC_PROVIDER=inhouse requires DATABASE_URL, KYC_SESSION_SECRET, and ' +
          'KYC_INHOUSE_WEBHOOK_SECRET (plus KYC_MASTER_KEY). See VERI-S1 / ' +
          'ADR-2026-07-01-kyc-inhouse-provider.',
      );
    }
    // Master key is validated here (fail-closed if unset/wrong length).
    const masterKey = masterKeyFromEnv(env);
    const store = await KycCaseStore.connect(databaseUrl);
    // Boot the retention/destruction sweep (VERI-S1-WP4). Unref'd timer — never
    // keeps the process alive on its own; sweeps tier-2 biometrics + tier-1 expiry.
    startRetentionScheduler(store);
    const captureBaseUrl =
      env.KYC_CAPTURE_BASE_URL ??
      `${(env.ISSUER_URL ?? 'http://localhost:3000').replace(/\/+$/, '')}/verify`;
    factoryEnv.inhouse = {
      mode: isProduction ? 'prod' : 'sandbox',
      store,
      masterKey,
      sessionSecret,
      webhookSecret,
      captureBaseUrl,
      ...(env.KYC_RETENTION_DAYS ? { retentionDays: Number(env.KYC_RETENTION_DAYS) } : {}),
    };
  }

  const provider = selectKycProvider(factoryEnv);
  setKycProvider(provider);
  return provider;
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

    case 'inhouse': {
      if (!env.inhouse) {
        throw new Error('KYC_PROVIDER=inhouse but in-house config is missing');
      }
      return new InhouseKycProvider(env.inhouse);
    }

    default:
      throw new Error(
        `KYC_PROVIDER="${name}" is not a recognised provider. ` +
          'Expected one of: sumsub, clear, mock.',
      );
  }
}
