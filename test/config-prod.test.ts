import { describe, expect, it } from 'vitest';
import {
  assertProductionConfig,
  isTrustedFirstPartyClient,
  TRUSTED_FIRST_PARTY_CLIENT_IDS,
  DEV_DEFAULT_COOKIE_KEY,
  MIN_COOKIE_KEY_LENGTH,
  type ConfigEnv,
} from '../src/config.js';

/**
 * TD-1 — fail-closed production config gate, and TD-8 — the trusted first-party
 * client set. `assertProductionConfig` is pure (env passed in), so every bad
 * branch is driven explicitly here.
 */

// A 32+ char high-entropy-ish cookie key that passes the length check.
const GOOD_KEY = 'x'.repeat(MIN_COOKIE_KEY_LENGTH);
const GOOD_KEY_2 = 'y'.repeat(MIN_COOKIE_KEY_LENGTH);

/** A fully-safe production env baseline; individual tests break one field. */
function safeProdEnv(): ConfigEnv {
  return {
    NODE_ENV: 'production',
    COOKIE_KEYS: `${GOOD_KEY},${GOOD_KEY_2}`,
    ISSUER_URL: 'https://auth.citrate.ai',
    EXPLORER_ORIGIN: 'https://explorer.citrate.ai',
    DASHBOARD_ORIGIN: 'https://dashboard.citrate.ai',
    // TD-2: KYC store must be DB-backed in production, so a safe baseline sets it.
    DATABASE_URL: 'postgres://user:pass@db.internal:5432/citrate_identity',
    // HA: Redis must back the persistent adapter + nonce + bus in production.
    REDIS_URL: 'redis://default:pass@redis.internal:6379',
  };
}

describe('assertProductionConfig — production fail-closed (TD-1)', () => {
  it('passes a fully safe production config (no throw, no warnings)', () => {
    const { warnings } = assertProductionConfig(safeProdEnv());
    expect(warnings).toEqual([]);
  });

  it('throws when CITRATE_ENV=production is the trigger (not just NODE_ENV)', () => {
    const env: ConfigEnv = {
      CITRATE_ENV: 'production',
      // everything else unsafe
    };
    expect(() => assertProductionConfig(env)).toThrow(/TD-1/);
  });

  it('throws when COOKIE_KEYS is unset', () => {
    const env = { ...safeProdEnv(), COOKIE_KEYS: undefined };
    expect(() => assertProductionConfig(env)).toThrow(/COOKIE_KEYS is unset/);
  });

  it('throws when COOKIE_KEYS equals the dev default', () => {
    const env = { ...safeProdEnv(), COOKIE_KEYS: DEV_DEFAULT_COOKIE_KEY };
    expect(() => assertProductionConfig(env)).toThrow(/dev-default key/);
  });

  it('throws when any COOKIE_KEYS entry is shorter than the minimum', () => {
    const env = { ...safeProdEnv(), COOKIE_KEYS: `${GOOD_KEY},short` };
    expect(() => assertProductionConfig(env)).toThrow(/shorter than/);
  });

  it('throws when ISSUER_URL is unset', () => {
    const env = { ...safeProdEnv(), ISSUER_URL: undefined };
    expect(() => assertProductionConfig(env)).toThrow(/ISSUER_URL is unset/);
  });

  it('throws when ISSUER_URL is localhost', () => {
    const env = { ...safeProdEnv(), ISSUER_URL: 'http://localhost:3000' };
    expect(() => assertProductionConfig(env)).toThrow(/local host/);
  });

  it('throws when ISSUER_URL is a 127.0.0.1 loopback', () => {
    const env = { ...safeProdEnv(), ISSUER_URL: 'http://127.0.0.1:3000' };
    expect(() => assertProductionConfig(env)).toThrow(/local host/);
  });

  it('throws when EXPLORER_ORIGIN is localhost', () => {
    const env = { ...safeProdEnv(), EXPLORER_ORIGIN: 'http://localhost:3001' };
    expect(() => assertProductionConfig(env)).toThrow(/EXPLORER_ORIGIN/);
  });

  it('throws when DASHBOARD_ORIGIN is localhost', () => {
    const env = { ...safeProdEnv(), DASHBOARD_ORIGIN: 'http://localhost:3002' };
    expect(() => assertProductionConfig(env)).toThrow(/DASHBOARD_ORIGIN/);
  });

  it('throws when DATABASE_URL is unset (TD-2 fail-closed)', () => {
    const env = { ...safeProdEnv(), DATABASE_URL: undefined };
    expect(() => assertProductionConfig(env)).toThrow(/DATABASE_URL is unset/);
  });

  it('throws when DATABASE_URL is blank (TD-2 fail-closed)', () => {
    const env = { ...safeProdEnv(), DATABASE_URL: '   ' };
    expect(() => assertProductionConfig(env)).toThrow(/DATABASE_URL is unset/);
  });

  it('throws when REDIS_URL is unset (HA fail-closed)', () => {
    const env = { ...safeProdEnv(), REDIS_URL: undefined };
    expect(() => assertProductionConfig(env)).toThrow(/REDIS_URL is unset/);
  });

  it('throws when REDIS_URL is blank (HA fail-closed)', () => {
    const env = { ...safeProdEnv(), REDIS_URL: '   ' };
    expect(() => assertProductionConfig(env)).toThrow(/REDIS_URL is unset/);
  });

  it('reports MULTIPLE problems in one throw when several are unsafe', () => {
    const env: ConfigEnv = {
      NODE_ENV: 'production',
      COOKIE_KEYS: DEV_DEFAULT_COOKIE_KEY,
      ISSUER_URL: 'http://localhost:3000',
      EXPLORER_ORIGIN: 'http://localhost:3001',
      DASHBOARD_ORIGIN: 'http://localhost:3002',
    };
    try {
      assertProductionConfig(env);
      throw new Error('expected assertProductionConfig to throw');
    } catch (err) {
      const msg = (err as Error).message;
      expect(msg).toContain('dev-default key');
      expect(msg).toContain('ISSUER_URL');
      expect(msg).toContain('EXPLORER_ORIGIN');
      expect(msg).toContain('DASHBOARD_ORIGIN');
    }
  });
});

describe('assertProductionConfig — non-production warns but allows (TD-1)', () => {
  it('does NOT throw in dev even with every dev default in place', () => {
    const env: ConfigEnv = {
      NODE_ENV: 'development',
      COOKIE_KEYS: DEV_DEFAULT_COOKIE_KEY,
      ISSUER_URL: 'http://localhost:3000',
      EXPLORER_ORIGIN: 'http://localhost:3001',
      DASHBOARD_ORIGIN: 'http://localhost:3002',
    };
    expect(() => assertProductionConfig(env)).not.toThrow();
  });

  it('returns the same problems as warnings in dev', () => {
    const env: ConfigEnv = {
      // NODE_ENV unset → treated as non-production
      COOKIE_KEYS: DEV_DEFAULT_COOKIE_KEY,
      ISSUER_URL: 'http://localhost:3000',
      EXPLORER_ORIGIN: 'http://localhost:3001',
      DASHBOARD_ORIGIN: 'http://localhost:3002',
    };
    const { warnings } = assertProductionConfig(env);
    expect(warnings.some((w) => /dev-default key/.test(w))).toBe(true);
    expect(warnings.some((w) => /ISSUER_URL/.test(w))).toBe(true);
    expect(warnings.some((w) => /EXPLORER_ORIGIN/.test(w))).toBe(true);
    expect(warnings.some((w) => /DASHBOARD_ORIGIN/.test(w))).toBe(true);
  });

  it('a fully safe dev config yields no warnings', () => {
    const env: ConfigEnv = {
      NODE_ENV: 'development',
      COOKIE_KEYS: `${GOOD_KEY},${GOOD_KEY_2}`,
      ISSUER_URL: 'https://auth.citrate.ai',
      EXPLORER_ORIGIN: 'https://explorer.citrate.ai',
      DASHBOARD_ORIGIN: 'https://dashboard.citrate.ai',
      // TD-2: a DB-backed KYC store is part of a fully-safe config.
      DATABASE_URL: 'postgres://user:pass@db.internal:5432/citrate_identity',
      // HA: a Redis-backed adapter/nonce/bus is part of a fully-safe config.
      REDIS_URL: 'redis://default:pass@redis.internal:6379',
    };
    expect(assertProductionConfig(env).warnings).toEqual([]);
  });

  it('warns (does not throw) in dev when REDIS_URL is unset (HA)', () => {
    const env: ConfigEnv = {
      NODE_ENV: 'development',
      COOKIE_KEYS: `${GOOD_KEY},${GOOD_KEY_2}`,
      ISSUER_URL: 'https://auth.citrate.ai',
      EXPLORER_ORIGIN: 'https://explorer.citrate.ai',
      DASHBOARD_ORIGIN: 'https://dashboard.citrate.ai',
      DATABASE_URL: 'postgres://user:pass@db.internal:5432/citrate_identity',
      // REDIS_URL intentionally unset.
    };
    const { warnings } = assertProductionConfig(env);
    expect(warnings.some((w) => /REDIS_URL is unset/.test(w))).toBe(true);
  });

  it('warns (does not throw) in dev when DATABASE_URL is unset (TD-2)', () => {
    const env: ConfigEnv = {
      NODE_ENV: 'development',
      COOKIE_KEYS: `${GOOD_KEY},${GOOD_KEY_2}`,
      ISSUER_URL: 'https://auth.citrate.ai',
      EXPLORER_ORIGIN: 'https://explorer.citrate.ai',
      DASHBOARD_ORIGIN: 'https://dashboard.citrate.ai',
      // DATABASE_URL intentionally unset.
    };
    const { warnings } = assertProductionConfig(env);
    expect(warnings.some((w) => /DATABASE_URL is unset/.test(w))).toBe(true);
  });
});

describe('KYC key custody gate (AV-S7 / HAR-244 — opt-in, default off)', () => {
  /** Safe prod baseline + a fully-configured in-house KYC provider. */
  function safeProdInhouse(): ConfigEnv {
    return {
      ...safeProdEnv(),
      KYC_PROVIDER: 'inhouse',
      KYC_MASTER_KEY: 'x'.repeat(44), // any non-empty value; length is checked at crypto load, not here
      KYC_SESSION_SECRET: 's'.repeat(32),
      KYC_INHOUSE_WEBHOOK_SECRET: 'w'.repeat(32),
    };
  }

  it('default (KYC_REQUIRE_KMS unset) → no custody problem; the live env-key path is unchanged', () => {
    const { warnings } = assertProductionConfig(safeProdInhouse());
    expect(warnings).toEqual([]); // no throw, no custody complaint
  });

  it('KYC_REQUIRE_KMS=true but source is env → REFUSES the plaintext env key in prod (throws)', () => {
    const env = { ...safeProdInhouse(), KYC_REQUIRE_KMS: 'true' }; // KYC_MASTER_KEY_SOURCE unset → env
    expect(() => assertProductionConfig(env)).toThrow(/plaintext env master key|HAR-244/);
  });

  it('KYC_REQUIRE_KMS=true AND source=kms → gate satisfied (no custody problem)', () => {
    const env = { ...safeProdInhouse(), KYC_REQUIRE_KMS: 'true', KYC_MASTER_KEY_SOURCE: 'kms' };
    const { warnings } = assertProductionConfig(env);
    expect(warnings).toEqual([]);
  });
});

describe('trusted first-party client set (TD-8)', () => {
  it('contains exactly the two first-party RPs', () => {
    expect(TRUSTED_FIRST_PARTY_CLIENT_IDS.has('citrate-explorer')).toBe(true);
    expect(TRUSTED_FIRST_PARTY_CLIENT_IDS.has('citrate-dashboard')).toBe(true);
  });

  it('isTrustedFirstPartyClient is true for both trusted RPs', () => {
    expect(isTrustedFirstPartyClient('citrate-explorer')).toBe(true);
    expect(isTrustedFirstPartyClient('citrate-dashboard')).toBe(true);
  });

  it('isTrustedFirstPartyClient is true for the citrate-core desktop client (CORE-S1.1)', () => {
    expect(isTrustedFirstPartyClient('citrate-core')).toBe(true);
  });

  it('isTrustedFirstPartyClient is false for an unknown / third-party client', () => {
    expect(isTrustedFirstPartyClient('some-third-party-app')).toBe(false);
    expect(isTrustedFirstPartyClient('')).toBe(false);
  });
});
