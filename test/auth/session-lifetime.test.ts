/** The browser session's idle + absolute lifetime (auth/session-lifetime.ts). */
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { privateKeyToAccount } from 'viem/accounts';
import { type Hex } from 'viem';
import { buildConfiguration } from '../../src/config.js';
import {
  DEFAULT_SESSION_IDLE_TTL_SEC,
  sessionLifetimeFromEnv,
  sessionTtlSeconds,
} from '../../src/auth/session-lifetime.js';
import {
  CookieJar,
  follow,
  signInOnPage,
  startAuth,
  startAuthority,
  type Client,
  type TestAuthority,
} from '../helpers/browser.js';

describe('session lifetime from the environment', () => {
  it('defaults to the previous behaviour: 14 days idle, no absolute limit', () => {
    expect(DEFAULT_SESSION_IDLE_TTL_SEC).toBe(14 * 24 * 60 * 60);
    expect(sessionLifetimeFromEnv({})).toEqual({ idleSec: 14 * 24 * 60 * 60 });
  });

  it('reads the proposed production values', () => {
    expect(
      sessionLifetimeFromEnv({ SESSION_IDLE_TTL_SECONDS: '43200', SESSION_ABSOLUTE_TTL_SECONDS: '604800' }),
    ).toEqual({ idleSec: 43_200, absoluteSec: 604_800 });
  });

  it('treats an empty value as unset', () => {
    expect(sessionLifetimeFromEnv({ SESSION_IDLE_TTL_SECONDS: ' ', SESSION_ABSOLUTE_TTL_SECONDS: '' })).toEqual({
      idleSec: DEFAULT_SESSION_IDLE_TTL_SEC,
    });
  });

  for (const bad of ['0', '-5', '1.5', '12h', 'abc', '1e3']) {
    it(`refuses ${JSON.stringify(bad)}`, () => {
      expect(() => sessionLifetimeFromEnv({ SESSION_IDLE_TTL_SECONDS: bad })).toThrow(/SESSION_IDLE_TTL_SECONDS/);
      expect(() => sessionLifetimeFromEnv({ SESSION_ABSOLUTE_TTL_SECONDS: bad })).toThrow(
        /SESSION_ABSOLUTE_TTL_SECONDS/,
      );
    });
  }

  it('refuses an idle limit longer than the absolute one', () => {
    expect(() =>
      sessionLifetimeFromEnv({ SESSION_IDLE_TTL_SECONDS: '7200', SESSION_ABSOLUTE_TTL_SECONDS: '3600' }),
    ).toThrow(/must not exceed/);
    // The 14-day default idle is also checked against a shorter absolute limit.
    expect(() => sessionLifetimeFromEnv({ SESSION_ABSOLUTE_TTL_SECONDS: '3600' })).toThrow(/must not exceed/);
  });
});

describe('session record TTL', () => {
  const lifetime = { idleSec: 12 * 3600, absoluteSec: 7 * 86400 };
  const now = 1_800_000_000;

  it('is the idle window when there is no absolute limit', () => {
    expect(sessionTtlSeconds({ idleSec: 600 }, { loginTs: now - 30 * 86400 }, now)).toBe(600);
  });

  it('is the idle window for a session with no sign-in yet', () => {
    expect(sessionTtlSeconds(lifetime, {}, now)).toBe(12 * 3600);
    expect(sessionTtlSeconds(lifetime, undefined, now)).toBe(12 * 3600);
  });

  it('is the idle window early in the absolute lifetime', () => {
    expect(sessionTtlSeconds(lifetime, { loginTs: now - 3600 }, now)).toBe(12 * 3600);
  });

  it('is cut short by the absolute deadline from the last sign-in', () => {
    expect(sessionTtlSeconds(lifetime, { loginTs: now - (7 * 86400 - 600) }, now)).toBe(600);
  });

  it('expires at once (1s) past the absolute deadline', () => {
    expect(sessionTtlSeconds(lifetime, { loginTs: now - 8 * 86400 }, now)).toBe(1);
  });
});

describe('provider configuration', () => {
  afterEach(() => {
    delete process.env.SESSION_IDLE_TTL_SECONDS;
    delete process.env.SESSION_ABSOLUTE_TTL_SECONDS;
  });

  it('refuses to build with an invalid session lifetime', async () => {
    process.env.SESSION_IDLE_TTL_SECONDS = '0';
    await expect(buildConfiguration()).rejects.toThrow(/SESSION_IDLE_TTL_SECONDS/);
  });

  it('applies a configured idle lifetime to the session TTL', async () => {
    process.env.SESSION_IDLE_TTL_SECONDS = '1800';
    const conf = (await buildConfiguration()) as unknown as {
      ttl: { Session: (ctx: unknown, s: { loginTs?: number }) => number };
    };
    expect(conf.ttl.Session(undefined, { loginTs: Math.floor(Date.now() / 1000) })).toBe(1800);
  });
});

describe('the session cookie a real sign-in sets', () => {
  const ORCHARD: Client = { clientId: 'citrate-orchard-web', redirectUri: 'https://www.citrate.ai/auth/callback' };
  const alice = privateKeyToAccount(`0x${'c7'.repeat(32)}` as Hex);
  let current: TestAuthority;
  let proposed: TestAuthority;

  beforeAll(async () => {
    current = await startAuthority({ googleEnabled: false });
    process.env.SESSION_IDLE_TTL_SECONDS = '43200';
    process.env.SESSION_ABSOLUTE_TTL_SECONDS = '604800';
    try {
      proposed = await startAuthority({ googleEnabled: false });
    } finally {
      delete process.env.SESSION_IDLE_TTL_SECONDS;
      delete process.env.SESSION_ABSOLUTE_TTL_SECONDS;
    }
  });
  afterAll(async () => {
    await current.close();
    await proposed.close();
  });

  async function cookieHours(auth: TestAuthority): Promise<number> {
    const jar = new CookieJar();
    const { location } = await startAuth(auth, jar, ORCHARD);
    await follow(auth, jar, ORCHARD, location);
    const res = await fetch(new URL(await signInOnPage(auth, jar, alice), auth.baseUrl), {
      headers: { cookie: jar.header() },
      redirect: 'manual',
    });
    jar.absorb(res);
    const cookie = jar.lastSetCookies.find((c) => /^_session=/.test(c));
    expect(cookie, 'the resumed sign-in sets the session cookie').toBeTruthy();
    return (Date.parse(/expires=([^;]+)/i.exec(cookie!)![1]) - Date.now()) / 3_600_000;
  }

  it('lasts 14 days with the variables unset (unchanged)', async () => {
    const h = await cookieHours(current);
    expect(h).toBeGreaterThan(14 * 24 - 0.1);
    expect(h).toBeLessThanOrEqual(14 * 24 + 0.01);
  });

  it('lasts 12 hours with the proposed values', async () => {
    const h = await cookieHours(proposed);
    expect(h).toBeGreaterThan(11.9);
    expect(h).toBeLessThanOrEqual(12.01);
  });
});
