/**
 * PBA-L3a-013 (INFO) — identity hardening notes:
 *   1. the account page back-link accepted ANY *.vercel.app host;
 *   2. session / grant / interaction TTLs were library defaults;
 *   3. passkey challenges lived in one process (broken behind >1 instance);
 *   4. every OAuth provider's state shared one Redis namespace.
 */
import { describe, expect, it } from 'vitest';
import RedisMock from 'ioredis-mock';
import type { RedisLike } from '../src/redis.js';
import { validatedBackLink, CITRATE_VERCEL_HOSTS } from '../src/account-routes.js';
import { buildConfiguration } from '../src/config.js';
import { InMemoryChallengeStore, RedisChallengeStore } from '../src/auth/webauthn-routes.js';
import { RedisStateStore } from '../src/auth/google-routes.js';

describe('1. account back-link', () => {
  it('accepts citrate.ai and the Citrate Vercel projects only', () => {
    expect(validatedBackLink('https://docs.citrate.ai/x')).toBe('https://docs.citrate.ai/x');
    expect(validatedBackLink('https://citrate.ai/')).toBe('https://citrate.ai/');
    for (const h of CITRATE_VERCEL_HOSTS) expect(validatedBackLink(`https://${h}/`)).toBe(`https://${h}/`);
    expect(validatedBackLink('https://evil-citrate.vercel.app/')).toBeUndefined();
    expect(validatedBackLink('https://anything.vercel.app/')).toBeUndefined();
    expect(validatedBackLink('https://evilcitrate.ai/')).toBeUndefined();
    expect(validatedBackLink('http://docs.citrate.ai/')).toBeUndefined();
    expect(validatedBackLink('not a url')).toBeUndefined();
    expect(validatedBackLink(undefined)).toBeUndefined();
  });
});

describe('1b. back-link through the real /account page', () => {
  it('a look-alike *.vercel.app return_to is not rendered as a link; a Citrate one is', async () => {
    const { createServer } = await import('node:http');
    const { InMemoryHandoffStore } = await import('../src/handoff-store.js');
    const { createProvider } = await import('../src/server.js');
    const handoffs = new InMemoryHandoffStore();
    const probe = createServer();
    await new Promise<void>((r) => probe.listen(0, '127.0.0.1', r));
    const { port } = probe.address() as import('node:net').AddressInfo;
    probe.close();
    const baseUrl = `http://127.0.0.1:${port}`;
    const p = await createProvider(baseUrl, { googleEnabled: false, handoffStore: handoffs });
    const server = createServer(p.callback());
    await new Promise<void>((r) => server.listen(port, '127.0.0.1', r));
    try {
      const page = async (rt: string) =>
        (await fetch(`${baseUrl}/account?handoff=${await handoffs.issue('0xabc')}&return_to=${encodeURIComponent(rt)}`)).text();
      expect(await page('https://citrate-login.vercel.app/steal')).not.toContain('citrate-login.vercel.app');
      expect(await page('https://citrate-atlas.vercel.app/back')).toContain('citrate-atlas.vercel.app/back');
    } finally {
      await new Promise<void>((r) => server.close(() => r()));
    }
  }, 30_000);
});

describe('2. explicit TTLs', () => {
  it('pins Session, Grant and Interaction lifetimes', async () => {
    const conf = (await buildConfiguration()) as { ttl: Record<string, number> };
    expect(conf.ttl.Session).toBe(14 * 24 * 60 * 60);
    expect(conf.ttl.Grant).toBe(14 * 24 * 60 * 60);
    expect(conf.ttl.Interaction).toBe(60 * 60);
    expect(conf.ttl.Session).toBeLessThanOrEqual(conf.ttl.RefreshToken!);
  });
});

describe('3. passkey challenges shared across instances', () => {
  it('a challenge put by instance A is taken once by instance B (Redis)', async () => {
    const redis = new RedisMock() as unknown as RedisLike;
    const a = new RedisChallengeStore(redis);
    const b = new RedisChallengeStore(redis);
    await a.put('auth:uid-1', 'chal-1', 'user-1');
    expect(await b.take('auth:uid-1')).toMatchObject({ challenge: 'chal-1', userId: 'user-1' });
    expect(await a.take('auth:uid-1')).toBeUndefined();
    await a.put('auth:uid-2', 'chal-2');
    const t = await b.take('auth:uid-2');
    expect(t).toMatchObject({ challenge: 'chal-2' });
    expect(t).not.toHaveProperty('userId');
  });
  it('expires via Redis TTL; corrupt entries read as absent', async () => {
    const redis = new RedisMock() as unknown as RedisLike & { pttl(k: string): Promise<number> };
    const s = new RedisChallengeStore(redis);
    await s.put('reg:u', 'c');
    const ttl = await redis.pttl('webauthn_challenge:reg:u');
    expect(ttl).toBeGreaterThan(0);
    expect(ttl).toBeLessThanOrEqual(5 * 60 * 1000);
    await redis.set('webauthn_challenge:bad', '{not json');
    expect(await s.take('bad')).toBeUndefined();
    await redis.set('webauthn_challenge:bad2', '{"challenge":5}');
    expect(await s.take('bad2')).toBeUndefined();
  });
  it('the in-memory store keeps the same single-use contract', async () => {
    const m = new InMemoryChallengeStore();
    await m.put('k', 'c');
    expect(await m.take('k')).toMatchObject({ challenge: 'c' });
    expect(await m.take('k')).toBeUndefined();
  });
});

describe('4. OAuth state namespaces', () => {
  it('a state minted under one provider prefix cannot be taken under another', async () => {
    const redis = new RedisMock() as unknown as RedisLike;
    const google = new RedisStateStore(redis);
    const github = new RedisStateStore(redis, 'oauth_state:github:');
    await google.put('s1', { interactionUid: 'u', nonce: 'n', codeVerifier: 'v' } as never);
    expect(await github.take('s1')).toBeUndefined();
    expect(await google.take('s1')).toBeDefined();
    await github.put('s2', { interactionUid: 'u', nonce: 'n', codeVerifier: 'v' } as never);
    expect(await google.take('s2')).toBeUndefined();
    expect(await github.take('s2')).toBeDefined();
  });
  it('the OAuth2 providers use a per-provider prefix', async () => {
    const { readFileSync } = await import('node:fs');
    const src = readFileSync(new URL('../src/auth/oauth2-provider.ts', import.meta.url), 'utf8');
    expect(src).toMatch(/new RedisStateStore\(cfg\.redis, `oauth_state:\$\{cfg\.name\}:`\)/);
  });
});
