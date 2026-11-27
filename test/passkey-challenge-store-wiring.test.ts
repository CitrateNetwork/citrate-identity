/**
 * When the authority runs with a shared Redis client, passkey challenges are
 * stored in that Redis (so a challenge issued by one instance can be verified
 * by another), not in a per-process map. Drives the real
 * /auth/webauthn/authenticate-options route of a provider built by
 * createProvider with a Redis client, and checks where the challenge landed.
 * The in-memory control (no Redis) is checked too.
 */
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { createHash, randomBytes } from 'node:crypto';
import { afterEach, describe, expect, it } from 'vitest';
import RedisMock from 'ioredis-mock';
import type { RedisLike } from '../src/redis.js';
import { createProvider } from '../src/server.js';
import {
  setUserStore,
  setWebAuthnStore,
  InMemoryUserStore,
  InMemoryWebAuthnCredentialStore,
} from '../src/auth/stores.js';

function b64u(buf: Buffer): string {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

class Jar {
  private readonly m = new Map<string, string>();
  absorb(res: Response): void {
    for (const sc of res.headers.getSetCookie()) {
      const [pair] = sc.split(';');
      const i = pair.indexOf('=');
      if (i === -1) continue;
      const k = pair.slice(0, i).trim();
      const v = pair.slice(i + 1).trim();
      if (v === '' || v === 'undefined') this.m.delete(k);
      else this.m.set(k, v);
    }
  }
  header(): string {
    return [...this.m].map(([k, v]) => `${k}=${v}`).join('; ');
  }
}

let server: Server | undefined;
afterEach(async () => {
  if (server) await new Promise<void>((r) => server!.close(() => r()));
  server = undefined;
});

async function listen(redis?: RedisLike): Promise<string> {
  setUserStore(new InMemoryUserStore());
  setWebAuthnStore(new InMemoryWebAuthnCredentialStore());
  const probe = createServer();
  await new Promise<void>((r) => probe.listen(0, '127.0.0.1', r));
  const { port } = probe.address() as AddressInfo;
  probe.close();
  const baseUrl = `http://127.0.0.1:${port}`;
  const provider = await createProvider(baseUrl, { googleEnabled: false, ...(redis ? { redis } : {}) });
  server = createServer(provider.callback());
  await new Promise<void>((r) => server!.listen(port, '127.0.0.1', r));
  return baseUrl;
}

async function passkeyOptions(baseUrl: string): Promise<{ status: number; challenge?: string }> {
  const jar = new Jar();
  const verifier = b64u(randomBytes(32));
  const challenge = b64u(createHash('sha256').update(verifier).digest());
  const authUrl =
    `${baseUrl}/auth?response_type=code&client_id=citrate-explorer` +
    `&redirect_uri=${encodeURIComponent('http://localhost:3001/auth/callback')}` +
    `&scope=${encodeURIComponent('openid profile wallet')}` +
    `&code_challenge=${challenge}&code_challenge_method=S256&state=${b64u(randomBytes(16))}`;
  const a = await fetch(authUrl, { redirect: 'manual' });
  jar.absorb(a);
  const loc = a.headers.get('location');
  if (loc) {
    const p = await fetch(`${baseUrl}${new URL(loc, baseUrl).pathname}`, {
      headers: { cookie: jar.header() },
      redirect: 'manual',
    });
    jar.absorb(p);
  }
  const res = await fetch(`${baseUrl}/auth/webauthn/authenticate-options`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie: jar.header() },
    body: '{}',
    redirect: 'manual',
  });
  const body = res.status === 200 ? ((await res.json()) as { challenge: string }) : undefined;
  return { status: res.status, challenge: body?.challenge };
}

describe('passkey challenge store wiring', () => {
  it('with a Redis client, the issued challenge is stored in Redis', async () => {
    const redis = new RedisMock() as unknown as RedisLike & { keys(p: string): Promise<string[]>; get(k: string): Promise<string | null> };
    const baseUrl = await listen(redis);
    const out = await passkeyOptions(baseUrl);
    expect(out.status).toBe(200);
    const keys = await redis.keys('webauthn_challenge:*');
    expect(keys).toHaveLength(1);
    const stored = JSON.parse((await redis.get(keys[0]!)) ?? '{}') as { challenge?: string };
    expect(stored.challenge).toBe(out.challenge);
  });

  it('control: without Redis the route still issues a challenge', async () => {
    const baseUrl = await listen();
    const out = await passkeyOptions(baseUrl);
    expect(out.status).toBe(200);
    expect(typeof out.challenge).toBe('string');
  });
});
