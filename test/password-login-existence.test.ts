/**
 * POST /auth/password/login answers the same way for an unknown email, an
 * existing account whose email is not yet verified, and an existing verified
 * account that has no password: each converges on the verify-first flow (200
 * `verification_required`, no session). Only a verified account proving its
 * password signs in directly.
 */
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { createHash, randomBytes } from 'node:crypto';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createProvider } from '../src/server.js';
import {
  getUserStore,
  setUserStore,
  setWebAuthnStore,
  InMemoryUserStore,
  InMemoryWebAuthnCredentialStore,
} from '../src/auth/stores.js';
import {
  setEmailVerificationStore,
  InMemoryEmailVerificationStore,
} from '../src/auth/email-verification-pg.js';
import { setEmailSender, resetEmailSender } from '../src/email-send.js';
import { hashPassword } from '../src/auth/password.js';

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

let server: Server;
let baseUrl: string;
let sent: string[] = [];

beforeAll(async () => {
  setWebAuthnStore(new InMemoryWebAuthnCredentialStore());
  const probe = createServer();
  await new Promise<void>((r) => probe.listen(0, '127.0.0.1', r));
  const { port } = probe.address() as AddressInfo;
  probe.close();
  baseUrl = `http://127.0.0.1:${port}`;
  const provider = await createProvider(baseUrl, { googleEnabled: false });
  server = createServer(provider.callback());
  await new Promise<void>((r) => server.listen(port, '127.0.0.1', r));
});

afterAll(async () => {
  resetEmailSender();
  await new Promise<void>((r) => server.close(() => r()));
});

beforeEach(() => {
  setUserStore(new InMemoryUserStore());
  setEmailVerificationStore(new InMemoryEmailVerificationStore());
  sent = [];
  setEmailSender(async (msg) => {
    sent.push(msg.to);
    return true;
  });
});

async function interaction(): Promise<Jar> {
  const jar = new Jar();
  const challenge = b64u(createHash('sha256').update(b64u(randomBytes(32))).digest());
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
  return jar;
}

async function login(email: string, password: string): Promise<{ status: number; body: Record<string, unknown> }> {
  const jar = await interaction();
  const res = await fetch(`${baseUrl}/auth/password/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie: jar.header() },
    body: JSON.stringify({ email, password }),
    redirect: 'manual',
  });
  return { status: res.status, body: (await res.json()) as Record<string, unknown> };
}

describe('password login does not reveal whether an unverified account exists', () => {
  it('unknown email, unverified account and verified passwordless account answer identically', async () => {
    const store = getUserStore();
    await store.createWithEmailPassword({
      email: 'pending@example.com',
      passwordHash: await hashPassword('the right password here'),
    });
    const noPw = await store.createWithEmailPassword({ email: 'nopass@example.com', passwordHash: '' });
    await store.markEmailVerified(noPw.id);

    const unknown = await login('nobody@example.com', 'some password guess');
    const pending = await login('pending@example.com', 'a wrong password guess');
    const pendingRight = await login('pending@example.com', 'the right password here');
    const passwordless = await login('nopass@example.com', 'some password guess');

    for (const r of [unknown, pending, pendingRight, passwordless]) {
      expect(r.status).toBe(200);
      expect(r.body).toEqual(unknown.body);
      expect(r.body.status).toBe('verification_required');
      expect(r.body).not.toHaveProperty('redirectTo');
    }
    // Every branch went through the same issue-and-send path.
    expect(sent).toEqual(['nobody@example.com', 'pending@example.com', 'pending@example.com', 'nopass@example.com']);
  });
});
