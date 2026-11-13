/**
 * Regression net for the identity layer: every registered client still
 * completes the OIDC Authorization Code + PKCE flow end to end (sign-in page,
 * consent where the client is not first-party, code exchange, userinfo, and
 * the refresh grant where the client holds offline access), and each sign-in
 * method still signs an existing member in to their own account.
 *
 * Added with the passkey duplicate-account fix (2026-11-13) because so much
 * depends on this layer: a change to the sign-in page or the account stores
 * must not break any relying party.
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { privateKeyToAccount } from 'viem/accounts';
import { type Hex } from 'viem';
import { decodeJwt } from 'jose';
import type { PublicKeyCredentialCreationOptionsJSON, PublicKeyCredentialRequestOptionsJSON } from '@simplewebauthn/server';
import { buildConfiguration } from '../src/config.js';
import { hashPassword } from '../src/auth/password.js';
import {
  getUserStore,
  InMemoryUserStore,
  InMemoryWebAuthnCredentialStore,
  setUserStore,
  setWebAuthnStore,
} from '../src/auth/stores.js';
import { InMemoryEmailVerificationStore, setEmailVerificationStore } from '../src/auth/email-verification-pg.js';
import { resetEmailSender, setEmailSender } from '../src/email-send.js';
import {
  CookieJar,
  exchange,
  follow,
  signInOnPage,
  startAuth,
  startAuthority,
  type Client,
  type TestAuthority,
} from './helpers/browser.js';
import { SoftAuthenticator } from './helpers/soft-authenticator.js';

type ClientShape = { client_id: string; redirect_uris?: string[]; grant_types?: string[]; scope?: string };

const member = privateKeyToAccount(`0x${'f7'.repeat(32)}` as Hex);
let auth: TestAuthority;
let registered: ClientShape[];

beforeAll(async () => {
  auth = await startAuthority({ googleEnabled: false });
  registered = ((await buildConfiguration()).clients ?? []) as ClientShape[];
});
afterAll(async () => {
  resetEmailSender();
  await auth.close();
});

async function userinfo(accessToken: string): Promise<Record<string, unknown>> {
  const res = await fetch(`${auth.baseUrl}/me`, { headers: { authorization: `Bearer ${accessToken}` } });
  expect(res.status).toBe(200);
  return (await res.json()) as Record<string, unknown>;
}

describe('every registered client completes the code flow', () => {
  it('has the clients the relying parties use', () => {
    const ids = registered.map((c) => c.client_id);
    for (const id of [
      'citrate-explorer',
      'citrate-dashboard',
      'citrate-comms-web',
      'citrate-core',
      'citrate-orchard-web',
      'american-learning-federation',
      'alf-portal-web',
      'citrate-dataroom',
      'citrate-atlas',
      'memrizz',
    ]) {
      expect(ids, id).toContain(id);
    }
  });

  it('signs in with SIWE, exchanges the code, reads userinfo and refreshes, for each client', async () => {
    expect(registered.length).toBeGreaterThan(10);
    for (const c of registered) {
      const redirectUri = c.redirect_uris?.[0];
      expect(redirectUri, c.client_id).toBeTruthy();
      const offline = (c.grant_types ?? []).includes('refresh_token') && (c.scope ?? '').includes('offline_access');
      const client: Client = {
        clientId: c.client_id,
        redirectUri: redirectUri!,
        scope: ['openid', ...['wallet', 'offline_access'].filter((x) => (c.scope ?? '').includes(x) && (x !== 'offline_access' || offline))].join(' '),
      };
      const jar = new CookieJar();
      const { location, codeVerifier } = await startAuth(auth, jar, client, offline ? { prompt: 'consent' } : {});
      expect((await follow(auth, jar, client, location)).signInPage, c.client_id).toBe(true);
      const done = await follow(auth, jar, client, await signInOnPage(auth, jar, member));
      expect(done.code, c.client_id).toBeTruthy();
      const tokens = await exchange(auth, client, done.code!, codeVerifier);
      const idToken = decodeJwt(tokens.id_token);
      expect(idToken.sub, c.client_id).toBe(member.address);
      expect(idToken.aud, c.client_id).toBe(c.client_id);
      expect((await userinfo(tokens.access_token)).sub, c.client_id).toBe(member.address);
      if (offline) {
        expect(tokens.refresh_token, c.client_id).toBeTruthy();
        const r = await fetch(`${auth.baseUrl}/token`, {
          method: 'POST',
          headers: { 'content-type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: tokens.refresh_token!, client_id: c.client_id }),
        });
        expect(r.status, `${c.client_id} refresh`).toBe(200);
      }
    }
  }, 60_000);
});

describe('each sign-in method signs an existing member in to their own account', () => {
  const EXPLORER: Client = { clientId: 'citrate-explorer', redirectUri: 'http://localhost:3001/auth/callback' };
  let codes: string[];

  beforeEach(() => {
    setUserStore(new InMemoryUserStore());
    setWebAuthnStore(new InMemoryWebAuthnCredentialStore());
    setEmailVerificationStore(new InMemoryEmailVerificationStore());
    codes = [];
    setEmailSender(async (msg) => {
      const m = /(\d{6})/.exec(msg.subject);
      if (m) codes.push(m[1]);
      return true;
    });
  });

  async function page() {
    const jar = new CookieJar();
    const { location, codeVerifier } = await startAuth(auth, jar, EXPLORER);
    expect((await follow(auth, jar, EXPLORER, location)).signInPage).toBe(true);
    return { jar, codeVerifier };
  }
  async function post(jar: CookieJar, path: string, body: unknown) {
    const res = await fetch(`${auth.baseUrl}${path}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: jar.header() },
      body: JSON.stringify(body),
    });
    jar.absorb(res);
    return res;
  }
  async function finish(jar: CookieJar, codeVerifier: string, redirectTo: string): Promise<string> {
    const done = await follow(auth, jar, EXPLORER, redirectTo);
    return decodeJwt((await exchange(auth, EXPLORER, done.code!, codeVerifier)).id_token).sub as string;
  }

  it('email + password: sign-up with a code, then sign-in with the password', async () => {
    const a = await page();
    expect((await post(a.jar, '/auth/password/register', { email: 'pw@citrate.example', password: 'correct horse battery staple' })).status).toBe(200);
    const v = await post(a.jar, '/auth/password/verify', { email: 'pw@citrate.example', code: codes.at(-1) });
    expect(v.status).toBe(200);
    const created = (await v.json()) as { userId: string; redirectTo: string };
    expect(await finish(a.jar, a.codeVerifier, created.redirectTo)).toBe(created.userId);

    const b = await page();
    const l = await post(b.jar, '/auth/password/login', { email: 'pw@citrate.example', password: 'correct horse battery staple' });
    expect(l.status).toBe(200);
    expect(await finish(b.jar, b.codeVerifier, ((await l.json()) as { redirectTo: string }).redirectTo)).toBe(created.userId);
  });

  it('passkey: an account with a passkey signs in to itself', async () => {
    const rec = await getUserStore().createWithEmailPassword({
      email: 'pk@citrate.example',
      passwordHash: await hashPassword('correct horse battery staple'),
    });
    await getUserStore().markEmailVerified(rec.id);
    const device = new SoftAuthenticator();
    const a = await page();
    await post(a.jar, '/auth/webauthn/signup-email', { email: 'pk@citrate.example' });
    const opts = (await (await post(a.jar, '/auth/webauthn/signup-options', { email: 'pk@citrate.example', code: codes.at(-1) })).json()) as
      PublicKeyCredentialCreationOptionsJSON;
    expect((await post(a.jar, '/auth/webauthn/signup-verify', { response: device.create(opts, auth.baseUrl) })).status).toBe(201);

    const b = await page();
    const aopts = (await (await post(b.jar, '/auth/webauthn/authenticate-options', {})).json()) as PublicKeyCredentialRequestOptionsJSON;
    const res = await post(b.jar, '/auth/webauthn/authenticate-verify', { response: device.get(aopts, auth.baseUrl) });
    expect(res.status).toBe(200);
    expect(await finish(b.jar, b.codeVerifier, ((await res.json()) as { redirectTo: string }).redirectTo)).toBe(rec.id);
  });

  it('wallet (SIWE): the wallet address is the account', async () => {
    const a = await page();
    expect(await finish(a.jar, a.codeVerifier, await signInOnPage(auth, a.jar, member))).toBe(member.address);
  });
});
