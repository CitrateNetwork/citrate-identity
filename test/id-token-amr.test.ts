/**
 * ID tokens carry how the member signed in: `amr` and `acr` from the login,
 * plus `auth_time` (2026-11-13: owner locked out of www.citrate.ai/admin/orchard).
 *
 * The sign-in routes set `amr` / `acr` on the login result (webauthn → amr
 * ["webauthn"], password → ["pwd"], SIWE → ["siwe"]), but neither claim was
 * listed under any scope, so panva's claim mask dropped them and discovery's
 * `claims_supported` did not list `amr`. An RP that requires a passkey or MFA
 * sign-in (the landing admin check) could never see one and refused even right
 * after a passkey sign-in.
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { privateKeyToAccount } from 'viem/accounts';
import { type Hex } from 'viem';
import { decodeJwt } from 'jose';
import type {
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
} from '@simplewebauthn/server';
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

// Both a first-party client and the (non-first-party) landing client.
const EXPLORER: Client = { clientId: 'citrate-explorer', redirectUri: 'http://localhost:3001/auth/callback' };
const ORCHARD: Client = { clientId: 'citrate-orchard-web', redirectUri: 'https://www.citrate.ai/auth/callback' };
const wallet = privateKeyToAccount(`0x${'a7'.repeat(32)}` as Hex);

let auth: TestAuthority;
let codes: string[];

beforeAll(async () => {
  auth = await startAuthority({ googleEnabled: false });
});
afterAll(async () => {
  resetEmailSender();
  await auth.close();
});
beforeEach(() => {
  setUserStore(new InMemoryUserStore());
  setWebAuthnStore(new InMemoryWebAuthnCredentialStore());
  setEmailVerificationStore(new InMemoryEmailVerificationStore());
  codes = [];
  setEmailSender(async (msg) => {
    const m = /(\d{6})/.exec(msg.subject);
    if (m) codes.push(m[1]!);
    return true;
  });
});

/**
 * `auth_time` is unchanged by this fix: panva adds it when the RP asks for it
 * (`max_age`, as the landing admin sign-in does with max_age=0 + prompt=login).
 */
// Exactly what citrate-landing's /auth/start?admin=1 sends (the claims
// parameter is not supported here and is ignored, as before).
const ADMIN_STYLE = {
  max_age: '0',
  prompt: 'login',
  claims: JSON.stringify({ id_token: { amr: { essential: true }, auth_time: { essential: true } } }),
};

async function page(client: Client, extra: Record<string, string> = {}) {
  const jar = new CookieJar();
  const { location, codeVerifier } = await startAuth(auth, jar, client, extra);
  expect((await follow(auth, jar, client, location)).signInPage).toBe(true);
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
async function idTokenAfter(client: Client, jar: CookieJar, codeVerifier: string, redirectTo: string) {
  const done = await follow(auth, jar, client, redirectTo);
  return decodeJwt((await exchange(auth, client, done.code!, codeVerifier)).id_token);
}

async function memberWithPassword(email: string, password: string): Promise<string> {
  const rec = await getUserStore().createWithEmailPassword({ email, passwordHash: await hashPassword(password) });
  await getUserStore().markEmailVerified(rec.id);
  return rec.id;
}

describe('the ID token says how the member signed in', () => {
  for (const client of [EXPLORER, ORCHARD]) {
    it(`passkey → amr ["webauthn"] and auth_time (${client.clientId})`, async () => {
      const email = `pk-${client.clientId}@citrate.example`;
      const userId = await memberWithPassword(email, 'correct horse battery staple');
      // Register a passkey for that account through the email-code sign-up path.
      const device = new SoftAuthenticator();
      const reg = await page(EXPLORER);
      await post(reg.jar, '/auth/webauthn/signup-email', { email });
      const opts = (await (await post(reg.jar, '/auth/webauthn/signup-options', { email, code: codes.at(-1) })).json()) as
        PublicKeyCredentialCreationOptionsJSON;
      expect((await post(reg.jar, '/auth/webauthn/signup-verify', { response: device.create(opts, auth.baseUrl) })).status).toBe(201);

      const before = Math.floor(Date.now() / 1000);
      const { jar, codeVerifier } = await page(client, ADMIN_STYLE);
      const aopts = (await (await post(jar, '/auth/webauthn/authenticate-options', {})).json()) as
        PublicKeyCredentialRequestOptionsJSON;
      const res = await post(jar, '/auth/webauthn/authenticate-verify', { response: device.get(aopts, auth.baseUrl) });
      expect(res.status).toBe(200);
      const claims = await idTokenAfter(client, jar, codeVerifier, ((await res.json()) as { redirectTo: string }).redirectTo);
      expect(claims.sub).toBe(userId);
      expect(claims.amr).toEqual(['webauthn']);
      expect(claims.acr).toBe('urn:citrate:webauthn');
      expect(typeof claims.auth_time).toBe('number');
      expect(claims.auth_time as number).toBeGreaterThanOrEqual(before - 1);
    });
  }

  it('password → amr ["pwd"]', async () => {
    const email = 'pwd@citrate.example';
    await memberWithPassword(email, 'correct horse battery staple');
    const { jar, codeVerifier } = await page(ORCHARD, ADMIN_STYLE);
    const res = await post(jar, '/auth/password/login', { email, password: 'correct horse battery staple' });
    expect(res.status).toBe(200);
    const claims = await idTokenAfter(ORCHARD, jar, codeVerifier, ((await res.json()) as { redirectTo: string }).redirectTo);
    expect(claims.amr).toEqual(['pwd']);
    expect(claims.acr).toBe('urn:citrate:password');
    expect(typeof claims.auth_time).toBe('number');
  });

  it('without max_age, amr is still there (auth_time stays as before: only on request)', async () => {
    const email = 'plain@citrate.example';
    await memberWithPassword(email, 'correct horse battery staple');
    const { jar, codeVerifier } = await page(EXPLORER);
    const res = await post(jar, '/auth/password/login', { email, password: 'correct horse battery staple' });
    const claims = await idTokenAfter(EXPLORER, jar, codeVerifier, ((await res.json()) as { redirectTo: string }).redirectTo);
    expect(claims.amr).toEqual(['pwd']);
    expect(claims.auth_time).toBeUndefined();
  });

  it('wallet (SIWE) → amr ["siwe"]', async () => {
    const { jar, codeVerifier } = await page(EXPLORER);
    const claims = await idTokenAfter(EXPLORER, jar, codeVerifier, await signInOnPage(auth, jar, wallet));
    expect(claims.amr).toEqual(['siwe']);
    expect(claims.sub).toBe(wallet.address);
  });
});

describe('discovery', () => {
  it('lists amr and acr in claims_supported', async () => {
    const d = (await (await fetch(`${auth.baseUrl}/.well-known/openid-configuration`)).json()) as {
      claims_supported: string[];
    };
    expect(d.claims_supported).toContain('amr');
    expect(d.claims_supported).toContain('acr');
    expect(d.claims_supported).toContain('auth_time');
  });
});
