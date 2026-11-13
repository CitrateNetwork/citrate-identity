/**
 * Passkeys never create an account by accident (owner report, 2026-11-13).
 *
 * Two passkey "sign-ins" by the owner each created a new, email-less users
 * row. The sign-in page turned every failed or dismissed passkey prompt
 * (including "this device has no passkey for you") into "First time? Create
 * one below" with that button focused, and the create path minted a fresh
 * account from any new passkey, with no email. Covered here:
 *   - signing in with a passkey only ever signs in to the account the passkey
 *     belongs to, and an unknown passkey creates nothing;
 *   - creating an account with a passkey is its own action and needs a
 *     verified email (a one-time code bound to this sign-in);
 *   - that action on an email that already has an account adds the passkey
 *     to THAT account instead of creating a second one;
 *   - a signed-in email account can add a passkey from /account;
 *   - the sign-in page no longer steers a failed sign-in into account creation.
 */
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import type {
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
} from '@simplewebauthn/server';
import { decodeJwt } from 'jose';
import {
  getUserStore,
  getWebAuthnStore,
  InMemoryUserStore,
  InMemoryWebAuthnCredentialStore,
  setUserStore,
  setWebAuthnStore,
} from '../../src/auth/stores.js';
import type { UserRecord } from '../../src/auth/users-pg.js';
import {
  InMemoryEmailVerificationStore,
  setEmailVerificationStore,
} from '../../src/auth/email-verification-pg.js';
import { hashPassword } from '../../src/auth/password.js';
import { resetEmailSender, setEmailSender, type EmailMessage } from '../../src/email-send.js';
import {
  CookieJar,
  exchange,
  follow,
  startAuth,
  startAuthority,
  type Client,
  type TestAuthority,
} from '../helpers/browser.js';
import { SoftAuthenticator } from '../helpers/soft-authenticator.js';
import { verifyRegistration } from '../../src/auth/webauthn.js';

/** Counts every account the authority creates, by any path. */
class CountingUserStore extends InMemoryUserStore {
  created = 0;
  override async createWithEmailPassword(args: { email: string; passwordHash: string }): Promise<UserRecord> {
    this.created += 1;
    return super.createWithEmailPassword(args);
  }
  override async createWithGoogle(args: { googleSub: string; email?: string }): Promise<UserRecord> {
    this.created += 1;
    return super.createWithGoogle(args);
  }
  override async createWithFederated(args: { provider: string; providerSub: string; email?: string }): Promise<UserRecord> {
    this.created += 1;
    return super.createWithFederated(args);
  }
  override async createWithPasskey(args?: { id?: string; email?: string }): Promise<UserRecord> {
    this.created += 1;
    return super.createWithPasskey(args);
  }
}

const EXPLORER: Client = { clientId: 'citrate-explorer', redirectUri: 'http://localhost:3001/auth/callback' };

let auth: TestAuthority;
let users: CountingUserStore;
let lastCode: { to: string; code: string } | null;
let sent: EmailMessage[];

beforeAll(async () => {
  auth = await startAuthority({ googleEnabled: false });
});
afterAll(async () => {
  resetEmailSender();
  await auth.close();
});
beforeEach(() => {
  users = new CountingUserStore();
  setUserStore(users);
  setWebAuthnStore(new InMemoryWebAuthnCredentialStore());
  setEmailVerificationStore(new InMemoryEmailVerificationStore());
  lastCode = null;
  sent = [];
  setEmailSender(async (msg) => {
    sent.push(msg);
    const m = /(\d{6})/.exec(msg.subject);
    if (m) lastCode = { to: msg.to, code: m[1] };
    return true;
  });
});

/** Notices (not verification codes) sent to `to`. */
const noticesTo = (to: string) => sent.filter((m) => m.to === to && !/\d{6}/.test(m.subject));

/** A browser on the sign-in page of a fresh /auth request. */
async function onSignInPage(jar = new CookieJar()) {
  const { location, codeVerifier } = await startAuth(auth, jar, EXPLORER);
  expect((await follow(auth, jar, EXPLORER, location)).signInPage).toBe(true);
  return { jar, codeVerifier };
}

async function postJson(jar: CookieJar, path: string, body: unknown, headers: Record<string, string> = {}) {
  const res = await fetch(`${auth.baseUrl}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie: jar.header(), ...headers },
    body: JSON.stringify(body),
    redirect: 'manual',
  });
  jar.absorb(res);
  return res;
}

/** Sign in with the authenticator's passkey; return the account the RP receives. */
async function passkeySignIn(device: SoftAuthenticator, jar?: CookieJar) {
  const page = await onSignInPage(jar);
  const opts = (await (await postJson(page.jar, '/auth/webauthn/authenticate-options', {})).json()) as
    PublicKeyCredentialRequestOptionsJSON;
  const res = await postJson(page.jar, '/auth/webauthn/authenticate-verify', {
    response: device.get(opts, auth.baseUrl),
  });
  if (res.status !== 200) return { status: res.status, sub: undefined };
  const { redirectTo } = (await res.json()) as { redirectTo: string };
  const done = await follow(auth, page.jar, EXPLORER, redirectTo);
  const tokens = await exchange(auth, EXPLORER, done.code!, page.codeVerifier);
  return { status: 200, sub: decodeJwt(tokens.id_token).sub as string, jar: page.jar };
}

/** The explicit "create an account with a passkey" action, through to its end. */
async function passkeySignUp(device: SoftAuthenticator, email: string) {
  const page = await onSignInPage();
  const start = await postJson(page.jar, '/auth/webauthn/signup-email', { email });
  expect(start.status).toBe(200);
  expect(lastCode?.to).toBe(email.toLowerCase());
  const optsRes = await postJson(page.jar, '/auth/webauthn/signup-options', { email, code: lastCode!.code });
  expect(optsRes.status).toBe(200);
  const opts = (await optsRes.json()) as PublicKeyCredentialCreationOptionsJSON;
  const verify = await postJson(page.jar, '/auth/webauthn/signup-verify', {
    response: device.create(opts, auth.baseUrl),
  });
  return { page, opts, verify };
}

describe('passkey sign-in never creates an account', () => {
  it('an unknown passkey is refused and creates nothing', async () => {
    const stranger = new SoftAuthenticator();
    // A passkey the authority never registered (e.g. made for another site build).
    stranger.create(
      {
        rp: { id: '127.0.0.1', name: 'x' },
        user: { id: Buffer.from('nobody').toString('base64url'), name: 'x', displayName: 'x' },
        challenge: 'AAAA',
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      },
      auth.baseUrl,
    );
    const r = await passkeySignIn(stranger);
    expect(r.status).toBe(401);
    expect(users.created).toBe(0);
  });

  it('signs in to the account the passkey belongs to, every time', async () => {
    const device = new SoftAuthenticator();
    const { verify } = await passkeySignUp(device, 'larry@citrate.example');
    expect(verify.status).toBe(201);
    const { userId } = (await verify.json()) as { userId: string };
    expect(users.created).toBe(1);

    for (let i = 0; i < 2; i++) {
      const r = await passkeySignIn(device);
      expect(r.status).toBe(200);
      expect(r.sub).toBe(userId);
    }
    expect(users.created).toBe(1);
  });
});

describe('existing passkey accounts keep working', () => {
  it('an email-less passkey account made before this change still signs in as itself', async () => {
    const legacy = await users.createWithPasskey();
    expect(legacy.email).toBeUndefined();
    users.created = 0;
    // Its passkey, registered the old way (no email on the account).
    const device = new SoftAuthenticator();
    const challenge = Buffer.from('legacy-enrolment').toString('base64url');
    const reg = device.create(
      {
        rp: { id: '127.0.0.1', name: 'Citrate' },
        user: { id: Buffer.from(legacy.id).toString('base64url'), name: 'New Citrate user', displayName: 'New Citrate user' },
        challenge,
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      },
      auth.baseUrl,
    );
    const v = await verifyRegistration({
      rp: { rpId: '127.0.0.1', rpName: 'Citrate', expectedOrigin: auth.baseUrl },
      expectedChallenge: challenge,
      response: reg,
    });
    await getWebAuthnStore().insertCredential({
      userId: legacy.id,
      credentialId: v.credentialId,
      publicKeyCose: v.publicKeyCose,
      signCount: v.signCount,
      transports: v.transports,
    });

    const r = await passkeySignIn(device);
    expect(r.status).toBe(200);
    expect(r.sub).toBe(legacy.id);
    expect(users.created).toBe(0);
  });
});

describe('creating an account with a passkey needs a verified email', () => {
  it('refuses to start without an email code', async () => {
    const { jar } = await onSignInPage();
    const res = await postJson(jar, '/auth/webauthn/signup-options', {});
    expect(res.status).toBe(400);
    expect(((await res.json()) as { error: string }).error).toBe('email_verification_required');
    expect(users.created).toBe(0);
  });

  it('refuses a wrong code', async () => {
    const { jar } = await onSignInPage();
    await postJson(jar, '/auth/webauthn/signup-email', { email: 'a@citrate.example' });
    const wrong = lastCode!.code === '000000' ? '111111' : '000000';
    const res = await postJson(jar, '/auth/webauthn/signup-options', { email: 'a@citrate.example', code: wrong });
    expect(res.status).toBe(401);
    expect(users.created).toBe(0);
  });

  it('refuses a code issued to another sign-in', async () => {
    const a = await onSignInPage();
    await postJson(a.jar, '/auth/webauthn/signup-email', { email: 'a@citrate.example' });
    const b = await onSignInPage();
    const res = await postJson(b.jar, '/auth/webauthn/signup-options', {
      email: 'a@citrate.example',
      code: lastCode!.code,
    });
    expect(res.status).toBe(401);
  });

  it('creates one account whose email is verified, and names the passkey after it', async () => {
    const device = new SoftAuthenticator();
    const { opts, verify } = await passkeySignUp(device, 'New.Member@Citrate.example');
    expect(opts.user.name).toBe('new.member@citrate.example');
    expect(verify.status).toBe(201);
    const { userId } = (await verify.json()) as { userId: string };
    const rec = await getUserStore().findById(userId);
    expect(rec?.email).toBe('new.member@citrate.example');
    expect(rec?.emailVerified).toBe(true);
    expect(users.created).toBe(1);
  });

  it('on an email that already has an account, adds the passkey to that account', async () => {
    const existing = await users.createWithEmailPassword({
      email: 'larry@citrate.example',
      passwordHash: await hashPassword('correct horse battery staple'),
    });
    await users.markEmailVerified(existing.id);
    users.created = 0;

    const device = new SoftAuthenticator();
    const { opts, verify } = await passkeySignUp(device, 'larry@citrate.example');
    expect(Buffer.from(opts.user.id, 'base64url').toString('utf8')).toBe(existing.id);
    expect(verify.status).toBe(201);
    expect(((await verify.json()) as { userId: string }).userId).toBe(existing.id);
    expect(users.created).toBe(0);
    expect((await passkeySignIn(device)).sub).toBe(existing.id);
    // The owner hears about a passkey added to their existing account.
    expect(noticesTo('larry@citrate.example').map((m) => m.subject)).toEqual([
      expect.stringMatching(/passkey was added/i),
    ]);
  });

  it('sends no "passkey added" notice for a brand-new account', async () => {
    await passkeySignUp(new SoftAuthenticator(), 'fresh@citrate.example');
    expect(noticesTo('fresh@citrate.example')).toHaveLength(0);
  });

  it('the code is single-use', async () => {
    const page = await onSignInPage();
    await postJson(page.jar, '/auth/webauthn/signup-email', { email: 'once@citrate.example' });
    const code = lastCode!.code;
    expect((await postJson(page.jar, '/auth/webauthn/signup-options', { email: 'once@citrate.example', code })).status).toBe(200);
    expect((await postJson(page.jar, '/auth/webauthn/signup-options', { email: 'once@citrate.example', code })).status).toBe(401);
  });
});

describe('a signed-in email account can add a passkey', () => {
  async function signedInWithPassword(email: string, password: string) {
    const rec = await users.createWithEmailPassword({ email, passwordHash: await hashPassword(password) });
    await users.markEmailVerified(rec.id);
    const page = await onSignInPage();
    const res = await postJson(page.jar, '/auth/password/login', { email, password });
    expect(res.status).toBe(200);
    const { redirectTo } = (await res.json()) as { redirectTo: string };
    await follow(auth, page.jar, EXPLORER, redirectTo);
    return { jar: page.jar, userId: rec.id };
  }

  async function accountHtml(jar: CookieJar): Promise<string> {
    return (await fetch(`${auth.baseUrl}/account`, { headers: { cookie: jar.header() } })).text();
  }

  function csrfFrom(html: string): string {
    const m = /id="add-passkey"[^>]*data-csrf="([^"]+)"/.exec(html);
    if (!m) throw new Error('no add-passkey control');
    return m[1];
  }

  it('offers "Add a passkey" and adds one to that account', async () => {
    const { jar, userId } = await signedInWithPassword('owner@citrate.example', 'correct horse battery staple');
    const html = await accountHtml(jar);
    expect(html).toContain('Add a passkey');
    expect(html).toContain('<script src="/account/passkey.js"');
    const csrf = csrfFrom(html);
    const origin = { origin: auth.baseUrl };

    const optsRes = await postJson(jar, '/account/passkey/options', { csrf }, origin);
    expect(optsRes.status).toBe(200);
    const opts = (await optsRes.json()) as PublicKeyCredentialCreationOptionsJSON;
    expect(Buffer.from(opts.user.id, 'base64url').toString('utf8')).toBe(userId);
    expect(opts.user.name).toBe('owner@citrate.example');

    const device = new SoftAuthenticator();
    const verify = await postJson(jar, '/account/passkey/verify', { csrf, response: device.create(opts, auth.baseUrl) }, origin);
    expect(verify.status).toBe(200);
    expect(await getWebAuthnStore().listByUserId(userId)).toHaveLength(1);
    users.created = 0;
    expect((await passkeySignIn(device)).sub).toBe(userId);
    expect(users.created).toBe(0);
  });

  it('serves the page script same-origin', async () => {
    const res = await fetch(`${auth.baseUrl}/account/passkey.js`);
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toMatch(/javascript/);
    expect(await res.text()).toContain('/account/passkey/options');
  });

  it('refuses without the page token, cross-site, or signed out', async () => {
    const { jar } = await signedInWithPassword('t@citrate.example', 'correct horse battery staple');
    const csrf = csrfFrom(await accountHtml(jar));
    expect((await postJson(jar, '/account/passkey/options', {}, { origin: auth.baseUrl })).status).toBe(403);
    expect((await postJson(jar, '/account/passkey/options', { csrf }, { origin: 'https://evil.example' })).status).toBe(403);
    expect((await postJson(new CookieJar(), '/account/passkey/options', { csrf }, { origin: auth.baseUrl })).status).toBe(401);
  });

  it('emails the account owner when a passkey is added', async () => {
    const { jar } = await signedInWithPassword('notify@citrate.example', 'correct horse battery staple');
    const csrf = csrfFrom(await accountHtml(jar));
    const origin = { origin: auth.baseUrl };
    const opts = (await (await postJson(jar, '/account/passkey/options', { csrf }, origin)).json()) as
      PublicKeyCredentialCreationOptionsJSON;
    expect(noticesTo('notify@citrate.example')).toHaveLength(0);
    const v = await postJson(jar, '/account/passkey/verify', { csrf, response: new SoftAuthenticator().create(opts, auth.baseUrl) }, origin);
    expect(v.status).toBe(200);
    const notices = noticesTo('notify@citrate.example');
    expect(notices).toHaveLength(1);
    expect(notices[0]!.subject).toMatch(/passkey was added/i);
    expect(notices[0]!.text).toMatch(/security@citrate\.ai/);
  });

  describe('needs a recent sign-in', () => {
    afterEach(() => vi.useRealTimers());

    async function sixMinutesLater() {
      vi.useFakeTimers({ toFake: ['Date'] });
      vi.setSystemTime(Date.now() + 6 * 60_000);
    }

    it('refuses to add a passkey on a sign-in older than 5 minutes, and offers to confirm instead', async () => {
      const { jar, userId } = await signedInWithPassword('stale@citrate.example', 'correct horse battery staple');
      const csrf = csrfFrom(await accountHtml(jar));
      await sixMinutesLater();
      const html = await accountHtml(jar);
      expect(html).not.toContain('id="add-passkey"');
      expect(html).toContain('href="/account/reauth"');
      const origin = { origin: auth.baseUrl };
      const res = await postJson(jar, '/account/passkey/options', { csrf }, origin);
      expect(res.status).toBe(401);
      expect(((await res.json()) as { error: string }).error).toBe('reauth_required');
      // Nor can a ceremony begun earlier be finished late.
      expect(await getWebAuthnStore().listByUserId(userId)).toHaveLength(0);
    });

    it('refuses to finish a ceremony once the sign-in has aged past 5 minutes', async () => {
      const { jar, userId } = await signedInWithPassword('late@citrate.example', 'correct horse battery staple');
      const csrf = csrfFrom(await accountHtml(jar));
      const origin = { origin: auth.baseUrl };
      const opts = (await (await postJson(jar, '/account/passkey/options', { csrf }, origin)).json()) as
        PublicKeyCredentialCreationOptionsJSON;
      await sixMinutesLater();
      const v = await postJson(jar, '/account/passkey/verify', { csrf, response: new SoftAuthenticator().create(opts, auth.baseUrl) }, origin);
      expect(v.status).toBe(401);
      expect(await getWebAuthnStore().listByUserId(userId)).toHaveLength(0);
    });

    it('/account/reauth asks for the sign-in again, then adding works', async () => {
      const email = 'again@citrate.example';
      const password = 'correct horse battery staple';
      const { jar, userId } = await signedInWithPassword(email, password);
      await sixMinutesLater();

      const start = await fetch(`${auth.baseUrl}/account/reauth`, { headers: { cookie: jar.header() }, redirect: 'manual' });
      jar.absorb(start);
      expect(start.status).toBe(302);
      const authorize = new URL(start.headers.get('location')!);
      expect(authorize.pathname).toBe('/auth');
      expect(authorize.searchParams.get('prompt')).toBe('login');
      const client = { clientId: authorize.searchParams.get('client_id')!, redirectUri: `${auth.baseUrl}/account/reauth/callback` };
      // The live session does NOT skip the sign-in page.
      expect((await follow(auth, jar, client, authorize.toString())).signInPage).toBe(true);
      const login = await postJson(jar, '/auth/password/login', { email, password });
      expect(login.status).toBe(200);
      const back = await follow(auth, jar, client, ((await login.json()) as { redirectTo: string }).redirectTo);
      const cb = await fetch(back.url!, { headers: { cookie: jar.header() }, redirect: 'manual' });
      jar.absorb(cb);
      expect(cb.status).toBe(302);
      expect(cb.headers.get('location')).toBe('/account');

      const csrf = csrfFrom(await accountHtml(jar));
      const origin = { origin: auth.baseUrl };
      const opts = (await (await postJson(jar, '/account/passkey/options', { csrf }, origin)).json()) as
        PublicKeyCredentialCreationOptionsJSON;
      const v = await postJson(jar, '/account/passkey/verify', { csrf, response: new SoftAuthenticator().create(opts, auth.baseUrl) }, origin);
      expect(v.status).toBe(200);
      expect(await getWebAuthnStore().listByUserId(userId)).toHaveLength(1);
    });

    it('/account/reauth/callback refuses a state this browser did not start', async () => {
      const { jar } = await signedInWithPassword('state@citrate.example', 'correct horse battery staple');
      const cb = await fetch(`${auth.baseUrl}/account/reauth/callback?state=forged&code=x`, {
        headers: { cookie: jar.header() },
        redirect: 'manual',
      });
      expect(cb.status).toBe(400);
    });
  });

  it('refuses a registration answering a different challenge', async () => {
    const { jar, userId } = await signedInWithPassword('c@citrate.example', 'correct horse battery staple');
    const csrf = csrfFrom(await accountHtml(jar));
    const origin = { origin: auth.baseUrl };
    const opts = (await (await postJson(jar, '/account/passkey/options', { csrf }, origin)).json()) as
      PublicKeyCredentialCreationOptionsJSON;
    const forged = new SoftAuthenticator().create({ ...opts, challenge: 'Zm9yZ2Vk' }, auth.baseUrl);
    expect((await postJson(jar, '/account/passkey/verify', { csrf, response: forged }, origin)).status).toBe(400);
    expect(await getWebAuthnStore().listByUserId(userId)).toHaveLength(0);
  });
});

describe('the sign-in page', () => {
  it('does not steer a failed passkey sign-in into creating an account', async () => {
    const { jar } = await onSignInPage();
    const loc = (await startAuth(auth, jar, EXPLORER)).location;
    const html = await (await fetch(new URL(loc, auth.baseUrl), { headers: { cookie: jar.header() } })).text();
    expect(html).not.toContain('First time? Create one below');
    expect(html).not.toContain('offerPasskeySignup');
    // Creating an account is its own, labelled action that asks for an email.
    expect(html).toContain('Create an account with a passkey');
    expect(html).toMatch(/id="signup-passkey-email"[^>]*type="email"/);
  });
});

describe('signup challenge storage', () => {
  it('carries the verified email and existing-account flag across instances (Redis)', async () => {
    const { default: RedisMock } = await import('ioredis-mock');
    const { RedisChallengeStore, InMemoryChallengeStore } = await import('../../src/auth/webauthn-routes.js');
    const redis = new RedisMock() as unknown as import('../../src/redis.js').RedisLike;
    await new RedisChallengeStore(redis).put('signup:x', 'chal', 'user-1', { email: 'a@citrate.example', existing: true });
    expect(await new RedisChallengeStore(redis).take('signup:x')).toMatchObject({
      challenge: 'chal',
      userId: 'user-1',
      email: 'a@citrate.example',
      existing: true,
    });
    const mem = new InMemoryChallengeStore();
    await mem.put('signup:y', 'chal', 'user-2', { email: 'b@citrate.example', existing: false });
    expect(await mem.take('signup:y')).toMatchObject({ userId: 'user-2', email: 'b@citrate.example', existing: false });
  });
});
