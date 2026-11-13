import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { privateKeyToAccount } from 'viem/accounts';
import { type Hex } from 'viem';
import {
  CookieJar,
  follow,
  hiddenFields,
  signedInBrowser,
  startAuth,
  startAuthority,
  type Client,
  type TestAuthority,
} from './helpers/browser.js';

/**
 * The signed-in page on auth.citrate.ai (/account): who is signed in, plus
 * "Sign out" (this browser) and "Sign out of all sessions" (every browser
 * session, grant and refresh token of the account). Both are same-origin form
 * POSTs carrying a session-bound token, so another site cannot sign a member
 * out (or keep them from being signed out) by posting the form for them.
 */

const alice = privateKeyToAccount(`0x${'e1'.repeat(32)}` as Hex);
const carol = privateKeyToAccount(`0x${'e3'.repeat(32)}` as Hex);

const EXPLORER: Client = {
  clientId: 'citrate-explorer',
  redirectUri: 'http://localhost:3001/auth/callback',
  scope: 'openid offline_access',
};
const ORCHARD: Client = {
  clientId: 'citrate-orchard-web',
  redirectUri: 'https://www.citrate.ai/auth/callback',
};

let auth: TestAuthority;

beforeAll(async () => {
  auth = await startAuthority({ googleEnabled: false });
});
afterAll(async () => {
  await auth.close();
});

async function accountPage(jar: CookieJar): Promise<string> {
  const res = await fetch(`${auth.baseUrl}/account`, { headers: { cookie: jar.header() } });
  expect(res.status).toBe(200);
  return res.text();
}

/** The fields of the form posting to `action` on the account page. */
function formFor(html: string, action: string): URLSearchParams {
  const re = new RegExp(`<form method="post" action="${action.replace(/\//g, '\\/')}"[^>]*>([\\s\\S]*?)</form>`);
  const m = re.exec(html);
  if (!m) throw new Error(`no form for ${action}`);
  return hiddenFields(m[1]);
}

async function post(jar: CookieJar, path: string, fields: URLSearchParams, origin = auth.baseUrl) {
  const res = await fetch(`${auth.baseUrl}${path}`, {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      cookie: jar.header(),
      origin,
    },
    body: fields.toString(),
    redirect: 'manual',
  });
  jar.absorb(res);
  return res;
}

async function hasLiveSession(jar: CookieJar, client: Client = ORCHARD): Promise<boolean> {
  const { location } = await startAuth(auth, jar, client);
  return !(await follow(auth, jar, client, location)).signInPage;
}

async function refresh(rt: string): Promise<number> {
  const res = await fetch(`${auth.baseUrl}/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: rt, client_id: EXPLORER.clientId }),
  });
  return res.status;
}

async function introspectActive(token: string): Promise<boolean> {
  const res = await fetch(`${auth.baseUrl}/token/introspection`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ token, client_id: EXPLORER.clientId }),
  });
  return ((await res.json()) as { active: boolean }).active;
}

describe('the signed-in page', () => {
  it('shows who is signed in with both sign-out actions', async () => {
    const { jar } = await signedInBrowser(auth, ORCHARD, alice);
    const html = await accountPage(jar);
    expect(html).toContain('Signed in as');
    expect(html).toContain(alice.address);
    expect(html).toMatch(/<button[^>]*>Sign out<\/button>/);
    expect(html).toMatch(/<button[^>]*>Sign out of all sessions<\/button>/);
    expect(formFor(html, '/account/sign-out').get('csrf')).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(formFor(html, '/account/sign-out-all').get('csrf')).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it('shows no sign-out actions to a signed-out browser', async () => {
    const html = await accountPage(new CookieJar());
    expect(html).not.toContain('/account/sign-out');
    expect(html).toContain('https://www.citrate.ai/join');
  });
});

describe('Sign out (this browser)', () => {
  it('ends this browser session only', async () => {
    const here = await signedInBrowser(auth, ORCHARD, alice);
    const elsewhere = await signedInBrowser(auth, ORCHARD, alice);
    const res = await post(here.jar, '/account/sign-out', formFor(await accountPage(here.jar), '/account/sign-out'));
    expect(res.status).toBe(303);
    expect(res.headers.get('location')).toBe('/account?signed_out=1');

    const after = await fetch(`${auth.baseUrl}${res.headers.get('location')}`, { headers: { cookie: here.jar.header() } });
    expect(await after.text()).toContain("You're signed out on this browser");
    expect(await hasLiveSession(here.jar)).toBe(false);
    expect(await hasLiveSession(elsewhere.jar)).toBe(true);
  });

  it('refuses a post without the page token', async () => {
    const { jar } = await signedInBrowser(auth, ORCHARD, alice);
    const res = await post(jar, '/account/sign-out', new URLSearchParams());
    expect(res.status).toBe(403);
    expect(await hasLiveSession(jar)).toBe(true);
  });

  it('refuses a cross-site post even with a token', async () => {
    const { jar } = await signedInBrowser(auth, ORCHARD, alice);
    const fields = formFor(await accountPage(jar), '/account/sign-out');
    const res = await post(jar, '/account/sign-out', fields, 'https://evil.example');
    expect(res.status).toBe(403);
    expect(await hasLiveSession(jar)).toBe(true);
  });

  it('refuses a token minted for another browser session', async () => {
    const a = await signedInBrowser(auth, ORCHARD, alice);
    const b = await signedInBrowser(auth, ORCHARD, alice);
    const stolen = formFor(await accountPage(a.jar), '/account/sign-out');
    const res = await post(b.jar, '/account/sign-out', stolen);
    expect(res.status).toBe(403);
    expect(await hasLiveSession(b.jar)).toBe(true);
  });
});

describe('Sign out of all sessions', () => {
  it('ends every browser session, grant and refresh token of the account', async () => {
    const here = await signedInBrowser(auth, ORCHARD, carol);
    const laptop = await signedInBrowser(auth, ORCHARD, carol);
    const app = await signedInBrowser(auth, EXPLORER, carol, { prompt: 'consent' });
    expect(app.tokens.refresh_token, 'refresh token issued').toBeTruthy();
    expect(await introspectActive(app.tokens.access_token)).toBe(true);
    // Another account's sessions are untouched.
    const bystander = await signedInBrowser(auth, ORCHARD, alice);

    const res = await post(here.jar, '/account/sign-out-all', formFor(await accountPage(here.jar), '/account/sign-out-all'));
    expect(res.status).toBe(303);
    expect(res.headers.get('location')).toBe('/account?signed_out=all');

    expect(await hasLiveSession(here.jar)).toBe(false);
    expect(await hasLiveSession(laptop.jar)).toBe(false);
    expect(await hasLiveSession(app.jar, EXPLORER)).toBe(false);
    expect(await refresh(app.tokens.refresh_token!)).toBe(400);
    expect(await introspectActive(app.tokens.access_token)).toBe(false);
    expect(await hasLiveSession(bystander.jar)).toBe(true);
  });

  it('removes the Session and Grant records, not just refuses them', async () => {
    const one = await signedInBrowser(auth, ORCHARD, carol);
    const app = await signedInBrowser(auth, EXPLORER, carol, { prompt: 'consent' });
    const at = (await auth.provider.AccessToken.find(app.tokens.access_token)) as unknown as {
      grantId: string;
      sessionUid?: string;
    };
    expect(await auth.provider.Grant.find(at.grantId)).toBeTruthy();

    await post(one.jar, '/account/sign-out-all', formFor(await accountPage(one.jar), '/account/sign-out-all'));

    expect(await auth.provider.Grant.find(at.grantId)).toBeUndefined();
    expect(await auth.provider.RefreshToken.find(app.tokens.refresh_token!)).toBeUndefined();
    if (at.sessionUid) expect(await auth.provider.Session.findByUid(at.sessionUid)).toBeUndefined();
  });

  it('refuses a cross-site post', async () => {
    const { jar } = await signedInBrowser(auth, ORCHARD, alice);
    const fields = formFor(await accountPage(jar), '/account/sign-out-all');
    const res = await post(jar, '/account/sign-out-all', fields, 'https://evil.example');
    expect(res.status).toBe(403);
    expect(await hasLiveSession(jar)).toBe(true);
  });
});
