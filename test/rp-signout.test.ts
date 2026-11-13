import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { rootRedirectFromEnv } from '../src/http-extras.js';
import { rpLogoutSeamless } from '../src/config.js';
import { privateKeyToAccount } from 'viem/accounts';
import { type Hex } from 'viem';
import { decodeJwt } from 'jose';
import {
  CookieJar,
  exchange,
  follow,
  hiddenFields,
  signInOnPage,
  signedInBrowser,
  startAuth,
  startAuthority,
  type Client,
  type TestAuthority,
} from './helpers/browser.js';

/**
 * Signing out of www.citrate.ai must end the auth.citrate.ai session too.
 *
 * The landing site used to clear only its own cookies, so the next "Sign in"
 * completed silently as whichever account the browser last used: a member
 * with two accounts could never reach the other one. Covered here:
 *   - RP-initiated logout with a valid id_token_hint and the registered
 *     post-logout URI ends the whole browser session and lands back on the
 *     site without a confirm click;
 *   - prompt=login and prompt=select_account force the sign-in page even
 *     with a live session, so the site can offer "Use a different account";
 *   - GET / sends a stray visitor to the join page.
 * Each is behind a default-off flag: ORCHARD_SIGNED_OUT_URI (the new
 * post-logout URI), RP_LOGOUT_SEAMLESS (no confirm click),
 * OIDC_PROMPT_SELECT_ACCOUNT and AUTH_ROOT_REDIRECT_URL. With all unset the
 * authority behaves as before (last describe block).
 */

const alice = privateKeyToAccount(`0x${'c1'.repeat(32)}` as Hex);
const bob = privateKeyToAccount(`0x${'c2'.repeat(32)}` as Hex);

const ORCHARD: Client = {
  clientId: 'citrate-orchard-web',
  redirectUri: 'https://www.citrate.ai/auth/callback',
};
const SIGNED_OUT = 'https://www.citrate.ai/join?signed_out=1';

let auth: TestAuthority;

let defaults: TestAuthority;
const FLAGS = ['RP_LOGOUT_SEAMLESS', 'AUTH_ROOT_REDIRECT_URL', 'OIDC_PROMPT_SELECT_ACCOUNT', 'ORCHARD_SIGNED_OUT_URI'];

beforeAll(async () => {
  // An authority as it runs with both flags unset (the behaviour before this change)...
  for (const f of FLAGS) delete process.env[f];
  defaults = await startAuthority({ googleEnabled: false });
  // ...and one with them set, as production is meant to run.
  process.env.RP_LOGOUT_SEAMLESS = '1';
  process.env.AUTH_ROOT_REDIRECT_URL = 'https://www.citrate.ai/join';
  process.env.OIDC_PROMPT_SELECT_ACCOUNT = '1';
  process.env.ORCHARD_SIGNED_OUT_URI = '1';
  try {
    auth = await startAuthority({ googleEnabled: false });
  } finally {
    for (const f of FLAGS) delete process.env[f];
  }
});
afterAll(async () => {
  await auth.close();
  await defaults.close();
});

async function endSession(jar: CookieJar, params: Record<string, string>) {
  const res = await fetch(`${auth.baseUrl}/session/end?${new URLSearchParams(params)}`, {
    headers: { cookie: jar.header() },
    redirect: 'manual',
  });
  jar.absorb(res);
  return res;
}

/** Post the page's logout form the way the browser (or its auto-submit) would. */
async function submitLogoutForm(jar: CookieJar, html: string) {
  const form = /<form id="op\.logoutForm" method="post" action="([^"]+)">([\s\S]*?)<\/form>/.exec(html);
  if (!form) throw new Error(`no logout form in: ${html}`);
  const res = await fetch(form[1], {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: jar.header() },
    body: hiddenFields(form[2]).toString(),
    redirect: 'manual',
  });
  jar.absorb(res);
  return res;
}

async function hasLiveSession(jar: CookieJar): Promise<boolean> {
  const { location } = await startAuth(auth, jar, ORCHARD);
  return !(await follow(auth, jar, ORCHARD, location)).signInPage;
}

describe('RP-initiated logout from www.citrate.ai', () => {
  it('ends the browser session and returns to the join page with no confirm click', async () => {
    const { jar, tokens } = await signedInBrowser(auth, ORCHARD, alice);
    expect(await hasLiveSession(jar)).toBe(true);

    const res = await endSession(jar, {
      id_token_hint: tokens.id_token,
      post_logout_redirect_uri: SIGNED_OUT,
      state: 'st-1',
    });
    expect(res.status).toBe(200);
    const csp = res.headers.get('content-security-policy') ?? '';
    const nonce = /'nonce-([^']+)'/.exec(csp)?.[1];
    expect(nonce, 'the page carries a nonce-scoped CSP').toBeTruthy();
    const html = await res.text();
    // Submitted by the page itself: a nonce'd script, and the form ends the
    // whole session (logout=yes), not just this one app's authorization.
    expect(html).toContain(`<script nonce="${nonce}">`);
    expect(hiddenFields(html).get('logout')).toBe('yes');
    expect(html).not.toMatch(/<button[^>]*>\s*Yes, sign me out/i);

    const done = await submitLogoutForm(jar, html);
    expect(done.status).toBe(303);
    expect(done.headers.get('location')).toBe(`${SIGNED_OUT}&state=st-1`);

    expect(await hasLiveSession(jar)).toBe(false);
  });

  it('refuses a post-logout URI that is not registered for the client', async () => {
    const { jar, tokens } = await signedInBrowser(auth, ORCHARD, alice);
    const res = await endSession(jar, {
      id_token_hint: tokens.id_token,
      post_logout_redirect_uri: 'https://evil.example/join',
    });
    expect(res.status).toBe(400);
    expect(await hasLiveSession(jar)).toBe(true);
  });

  it('without a hint, asks the member to confirm instead of signing out silently', async () => {
    const { jar } = await signedInBrowser(auth, ORCHARD, alice);
    const res = await endSession(jar, {});
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).not.toContain('<script');
    expect(html).toMatch(/<button[^>]*form="op\.logoutForm"[^>]*>\s*Sign out/);
    // Confirming still signs the browser out.
    const done = await submitLogoutForm(jar, html);
    expect(done.status).toBe(303);
    expect(await hasLiveSession(jar)).toBe(false);
  });

  it('asks for confirmation when the hint names a different account than the browser', async () => {
    const other = await signedInBrowser(auth, ORCHARD, bob);
    const { jar } = await signedInBrowser(auth, ORCHARD, alice);
    const res = await endSession(jar, {
      id_token_hint: other.tokens.id_token,
      post_logout_redirect_uri: SIGNED_OUT,
    });
    expect(res.status).toBe(200);
    expect(await res.text()).not.toContain('<script');
    expect(await hasLiveSession(jar)).toBe(true);
  });

  it('shows a branded signed-out page when no post-logout URI is given', async () => {
    const { jar } = await signedInBrowser(auth, ORCHARD, alice);
    const done = await submitLogoutForm(jar, await (await endSession(jar, {})).text());
    const page = await fetch(new URL(done.headers.get('location')!, auth.baseUrl));
    expect(page.status).toBe(200);
    const html = await page.text();
    expect(html).toContain('signed out');
    expect(html).toContain('https://www.citrate.ai/join');
  });
});

describe('account choice on a browser that is already signed in', () => {
  for (const prompt of ['login', 'select_account']) {
    it(`prompt=${prompt} shows the sign-in page and can switch to another account`, async () => {
      const { jar } = await signedInBrowser(auth, ORCHARD, alice);
      const { status, location, codeVerifier } = await startAuth(auth, jar, ORCHARD, { prompt });
      expect([302, 303]).toContain(status);
      expect((await follow(auth, jar, ORCHARD, location)).signInPage).toBe(true);
      const done = await follow(auth, jar, ORCHARD, await signInOnPage(auth, jar, bob));
      const tokens = await exchange(auth, ORCHARD, done.code!, codeVerifier);
      expect(decodeJwt(tokens.id_token).sub).toBe(bob.address);
    });
  }

  it('prompt=select_account can also continue as the same account', async () => {
    const { jar } = await signedInBrowser(auth, ORCHARD, alice);
    const { location, codeVerifier } = await startAuth(auth, jar, ORCHARD, { prompt: 'select_account' });
    expect((await follow(auth, jar, ORCHARD, location)).signInPage).toBe(true);
    const done = await follow(auth, jar, ORCHARD, await signInOnPage(auth, jar, alice));
    const tokens = await exchange(auth, ORCHARD, done.code!, codeVerifier);
    expect(decodeJwt(tokens.id_token).sub).toBe(alice.address);
  });

  it('without a prompt, single sign-on still completes silently', async () => {
    const { jar } = await signedInBrowser(auth, ORCHARD, alice);
    expect(await hasLiveSession(jar)).toBe(true);
  });
});

describe('auth.citrate.ai root page', () => {
  it('redirects GET / to the join page', async () => {
    const res = await fetch(`${auth.baseUrl}/`, { redirect: 'manual' });
    expect(res.status).toBe(302);
    expect(res.headers.get('location')).toBe('https://www.citrate.ai/join');
  });

  it('leaves other unknown paths as 404', async () => {
    const res = await fetch(`${auth.baseUrl}/nothing-here`, { redirect: 'manual' });
    expect(res.status).toBe(404);
  });
});

describe('with RP_LOGOUT_SEAMLESS and AUTH_ROOT_REDIRECT_URL unset (current behaviour)', () => {
  async function signedIn() {
    return signedInBrowser(defaults, ORCHARD, alice);
  }

  it('does not register the new post-logout URI', async () => {
    const { jar, tokens } = await signedIn();
    const res = await fetch(
      `${defaults.baseUrl}/session/end?${new URLSearchParams({ id_token_hint: tokens.id_token, post_logout_redirect_uri: SIGNED_OUT })}`,
      { headers: { cookie: jar.header() }, redirect: 'manual' },
    );
    expect(res.status).toBe(400);
  });

  it("keeps panva's confirm page for the URIs registered before", async () => {
    const { jar, tokens } = await signedIn();
    const res = await fetch(
      `${defaults.baseUrl}/session/end?${new URLSearchParams({ id_token_hint: tokens.id_token, post_logout_redirect_uri: 'https://www.citrate.ai/' })}`,
      { headers: { cookie: jar.header() }, redirect: 'manual' },
    );
    jar.absorb(res);
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain('Yes, sign me out');
    expect(html).not.toContain('<script');
    const form = /<form id="op\.logoutForm" method="post" action="([^"]+)">([\s\S]*?)<\/form>/.exec(html)!;
    const fields = hiddenFields(form[2]);
    fields.set('logout', 'yes');
    const done = await fetch(form[1], {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: jar.header() },
      body: fields.toString(),
      redirect: 'manual',
    });
    expect(done.status).toBe(303);
    expect(done.headers.get('location')).toBe('https://www.citrate.ai/');
  });

  it('still refuses prompt=select_account', async () => {
    const { jar } = await signedIn();
    const { location } = await startAuth(defaults, jar, ORCHARD, { prompt: 'select_account' });
    const to = new URL(location, defaults.baseUrl);
    expect(to.href.startsWith(ORCHARD.redirectUri)).toBe(true);
    expect(to.searchParams.get('error')).toBe('invalid_request');
  });

  it('keeps GET / as a 404', async () => {
    expect((await fetch(`${defaults.baseUrl}/`, { redirect: 'manual' })).status).toBe(404);
  });

  it('reads the flags strictly', () => {
    expect(rpLogoutSeamless({})).toBe(false);
    expect(rpLogoutSeamless({ RP_LOGOUT_SEAMLESS: '0' })).toBe(false);
    expect(rpLogoutSeamless({ RP_LOGOUT_SEAMLESS: 'yes' })).toBe(false);
    expect(rpLogoutSeamless({ RP_LOGOUT_SEAMLESS: '1' })).toBe(true);
    expect(rpLogoutSeamless({ RP_LOGOUT_SEAMLESS: 'true' })).toBe(true);
    expect(rootRedirectFromEnv({})).toBeUndefined();
    expect(rootRedirectFromEnv({ AUTH_ROOT_REDIRECT_URL: ' ' })).toBeUndefined();
    expect(rootRedirectFromEnv({ AUTH_ROOT_REDIRECT_URL: 'https://www.citrate.ai/join' })).toBe('https://www.citrate.ai/join');
    expect(() => rootRedirectFromEnv({ AUTH_ROOT_REDIRECT_URL: 'http://www.citrate.ai/join' })).toThrow(/https/);
    expect(() => rootRedirectFromEnv({ AUTH_ROOT_REDIRECT_URL: '/join' })).toThrow(/https/);
  });
});
