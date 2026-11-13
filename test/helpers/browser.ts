/**
 * A real browser, driven over HTTP: a cookie jar, the Authorization Code + PKCE
 * request, redirect following, and the SIWE sign-in the interaction page runs.
 * Shared by the sign-out and account-choice tests, which need several
 * independent "browsers" signing in as different wallets.
 */
import { createHash, randomBytes } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { SiweMessage } from 'siwe';
import type { privateKeyToAccount } from 'viem/accounts';
import type Provider from 'oidc-provider';
import { createProvider, type CreateProviderOptions } from '../../src/server.js';
import { CITRATE_CHAIN_ID } from '../../src/siwe.js';

export type Signer = ReturnType<typeof privateKeyToAccount>;
export type Client = { clientId: string; redirectUri: string; scope?: string };

export class CookieJar {
  private readonly jar = new Map<string, string>();
  /** Raw `Set-Cookie` lines from the last absorbed response. */
  lastSetCookies: string[] = [];
  absorb(res: Response): void {
    const setCookies = res.headers.getSetCookie();
    this.lastSetCookies = setCookies;
    for (const sc of setCookies) {
      const [pair] = sc.split(';');
      const eq = pair.indexOf('=');
      if (eq === -1) continue;
      const name = pair.slice(0, eq).trim();
      const value = pair.slice(eq + 1).trim();
      const expired = /expires=Thu, 01 Jan 1970/i.test(sc);
      if (value === '' || value === 'undefined' || expired) this.jar.delete(name);
      else this.jar.set(name, value);
    }
  }
  has(name: string): boolean {
    return this.jar.has(name);
  }
  header(): string {
    return Array.from(this.jar.entries())
      .map(([k, v]) => `${k}=${v}`)
      .join('; ');
  }
}

export interface TestAuthority {
  baseUrl: string;
  host: string;
  provider: Provider;
  close(): Promise<void>;
}

export async function startAuthority(options: CreateProviderOptions = {}): Promise<TestAuthority> {
  const probe = createServer();
  await new Promise<void>((res) => probe.listen(0, '127.0.0.1', res));
  const { port } = probe.address() as AddressInfo;
  probe.close();
  const baseUrl = `http://127.0.0.1:${port}`;
  const provider = await createProvider(baseUrl, options);
  const server: Server = createServer(provider.callback());
  await new Promise<void>((res) => server.listen(port, '127.0.0.1', res));
  return {
    baseUrl,
    host: `127.0.0.1:${port}`,
    provider,
    close: () => new Promise<void>((res, rej) => server.close((err) => (err ? rej(err) : res()))),
  };
}

function base64url(buf: Buffer): string {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Start /auth with the browser's cookies; return the first redirect target. */
export async function startAuth(
  auth: TestAuthority,
  jar: CookieJar,
  client: Client,
  extra: Record<string, string> = {},
) {
  const codeVerifier = base64url(randomBytes(32));
  const codeChallenge = base64url(createHash('sha256').update(codeVerifier).digest());
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: client.clientId,
    redirect_uri: client.redirectUri,
    scope: client.scope ?? 'openid profile wallet',
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
    state: base64url(randomBytes(16)),
    nonce: base64url(randomBytes(24)),
    ...extra,
  });
  const res = await fetch(`${auth.baseUrl}/auth?${params}`, {
    headers: { cookie: jar.header() },
    redirect: 'manual',
  });
  jar.absorb(res);
  return { status: res.status, location: res.headers.get('location') ?? '', codeVerifier, res };
}

/**
 * Follow redirects until the client callback (returns the code) or a rendered
 * sign-in page (returns `{ signInPage: true }`). panva's own auto-submitted
 * forms (account switch) are posted the way a browser would.
 */
export async function follow(auth: TestAuthority, jar: CookieJar, client: Client, location: string) {
  for (let hop = 0; hop < 12; hop++) {
    const url = location.startsWith('http') ? location : `${auth.baseUrl}${location}`;
    if (url.startsWith(client.redirectUri)) {
      return { code: new URL(url).searchParams.get('code') ?? undefined, signInPage: false };
    }
    const res = await fetch(url, { headers: { cookie: jar.header() }, redirect: 'manual' });
    jar.absorb(res);
    if (res.status === 200) {
      const html = await res.text();
      // A non-first-party client's consent page: approve it as the member would.
      if (html.includes("fetch('/consent/approve'")) {
        const approve = await fetch(`${auth.baseUrl}/consent/approve`, {
          method: 'POST',
          headers: { 'content-type': 'application/json', cookie: jar.header() },
          body: '{}',
        });
        jar.absorb(approve);
        location = ((await approve.json()) as { redirectTo: string }).redirectTo;
        continue;
      }
      const form =/<form method="post" action="([^"]+)">([\s\S]*?)<\/form>/.exec(html);
      if (form) {
        const post = await fetch(form[1], {
          method: 'POST',
          headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: jar.header() },
          body: hiddenFields(form[2]).toString(),
          redirect: 'manual',
        });
        jar.absorb(post);
        location = post.headers.get('location') ?? '';
        continue;
      }
      return { code: undefined, signInPage: true };
    }
    if (res.status !== 302 && res.status !== 303) {
      throw new Error(`unexpected ${res.status} at ${url}: ${await res.text()}`);
    }
    location = res.headers.get('location') ?? '';
  }
  throw new Error('redirect chain did not end');
}

/** The hidden `<input>` fields inside a chunk of form HTML. */
export function hiddenFields(formHtml: string): URLSearchParams {
  const fields = new URLSearchParams();
  for (const m of formHtml.matchAll(/<input type="hidden" name="([^"]+)" value="([^"]*)"\s*\/?>/g)) {
    fields.set(m[1], m[2]);
  }
  return fields;
}

/** Complete the rendered sign-in page with a SIWE signature from `who`. */
export async function signInOnPage(auth: TestAuthority, jar: CookieJar, who: Signer): Promise<string> {
  const challengeRes = await fetch(`${auth.baseUrl}/siwe/challenge`, { headers: { cookie: jar.header() } });
  jar.absorb(challengeRes);
  const { nonce } = (await challengeRes.json()) as { nonce: string };
  const issuedAt = new Date();
  const message = new SiweMessage({
    domain: auth.host,
    address: who.address,
    statement: 'Sign in to Citrate',
    uri: auth.baseUrl,
    version: '1',
    chainId: CITRATE_CHAIN_ID,
    nonce,
    issuedAt: issuedAt.toISOString(),
    expirationTime: new Date(issuedAt.getTime() + 10 * 60 * 1000).toISOString(),
  }).prepareMessage();
  const signature = await who.signMessage({ message });
  const verifyRes = await fetch(`${auth.baseUrl}/siwe/verify`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie: jar.header() },
    body: JSON.stringify({ message, signature }),
  });
  jar.absorb(verifyRes);
  return ((await verifyRes.json()) as { redirectTo: string }).redirectTo;
}

export interface Tokens {
  id_token: string;
  access_token: string;
  refresh_token?: string;
}

export async function exchange(
  auth: TestAuthority,
  client: Client,
  code: string,
  codeVerifier: string,
): Promise<Tokens> {
  const tokenRes = await fetch(`${auth.baseUrl}/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      client_id: client.clientId,
      redirect_uri: client.redirectUri,
      code_verifier: codeVerifier,
    }).toString(),
  });
  if (tokenRes.status !== 200) throw new Error(`token ${tokenRes.status}: ${await tokenRes.text()}`);
  return (await tokenRes.json()) as Tokens;
}

/** A fresh browser that signs in to `client` as `who`; returns its jar + tokens. */
export async function signedInBrowser(
  auth: TestAuthority,
  client: Client,
  who: Signer,
  extra: Record<string, string> = {},
  jar: CookieJar = new CookieJar(),
): Promise<{ jar: CookieJar; tokens: Tokens }> {
  const { location, codeVerifier } = await startAuth(auth, jar, client, extra);
  const first = await follow(auth, jar, client, location);
  if (!first.signInPage) throw new Error('expected the sign-in page');
  const done = await follow(auth, jar, client, await signInOnPage(auth, jar, who));
  if (!done.code) throw new Error('sign-in did not return a code');
  return { jar, tokens: await exchange(auth, client, done.code, codeVerifier) };
}
