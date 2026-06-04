import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { createHash, randomBytes } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { privateKeyToAccount } from 'viem/accounts';
import { type Hex } from 'viem';
import { SiweMessage } from 'siwe';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import { createProvider } from '../src/server.js';
import { CITRATE_CHAIN_ID } from '../src/siwe.js';

/**
 * IDP-S5 — citrate-explorer as the first Authorization-Code + PKCE relying party,
 * authenticated end-to-end with SIWE (EIP-4361).
 *
 *   gtm-spine/features/IDP-S5-explorer-rp.feature
 *
 * The whole OIDC dance is driven over real HTTP with a manual cookie jar so the
 * interaction cookie panva sets at /auth is carried into /siwe/verify (Path A —
 * interactionResult), and the resumed interaction's session cookie is carried
 * into the auth-code redirect. A viem EOA signs the SIWE message; the resulting
 * id_token is verified against the published /jwks.
 */

let server: Server;
let baseUrl: string;
let host: string;
const account = privateKeyToAccount(`0x${'b2'.repeat(32)}` as Hex);

// The explorer relying party's registered redirect URI (dev).
const EXPLORER_REDIRECT = 'http://localhost:3001/auth/callback';

/** A tiny cookie jar: name → value, last-write-wins per name. */
class CookieJar {
  private readonly jar = new Map<string, string>();

  absorb(res: Response): void {
    // Node fetch exposes set-cookie via getSetCookie() (one entry per cookie).
    const setCookies =
      typeof (res.headers as Headers & { getSetCookie?: () => string[] })
        .getSetCookie === 'function'
        ? (res.headers as Headers & { getSetCookie: () => string[] }).getSetCookie()
        : [];
    for (const sc of setCookies) {
      const [pair] = sc.split(';');
      const eq = pair.indexOf('=');
      if (eq === -1) continue;
      const name = pair.slice(0, eq).trim();
      const value = pair.slice(eq + 1).trim();
      if (value === '' || value === 'undefined') {
        this.jar.delete(name);
      } else {
        this.jar.set(name, value);
      }
    }
  }

  header(): string {
    return Array.from(this.jar.entries())
      .map(([k, v]) => `${k}=${v}`)
      .join('; ');
  }
}

beforeAll(async () => {
  const probe = createServer();
  await new Promise<void>((res) => probe.listen(0, '127.0.0.1', res));
  const { port } = probe.address() as AddressInfo;
  probe.close();

  baseUrl = `http://127.0.0.1:${port}`;
  host = `127.0.0.1:${port}`;
  const provider = await createProvider(baseUrl);
  server = createServer(provider.callback());
  await new Promise<void>((res) => server.listen(port, '127.0.0.1', res));
});

afterAll(async () => {
  await new Promise<void>((res, rej) =>
    server.close((err) => (err ? rej(err) : res())),
  );
});

function base64url(buf: Buffer): string {
  return buf
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

describe('citrate-explorer OIDC relying party (IDP-S5)', () => {
  it('drives a full Authorization-Code + PKCE + SIWE login and mints a verifiable id_token', async () => {
    const jar = new CookieJar();

    // PKCE: S256 challenge from a high-entropy verifier.
    const codeVerifier = base64url(randomBytes(32));
    const codeChallenge = base64url(
      createHash('sha256').update(codeVerifier).digest(),
    );
    const state = base64url(randomBytes(16));

    // 1) /auth — start Authorization Code flow. panva 303s to the interaction.
    const authUrl =
      `${baseUrl}/auth?response_type=code&client_id=citrate-explorer` +
      `&redirect_uri=${encodeURIComponent(EXPLORER_REDIRECT)}` +
      `&scope=${encodeURIComponent('openid profile wallet')}` +
      `&code_challenge=${codeChallenge}&code_challenge_method=S256` +
      `&state=${state}`;
    const authRes = await fetch(authUrl, { redirect: 'manual' });
    jar.absorb(authRes);
    expect(authRes.status).toBe(303);
    const interactionLoc = authRes.headers.get('location')!;
    expect(interactionLoc).toMatch(/\/interaction\/[^/]+$/);

    // 2) GET the interaction page — confirms the custom SIWE view renders for the
    //    in-flight interaction (and carries the interaction cookie forward).
    const interactionUrl = interactionLoc.startsWith('http')
      ? interactionLoc
      : `${baseUrl}${interactionLoc}`;
    const viewRes = await fetch(interactionUrl, {
      headers: { cookie: jar.header() },
      redirect: 'manual',
    });
    jar.absorb(viewRes);
    expect(viewRes.status).toBe(200);
    const viewHtml = await viewRes.text();
    expect(viewHtml).toContain('/siwe/challenge');
    expect(viewHtml).toContain('/siwe/verify');

    // 3) /siwe/challenge — fresh nonce.
    const challengeRes = await fetch(`${baseUrl}/siwe/challenge`, {
      headers: { cookie: jar.header() },
    });
    jar.absorb(challengeRes);
    expect(challengeRes.status).toBe(200);
    const { nonce } = (await challengeRes.json()) as { nonce: string };
    expect(typeof nonce).toBe('string');

    // 4) Build + sign the EIP-4361 message bound to this authority + Citrate.
    const issuedAt = new Date();
    const expirationTime = new Date(issuedAt.getTime() + 10 * 60 * 1000);
    const siwe = new SiweMessage({
      domain: host,
      address: account.address,
      statement: 'Sign in to Citrate',
      uri: baseUrl,
      version: '1',
      chainId: CITRATE_CHAIN_ID,
      nonce,
      issuedAt: issuedAt.toISOString(),
      expirationTime: expirationTime.toISOString(),
    });
    const message = siwe.prepareMessage();
    const signature = await account.signMessage({ message });

    // 5) POST /siwe/verify WITH the interaction cookie → Path A → redirectTo.
    const verifyRes = await fetch(`${baseUrl}/siwe/verify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: jar.header() },
      body: JSON.stringify({ message, signature }),
    });
    jar.absorb(verifyRes);
    expect(verifyRes.status).toBe(200);
    const verifyJson = (await verifyRes.json()) as {
      address: string;
      redirectTo?: string;
    };
    expect(verifyJson.address).toBe(account.address);
    expect(typeof verifyJson.redirectTo).toBe('string');

    // 6) Resume the OIDC flow. GET redirectTo follows panva's internal 303
    //    chain — resume → consent interaction (auto-granted) → resume → the
    //    explorer callback carrying the authorization code + state. We follow
    //    redirects manually (cookie jar in hand) until we leave the authority's
    //    origin for the explorer's redirect_uri.
    let location = verifyJson.redirectTo!;
    let callbackLoc: string | undefined;
    for (let hop = 0; hop < 10; hop++) {
      const url = location.startsWith('http') ? location : `${baseUrl}${location}`;
      // Once panva redirects to the explorer's callback origin we stop and
      // assert on it rather than chasing a (non-existent in-test) explorer.
      if (url.startsWith(EXPLORER_REDIRECT)) {
        callbackLoc = url;
        break;
      }
      const hopRes = await fetch(url, {
        headers: { cookie: jar.header() },
        redirect: 'manual',
      });
      jar.absorb(hopRes);
      expect(hopRes.status).toBe(303);
      location = hopRes.headers.get('location')!;
    }
    expect(callbackLoc).toBeDefined();
    expect(callbackLoc!.startsWith(EXPLORER_REDIRECT)).toBe(true);
    const callbackUrl = new URL(callbackLoc!);
    const code = callbackUrl.searchParams.get('code');
    expect(typeof code).toBe('string');
    expect(callbackUrl.searchParams.get('state')).toBe(state);

    // 7) /token — exchange the code with the PKCE verifier for an id_token.
    const tokenRes = await fetch(`${baseUrl}/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: code!,
        client_id: 'citrate-explorer',
        redirect_uri: EXPLORER_REDIRECT,
        code_verifier: codeVerifier,
      }).toString(),
    });
    expect(tokenRes.status).toBe(200);
    const tokenJson = (await tokenRes.json()) as {
      id_token?: string;
      access_token?: string;
      token_type?: string;
    };
    expect(typeof tokenJson.id_token).toBe('string');
    expect(typeof tokenJson.access_token).toBe('string');

    // 8) Verify the id_token against the authority's published JWKS.
    const jwks = createRemoteJWKSet(new URL(`${baseUrl}/jwks`));
    const { payload } = await jwtVerify(tokenJson.id_token!, jwks, {
      issuer: baseUrl,
      audience: 'citrate-explorer',
    });
    expect(payload.iss).toBe(baseUrl);
    expect(payload.aud).toBe('citrate-explorer');
    expect(payload.sub).toBe(account.address);
    expect(payload.wallet_address).toBe(account.address);
  });
});
