import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { createHash, randomBytes } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { privateKeyToAccount } from 'viem/accounts';
import { type Hex } from 'viem';
import { SiweMessage } from 'siwe';
import { decodeJwt } from 'jose';
import { createProvider } from '../src/server.js';
import { CITRATE_CHAIN_ID } from '../src/siwe.js';

/**
 * TD-8 — consent auto-grant generalized to a trusted first-party client SET.
 *
 * For BOTH trusted clients we drive a real Authorization-Code + SIWE login and
 * assert that the `consent` interaction is AUTO-GRANTED (the flow reaches the
 * client callback with an authorization code WITHOUT any human consent POST) and
 * that the persisted Grant carries the requested scopes — verifiable in the
 * minted id_token's claims (wallet_address from the `wallet` scope).
 */

let server: Server;
let baseUrl: string;
let host: string;
const account = privateKeyToAccount(`0x${'c4'.repeat(32)}` as Hex);

const TRUSTED = [
  { clientId: 'citrate-explorer', redirectUri: 'http://localhost:3001/auth/callback' },
  { clientId: 'citrate-dashboard', redirectUri: 'http://localhost:3002/auth/callback' },
] as const;

class CookieJar {
  private readonly jar = new Map<string, string>();
  absorb(res: Response): void {
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
      if (value === '' || value === 'undefined') this.jar.delete(name);
      else this.jar.set(name, value);
    }
  }
  header(): string {
    return Array.from(this.jar.entries())
      .map(([k, v]) => `${k}=${v}`)
      .join('; ');
  }
}

function base64url(buf: Buffer): string {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
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

/** Run the auth flow up to (but not through) /token, returning the auth code. */
async function loginToAuthCode(
  clientId: string,
  redirectUri: string,
): Promise<{ code: string; consentPosts: number; jar: CookieJar; codeVerifier: string }> {
  const jar = new CookieJar();
  const codeVerifier = base64url(randomBytes(32));
  const codeChallenge = base64url(createHash('sha256').update(codeVerifier).digest());
  const state = base64url(randomBytes(16));

  const authUrl =
    `${baseUrl}/auth?response_type=code&client_id=${encodeURIComponent(clientId)}` +
    `&redirect_uri=${encodeURIComponent(redirectUri)}` +
    `&scope=${encodeURIComponent('openid profile wallet')}` +
    `&code_challenge=${codeChallenge}&code_challenge_method=S256&state=${state}`;
  const authRes = await fetch(authUrl, { redirect: 'manual' });
  jar.absorb(authRes);
  const interactionLoc = authRes.headers.get('location')!;

  // Render the (login) interaction page to carry cookies forward.
  await fetch(`${baseUrl}${new URL(interactionLoc, baseUrl).pathname}`, {
    headers: { cookie: jar.header() },
    redirect: 'manual',
  }).then((r) => jar.absorb(r));

  const challengeRes = await fetch(`${baseUrl}/siwe/challenge`, {
    headers: { cookie: jar.header() },
  });
  jar.absorb(challengeRes);
  const { nonce } = (await challengeRes.json()) as { nonce: string };

  const issuedAt = new Date();
  const siwe = new SiweMessage({
    domain: host,
    address: account.address,
    statement: 'Sign in to Citrate',
    uri: baseUrl,
    version: '1',
    chainId: CITRATE_CHAIN_ID,
    nonce,
    issuedAt: issuedAt.toISOString(),
    expirationTime: new Date(issuedAt.getTime() + 10 * 60 * 1000).toISOString(),
  });
  const message = siwe.prepareMessage();
  const signature = await account.signMessage({ message });

  const verifyRes = await fetch(`${baseUrl}/siwe/verify`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie: jar.header() },
    body: JSON.stringify({ message, signature }),
  });
  jar.absorb(verifyRes);
  const verifyJson = (await verifyRes.json()) as { redirectTo?: string };

  // Follow the resume chain. We count how many times we would have needed an
  // explicit /consent/approve POST: for a trusted client the consent prompt
  // auto-303s, so we never see a consent PAGE (200) — consentPosts stays 0.
  let location = verifyJson.redirectTo!;
  let code: string | undefined;
  let consentPosts = 0;
  for (let hop = 0; hop < 12; hop++) {
    const url = location.startsWith('http') ? location : `${baseUrl}${location}`;
    if (url.startsWith(redirectUri)) {
      code = new URL(url).searchParams.get('code') ?? undefined;
      break;
    }
    const res = await fetch(url, { headers: { cookie: jar.header() }, redirect: 'manual' });
    jar.absorb(res);
    if (res.status === 200) {
      // A rendered consent page would mean NO auto-grant — drive the explicit
      // approval so the test still completes, and record that it happened.
      consentPosts += 1;
      const approve = await fetch(`${baseUrl}/consent/approve`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', cookie: jar.header() },
        body: '{}',
      });
      jar.absorb(approve);
      const aj = (await approve.json()) as { redirectTo?: string };
      location = aj.redirectTo!;
      continue;
    }
    expect(res.status).toBe(303);
    location = res.headers.get('location')!;
  }
  expect(code).toBeDefined();
  return { code: code!, consentPosts, jar, codeVerifier };
}

describe.each(TRUSTED)(
  'consent auto-grant for trusted first-party client $clientId (TD-8)',
  ({ clientId, redirectUri }) => {
    it('auto-grants consent (no explicit approval) and persists a Grant with the wallet scope', async () => {
      const { code, consentPosts, codeVerifier } = await loginToAuthCode(
        clientId,
        redirectUri,
      );

      // The key TD-8 assertion: a TRUSTED client never had to show a consent
      // page / POST /consent/approve — consent was auto-granted.
      expect(consentPosts).toBe(0);

      // The persisted Grant must carry the requested scopes: exchange the code
      // and confirm the wallet-scope claim is present in the id_token.
      const tokenRes = await fetch(`${baseUrl}/token`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          client_id: clientId,
          redirect_uri: redirectUri,
          code_verifier: codeVerifier,
        }).toString(),
      });
      expect(tokenRes.status).toBe(200);
      const tokenJson = (await tokenRes.json()) as { id_token?: string };
      expect(typeof tokenJson.id_token).toBe('string');
      const claims = decodeJwt(tokenJson.id_token!);
      expect(claims.aud).toBe(clientId);
      // `wallet_address` is a `wallet`-scope claim — present only if the Grant
      // actually included that scope (auto-consent built it correctly).
      expect(claims.wallet_address).toBe(account.address);
    });
  },
);
