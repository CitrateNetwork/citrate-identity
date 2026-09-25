/**
 * IDP-S3 — `/identity/:sub/wallets` HTTP surface, end-to-end.
 *
 * Planset gate demonstrated for real: a SIWE-logged-in identity links a
 * SECOND wallet with a proof signed by that wallet's own key; the
 * `wallets` claim served by /userinfo immediately reflects it (so the
 * marketplace settlement seam can attribute earnings); replayed nonces
 * and cross-sub access fail closed.
 *
 * Token acquisition drives the REAL Authorization-Code + PKCE + SIWE
 * flow (same harness shape as logout.test.ts / explorer-rp.test.ts).
 */

import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { createHash, randomBytes } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { privateKeyToAccount } from 'viem/accounts';
import { type Hex } from 'viem';
import { SiweMessage } from 'siwe';

import { createProvider } from '../src/server.js';
import { CITRATE_CHAIN_ID } from '../src/siwe.js';
import {
  InMemoryWalletRegistry,
  buildWalletLinkMessage,
  setWalletRegistry,
} from '../src/identity-registry.js';

let server: Server;
let baseUrl: string;
let host: string;
let userinfoEndpoint: string;

const account = privateKeyToAccount(`0x${'a7'.repeat(32)}` as Hex);
const secondWallet = privateKeyToAccount(`0x${'b9'.repeat(32)}` as Hex);

// PBA-L3a-005: wallet linking needs a Citrate wallet client; drive the flow as
// the desktop app (citrate-core, RFC 8252 loopback redirect).
const EXPLORER_REDIRECT = 'http://127.0.0.1/auth/callback';

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
      if (!pair) continue;
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
  setWalletRegistry(new InMemoryWalletRegistry());

  const probe = createServer();
  await new Promise<void>((res) => probe.listen(0, '127.0.0.1', res));
  const { port } = probe.address() as AddressInfo;
  probe.close();

  baseUrl = `http://127.0.0.1:${port}`;
  host = `127.0.0.1:${port}`;
  const provider = await createProvider(baseUrl);
  server = createServer(provider.callback());
  await new Promise<void>((res) => server.listen(port, '127.0.0.1', res));

  const discovery = await fetch(`${baseUrl}/.well-known/openid-configuration`);
  const doc = (await discovery.json()) as { userinfo_endpoint: string };
  userinfoEndpoint = doc.userinfo_endpoint;
});

afterAll(async () => {
  await new Promise<void>((res, rej) =>
    server.close((err) => (err ? rej(err) : res())),
  );
});

/** Real Authorization-Code + PKCE + SIWE login → access token. */
async function loginForAccessToken(): Promise<string> {
  const jar = new CookieJar();
  const codeVerifier = base64url(randomBytes(32));
  const codeChallenge = base64url(createHash('sha256').update(codeVerifier).digest());
  const state = base64url(randomBytes(16));

  const authRes = await fetch(
    `${baseUrl}/auth?response_type=code&client_id=citrate-core` +
      `&redirect_uri=${encodeURIComponent(EXPLORER_REDIRECT)}` +
      `&scope=${encodeURIComponent('openid wallet')}` +
      `&code_challenge=${codeChallenge}&code_challenge_method=S256` +
      `&state=${state}`,
    { redirect: 'manual' },
  );
  jar.absorb(authRes);
  const interactionLoc = authRes.headers.get('location') ?? '';
  const interactionUrl = interactionLoc.startsWith('http')
    ? interactionLoc
    : `${baseUrl}${interactionLoc}`;
  const viewRes = await fetch(interactionUrl, {
    headers: { cookie: jar.header() },
    redirect: 'manual',
  });
  jar.absorb(viewRes);

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

  let location = verifyJson.redirectTo ?? '';
  let callbackLoc: string | undefined;
  for (let hop = 0; hop < 10; hop++) {
    const url = location.startsWith('http') ? location : `${baseUrl}${location}`;
    if (url.startsWith(EXPLORER_REDIRECT)) {
      callbackLoc = url;
      break;
    }
    const hopRes = await fetch(url, { headers: { cookie: jar.header() }, redirect: 'manual' });
    jar.absorb(hopRes);
    location = hopRes.headers.get('location') ?? '';
  }
  const code = new URL(callbackLoc ?? '').searchParams.get('code') ?? '';

  const tokenRes = await fetch(`${baseUrl}/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      client_id: 'citrate-core',
      redirect_uri: EXPLORER_REDIRECT,
      code_verifier: codeVerifier,
    }).toString(),
  });
  const tokenJson = (await tokenRes.json()) as { access_token?: string };
  expect(typeof tokenJson.access_token).toBe('string');
  return tokenJson.access_token as string;
}

describe('IDP-S3 /identity/:sub/wallets', () => {
  it('fails closed without a token and across subs', async () => {
    const sub = account.address;
    const noToken = await fetch(`${baseUrl}/identity/${sub}/wallets`);
    expect(noToken.status).toBe(401);

    const token = await loginForAccessToken();
    const crossSub = await fetch(`${baseUrl}/identity/0xsomeoneElse/wallets`, {
      headers: { authorization: `Bearer ${token}` },
    });
    expect(crossSub.status).toBe(403);
  });

  it('links a 2nd wallet with its own proof; /userinfo wallets reflects it; replay rejected', async () => {
    const token = await loginForAccessToken();
    const sub = account.address;
    const auth = { authorization: `Bearer ${token}` };

    // 1. Challenge → one-time nonce.
    const chRes = await fetch(`${baseUrl}/identity/${sub}/wallets/challenge`, {
      method: 'POST',
      headers: auth,
    });
    expect(chRes.status).toBe(200);
    const { nonce } = (await chRes.json()) as { nonce: string };

    // 2. The SECOND wallet signs the canonical link message itself.
    const message = buildWalletLinkMessage({
      authority: host,
      sub,
      address: secondWallet.address,
      nonce,
      chainId: CITRATE_CHAIN_ID,
    });
    const proof = await secondWallet.signMessage({ message });

    const linkRes = await fetch(`${baseUrl}/identity/${sub}/wallets`, {
      method: 'POST',
      headers: { ...auth, 'content-type': 'application/json' },
      body: JSON.stringify({ address: secondWallet.address, signature: proof, nonce }),
    });
    expect(linkRes.status).toBe(201);

    // 3. Replay with the SAME nonce is rejected (consumed once).
    const replay = await fetch(`${baseUrl}/identity/${sub}/wallets`, {
      method: 'POST',
      headers: { ...auth, 'content-type': 'application/json' },
      body: JSON.stringify({ address: secondWallet.address, signature: proof, nonce }),
    });
    expect(replay.status).toBe(401);

    // 4. The list shows the linked wallet.
    const listRes = await fetch(`${baseUrl}/identity/${sub}/wallets`, { headers: auth });
    const listJson = (await listRes.json()) as { wallets: { address: string }[] };
    expect(listJson.wallets.map((w) => w.address.toLowerCase())).toContain(
      secondWallet.address.toLowerCase(),
    );

    // 5. /userinfo `wallets` claim carries BOTH (earnings-attribution seam):
    //    the SIWE identity wallet first (canonical), the linked one after.
    const ui = await fetch(userinfoEndpoint, { headers: auth });
    expect(ui.status).toBe(200);
    const claims = (await ui.json()) as { wallets?: string[]; wallet_address?: string };
    expect(claims.wallet_address?.toLowerCase()).toBe(sub.toLowerCase());
    expect(claims.wallets?.map((w) => w.toLowerCase())).toEqual([
      sub.toLowerCase(),
      secondWallet.address.toLowerCase(),
    ]);

    // 6. Unlink works and the claim shrinks back.
    const del = await fetch(`${baseUrl}/identity/${sub}/wallets/${secondWallet.address}`, {
      method: 'DELETE',
      headers: auth,
    });
    expect(del.status).toBe(200);
    const ui2 = await fetch(userinfoEndpoint, { headers: auth });
    const claims2 = (await ui2.json()) as { wallets?: string[] };
    expect(claims2.wallets?.map((w) => w.toLowerCase())).toEqual([sub.toLowerCase()]);
  });

  it('rejects a proof signed by the wrong key', async () => {
    const token = await loginForAccessToken();
    const sub = account.address;
    const auth = { authorization: `Bearer ${token}` };

    const chRes = await fetch(`${baseUrl}/identity/${sub}/wallets/challenge`, {
      method: 'POST',
      headers: auth,
    });
    const { nonce } = (await chRes.json()) as { nonce: string };
    const message = buildWalletLinkMessage({
      authority: host,
      sub,
      address: secondWallet.address,
      nonce,
      chainId: CITRATE_CHAIN_ID,
    });
    // Signed by the IDENTITY's key, not the wallet being linked.
    const wrongProof = await account.signMessage({ message });
    const res = await fetch(`${baseUrl}/identity/${sub}/wallets`, {
      method: 'POST',
      headers: { ...auth, 'content-type': 'application/json' },
      body: JSON.stringify({ address: secondWallet.address, signature: wrongProof, nonce }),
    });
    expect(res.status).toBe(401);
  });
});
