/**
 * Self-published bindings directory — HTTP surface, end-to-end (citrate-core#61).
 *
 * Drives the REAL Authorization-Code + PKCE + SIWE login (same harness shape as
 * wallet-registry-http.test.ts) to obtain a member Bearer, then exercises the four
 * endpoints against the live OIDC server:
 *
 *   - publish: valid → stored; bad ownership_proof → 422; bad sig → 422
 *   - lookup:  published → hit; unpublished → null; revoked → null
 *   - search:  prefix match, opted-in only, capped
 *   - revoke:  → lookups null; reads still require a Bearer
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
  InMemoryDirectoryStore,
  setDirectoryStore,
  buildSocialBindingMessage,
  buildDirectoryPublishStatement,
  buildDirectoryRevokeStatement,
  handleKeyOf,
  signedHandle,
} from '../src/directory.js';

let server: Server;
let baseUrl: string;
let host: string;

const account = privateKeyToAccount(`0x${'a7'.repeat(32)}` as Hex);
const stranger = privateKeyToAccount(`0x${'e5'.repeat(32)}` as Hex);
const EXPLORER_REDIRECT = 'http://localhost:3001/auth/callback';

class CookieJar {
  private readonly jar = new Map<string, string>();
  absorb(res: Response): void {
    const setCookies =
      typeof (res.headers as Headers & { getSetCookie?: () => string[] }).getSetCookie === 'function'
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
    return Array.from(this.jar.entries()).map(([k, v]) => `${k}=${v}`).join('; ');
  }
}

function base64url(buf: Buffer): string {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

beforeAll(async () => {
  setDirectoryStore(new InMemoryDirectoryStore());

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
  await new Promise<void>((res, rej) => server.close((err) => (err ? rej(err) : res())));
});

/** Real Authorization-Code + PKCE + SIWE login → access token. */
async function loginForAccessToken(): Promise<string> {
  const jar = new CookieJar();
  const codeVerifier = base64url(randomBytes(32));
  const codeChallenge = base64url(createHash('sha256').update(codeVerifier).digest());
  const state = base64url(randomBytes(16));

  const authRes = await fetch(
    `${baseUrl}/auth?response_type=code&client_id=citrate-explorer` +
      `&redirect_uri=${encodeURIComponent(EXPLORER_REDIRECT)}` +
      `&scope=${encodeURIComponent('openid wallet')}` +
      `&code_challenge=${codeChallenge}&code_challenge_method=S256&state=${state}`,
    { redirect: 'manual' },
  );
  jar.absorb(authRes);
  const interactionLoc = authRes.headers.get('location') ?? '';
  const interactionUrl = interactionLoc.startsWith('http') ? interactionLoc : `${baseUrl}${interactionLoc}`;
  const viewRes = await fetch(interactionUrl, { headers: { cookie: jar.header() }, redirect: 'manual' });
  jar.absorb(viewRes);

  const challengeRes = await fetch(`${baseUrl}/siwe/challenge`, { headers: { cookie: jar.header() } });
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
      client_id: 'citrate-explorer',
      redirect_uri: EXPLORER_REDIRECT,
      code_verifier: codeVerifier,
    }).toString(),
  });
  const tokenJson = (await tokenRes.json()) as { access_token?: string };
  expect(typeof tokenJson.access_token).toBe('string');
  return tokenJson.access_token as string;
}

/** Build a fully-signed publish body the way citrate-core would. */
async function signedPublishBody(opts: {
  handle: string;
  address?: string;
  boundAt: number;
  displayName?: string;
  ownershipSigner?: typeof account;
  publishSigner?: typeof account;
}): Promise<Record<string, unknown>> {
  const platform = 'x' as const;
  const address = opts.address ?? account.address;
  const ownershipSigner = opts.ownershipSigner ?? account;
  const publishSigner = opts.publishSigner ?? account;
  const nonce = `nonce-${opts.handle}`;
  const ownership = await ownershipSigner.signMessage({
    message: buildSocialBindingMessage(platform, signedHandle(opts.handle), address, nonce),
  });
  const sig = await publishSigner.signMessage({
    message: buildDirectoryPublishStatement({ platform, handleKey: handleKeyOf(opts.handle), address, boundAt: opts.boundAt }),
  });
  return {
    platform,
    handle: opts.handle,
    address,
    bound_at: opts.boundAt,
    ...(opts.displayName ? { display_name: opts.displayName } : {}),
    ownership_proof: { nonce, signature: ownership },
    sig,
  };
}

const bearer = (t: string) => ({ authorization: `Bearer ${t}`, 'content-type': 'application/json' });
const now = () => Math.floor(Date.now() / 1000);

describe('citrate-core#61 /directory HTTP', () => {
  it('the whole surface is Bearer-gated (no open scraper)', async () => {
    expect((await fetch(`${baseUrl}/directory/lookup?platform=x&handle=@foo`)).status).toBe(401);
    expect((await fetch(`${baseUrl}/directory/search?platform=x&q=foo`)).status).toBe(401);
    expect((await fetch(`${baseUrl}/directory/bindings`, { method: 'POST' })).status).toBe(401);
  });

  it('publishes a valid binding; lookup + search then find it', async () => {
    const token = await loginForAccessToken();
    const body = await signedPublishBody({ handle: 'satoshi', boundAt: now(), displayName: 'Satoshi N' });

    const pub = await fetch(`${baseUrl}/directory/bindings`, {
      method: 'POST',
      headers: bearer(token),
      body: JSON.stringify(body),
    });
    expect(pub.status).toBe(200);
    expect(((await pub.json()) as { status: string }).status).toBe('stored');

    const look = await fetch(`${baseUrl}/directory/lookup?platform=x&handle=@Satoshi`, {
      headers: { authorization: `Bearer ${token}` },
    });
    expect(look.status).toBe(200);
    const hit = (await look.json()) as { address: string; bound_at: number };
    expect(hit.address.toLowerCase()).toBe(account.address.toLowerCase());

    const search = await fetch(`${baseUrl}/directory/search?platform=x&q=sat`, {
      headers: { authorization: `Bearer ${token}` },
    });
    const rows = (await search.json()) as { handle: string; address: string; display_name?: string }[];
    expect(rows.some((r) => r.handle === 'satoshi' && r.display_name === 'Satoshi N')).toBe(true);
  });

  it('lookup of an unpublished handle returns null (never a guess)', async () => {
    const token = await loginForAccessToken();
    const look = await fetch(`${baseUrl}/directory/lookup?platform=x&handle=@ghost`, {
      headers: { authorization: `Bearer ${token}` },
    });
    expect(look.status).toBe(200);
    expect(await look.json()).toBeNull();
  });

  it('rejects a bad ownership_proof (422) and a bad directory sig (422)', async () => {
    const token = await loginForAccessToken();

    // ownership_proof signed by a DIFFERENT key than `address`.
    const badOwnership = await signedPublishBody({ handle: 'vitalik', boundAt: now(), ownershipSigner: stranger });
    const r1 = await fetch(`${baseUrl}/directory/bindings`, {
      method: 'POST',
      headers: bearer(token),
      body: JSON.stringify(badOwnership),
    });
    expect(r1.status).toBe(422);
    expect(((await r1.json()) as { error: string }).error).toBe('invalid_ownership_proof');

    // directory `sig` signed by a DIFFERENT key than `address`.
    const badSig = await signedPublishBody({ handle: 'vitalik', boundAt: now(), publishSigner: stranger });
    const r2 = await fetch(`${baseUrl}/directory/bindings`, {
      method: 'POST',
      headers: bearer(token),
      body: JSON.stringify(badSig),
    });
    expect(r2.status).toBe(422);
    expect(((await r2.json()) as { error: string }).error).toBe('invalid_signature');

    // Neither attempt was stored.
    const look = await fetch(`${baseUrl}/directory/lookup?platform=x&handle=vitalik`, {
      headers: { authorization: `Bearer ${token}` },
    });
    expect(await look.json()).toBeNull();
  });

  it('revoke makes lookup + search return nothing', async () => {
    const token = await loginForAccessToken();
    const at = now();
    await fetch(`${baseUrl}/directory/bindings`, {
      method: 'POST',
      headers: bearer(token),
      body: JSON.stringify(await signedPublishBody({ handle: 'dana', boundAt: at })),
    });
    // present before revoke
    const before = await fetch(`${baseUrl}/directory/lookup?platform=x&handle=dana`, {
      headers: { authorization: `Bearer ${token}` },
    });
    expect(await before.json()).not.toBeNull();

    const revokeSig = await account.signMessage({
      message: buildDirectoryRevokeStatement({ platform: 'x', handleKey: 'dana', address: account.address }),
    });
    const del = await fetch(`${baseUrl}/directory/bindings`, {
      method: 'DELETE',
      headers: bearer(token),
      body: JSON.stringify({ platform: 'x', handle: 'dana', address: account.address, sig: revokeSig }),
    });
    expect(del.status).toBe(200);
    expect(((await del.json()) as { status: string }).status).toBe('revoked');

    const after = await fetch(`${baseUrl}/directory/lookup?platform=x&handle=dana`, {
      headers: { authorization: `Bearer ${token}` },
    });
    expect(await after.json()).toBeNull();
    const search = await fetch(`${baseUrl}/directory/search?platform=x&q=dan`, {
      headers: { authorization: `Bearer ${token}` },
    });
    expect((await search.json()) as unknown[]).toEqual([]);
  });

  it('a stranger cannot revoke a binding they do not control', async () => {
    const token = await loginForAccessToken();
    await fetch(`${baseUrl}/directory/bindings`, {
      method: 'POST',
      headers: bearer(token),
      body: JSON.stringify(await signedPublishBody({ handle: 'held', boundAt: now() })),
    });
    // A revoke sig by the stranger's key does not match the bound address.
    const strangerSig = await stranger.signMessage({
      message: buildDirectoryRevokeStatement({ platform: 'x', handleKey: 'held', address: stranger.address }),
    });
    const del = await fetch(`${baseUrl}/directory/bindings`, {
      method: 'DELETE',
      headers: bearer(token),
      body: JSON.stringify({ platform: 'x', handle: 'held', address: stranger.address, sig: strangerSig }),
    });
    expect(del.status).toBe(404);
    const look = await fetch(`${baseUrl}/directory/lookup?platform=x&handle=held`, {
      headers: { authorization: `Bearer ${token}` },
    });
    expect(await look.json()).not.toBeNull();
  });

  it('search never dumps: a blank prefix returns []', async () => {
    const token = await loginForAccessToken();
    const search = await fetch(`${baseUrl}/directory/search?platform=x&q=`, {
      headers: { authorization: `Bearer ${token}` },
    });
    expect((await search.json()) as unknown[]).toEqual([]);
  });
});
