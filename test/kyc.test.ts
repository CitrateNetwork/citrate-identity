import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { createHash, randomBytes } from 'node:crypto';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { privateKeyToAccount } from 'viem/accounts';
import { type Hex } from 'viem';
import { SiweMessage } from 'siwe';
import { createProvider } from '../src/server.js';
import { CITRATE_CHAIN_ID } from '../src/siwe.js';
import {
  InMemoryKycStore,
  effectiveVerified,
  isExpired,
  setKycStore,
  type KycClaim,
} from '../src/kyc.js';

/**
 * IDP-KYC — KYC status is a LIVE, revocable claim surfaced via /userinfo, not a
 * stale immutable token claim.
 *
 *   gtm-spine/features/IDP-KYC-claim-revocation.feature
 *   adrs/ADR-2026-06-03-kyc-flow.md
 *
 * The full OIDC dance (Authorization-Code + PKCE + SIWE) is driven over real HTTP
 * exactly like explorer-rp.test.ts so we obtain a REAL access token, then hit the
 * userinfo endpoint (/me) to read the live KYC status. The KYC store is swapped
 * per-test so we can verify / revoke / expire and observe /userinfo flip.
 */

const WEBHOOK_SECRET = 'test-kyc-webhook-secret-0xfeed';

let server: Server;
let baseUrl: string;
let host: string;
let userinfoEndpoint: string;
const account = privateKeyToAccount(`0x${'c3'.repeat(32)}` as Hex);

const EXPLORER_REDIRECT = 'http://localhost:3001/auth/callback';

/** A tiny cookie jar: name → value, last-write-wins per name. */
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
  const provider = await createProvider(baseUrl, { kycWebhookSecret: WEBHOOK_SECRET });
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

afterEach(() => {
  // Reset to a fresh store so tests don't leak claim state into each other.
  setKycStore(new InMemoryKycStore());
});

/**
 * Drive the full Authorization-Code + PKCE + SIWE login (the explorer flow) and
 * return a real access token whose grant includes the requested scopes. The
 * KYC claims only ride userinfo when the `kyc` scope was granted, so callers
 * request `openid wallet kyc`.
 */
async function loginForAccessToken(scope = 'openid wallet kyc'): Promise<string> {
  const jar = new CookieJar();
  const codeVerifier = base64url(randomBytes(32));
  const codeChallenge = base64url(createHash('sha256').update(codeVerifier).digest());
  const state = base64url(randomBytes(16));

  const authUrl =
    `${baseUrl}/auth?response_type=code&client_id=citrate-explorer` +
    `&redirect_uri=${encodeURIComponent(EXPLORER_REDIRECT)}` +
    `&scope=${encodeURIComponent(scope)}` +
    `&code_challenge=${codeChallenge}&code_challenge_method=S256` +
    `&state=${state}`;
  const authRes = await fetch(authUrl, { redirect: 'manual' });
  jar.absorb(authRes);
  expect(authRes.status).toBe(303);
  const interactionLoc = authRes.headers.get('location')!;

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

  const verifyRes = await fetch(`${baseUrl}/siwe/verify`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie: jar.header() },
    body: JSON.stringify({ message, signature }),
  });
  jar.absorb(verifyRes);
  const verifyJson = (await verifyRes.json()) as { redirectTo?: string };

  let location = verifyJson.redirectTo!;
  let callbackLoc: string | undefined;
  for (let hop = 0; hop < 10; hop++) {
    const url = location.startsWith('http') ? location : `${baseUrl}${location}`;
    if (url.startsWith(EXPLORER_REDIRECT)) {
      callbackLoc = url;
      break;
    }
    const hopRes = await fetch(url, { headers: { cookie: jar.header() }, redirect: 'manual' });
    jar.absorb(hopRes);
    expect(hopRes.status).toBe(303);
    location = hopRes.headers.get('location')!;
  }
  const code = new URL(callbackLoc!).searchParams.get('code')!;

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
  expect(tokenRes.status).toBe(200);
  const tokenJson = (await tokenRes.json()) as { access_token?: string };
  expect(typeof tokenJson.access_token).toBe('string');
  return tokenJson.access_token!;
}

async function userinfo(accessToken: string): Promise<Record<string, unknown>> {
  const res = await fetch(userinfoEndpoint, {
    headers: { authorization: `Bearer ${accessToken}` },
  });
  expect(res.status).toBe(200);
  return (await res.json()) as Record<string, unknown>;
}

// `secret: null` means "send NO Authorization header" (vs. omitting the arg,
// which defaults to the valid secret). Passing `undefined` would re-trigger the
// default param, so we use an explicit null sentinel for the unauthenticated case.
async function postKyc(
  path: '/kyc/_set' | '/kyc/_revoke',
  body: Record<string, unknown>,
  secret: string | null = WEBHOOK_SECRET,
): Promise<Response> {
  const headers: Record<string, string> = { 'content-type': 'application/json' };
  if (secret !== null) headers.authorization = `Bearer ${secret}`;
  return fetch(`${baseUrl}${path}`, { method: 'POST', headers, body: JSON.stringify(body) });
}

describe('IDP-KYC: live, revocable KYC via /userinfo', () => {
  it('verification → /userinfo shows kyc_status verified', async () => {
    const verified_at = new Date().toISOString();
    const expires_at = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString();
    const setRes = await postKyc('/kyc/_set', {
      address: account.address,
      status: 'verified',
      verified_at,
      expires_at,
      vendor_ref: 'clear:applicant-abc123',
    });
    expect(setRes.status).toBe(200);

    const accessToken = await loginForAccessToken();
    const info = await userinfo(accessToken);
    expect(info.sub).toBe(account.address);
    expect(info.kyc_status).toBe('verified');
    expect(info.kyc_verified_at).toBe(verified_at);
    expect(info.kyc_expires_at).toBe(expires_at);
  });

  it('revoke → /userinfo flips to not-verified IMMEDIATELY, even though the old token baked verified', async () => {
    // Verify first, then log in while verified → the access token's snapshot is verified.
    await postKyc('/kyc/_set', {
      address: account.address,
      status: 'verified',
      verified_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(),
      vendor_ref: 'clear:applicant-abc123',
    });
    const accessToken = await loginForAccessToken();
    expect((await userinfo(accessToken)).kyc_status).toBe('verified');

    // Vendor revokes. We do NOT re-issue the token — the SAME access token is reused.
    const revokeRes = await postKyc('/kyc/_revoke', { address: account.address });
    expect(revokeRes.status).toBe(200);

    // /userinfo (live, re-reads the store) must flip immediately to not-verified,
    // proving the store — not the immutable token — is authoritative.
    const info = await userinfo(accessToken);
    expect(info.kyc_status).not.toBe('verified');
    expect(info.kyc_status).toBe('revoked');
  });

  it('expired claim (expires_at in the past) → not verified', async () => {
    await postKyc('/kyc/_set', {
      address: account.address,
      status: 'verified',
      verified_at: new Date(Date.now() - 400 * 24 * 60 * 60 * 1000).toISOString(),
      expires_at: new Date(Date.now() - 60_000).toISOString(), // expired a minute ago
      vendor_ref: 'clear:applicant-expired',
    });
    const accessToken = await loginForAccessToken();
    const info = await userinfo(accessToken);
    expect(info.kyc_status).not.toBe('verified');
    expect(info.kyc_status).toBe('expired');
  });

  it('a wallet that never did KYC reports kyc_status none', async () => {
    const accessToken = await loginForAccessToken();
    const info = await userinfo(accessToken);
    expect(info.kyc_status).toBe('none');
    expect(info.kyc_verified_at).toBeUndefined();
  });

  it('the claim record contains NO PII — only status/dates/vendor_ref', async () => {
    // Even if a webhook payload smuggles PII, only the four allowed fields persist.
    await postKyc('/kyc/_set', {
      address: account.address,
      status: 'verified',
      verified_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + 1000).toISOString(),
      vendor_ref: 'clear:applicant-abc123',
      // Hostile extras that MUST NOT be stored:
      ssn: '123-45-6789',
      full_name: 'Jane Q. Public',
      document_image: 'data:image/png;base64,AAAA',
    });

    const store = new InMemoryKycStore();
    setKycStore(store);
    // Re-set through the same code path against the fresh store.
    await postKyc('/kyc/_set', {
      address: account.address,
      status: 'verified',
      verified_at: '2026-06-04T00:00:00.000Z',
      expires_at: '2027-06-04T00:00:00.000Z',
      vendor_ref: 'clear:applicant-abc123',
      ssn: '123-45-6789',
      full_name: 'Jane Q. Public',
      document_image: 'data:image/png;base64,AAAA',
    });

    const claim = store.get(account.address)!;
    expect(claim).toBeDefined();
    // The record's keys are EXACTLY the allowed claim fields.
    expect(new Set(Object.keys(claim))).toEqual(
      new Set(['status', 'verified_at', 'expires_at', 'vendor_ref']),
    );
    // And the PII values are nowhere in the serialized record.
    const serialized = JSON.stringify(claim);
    expect(serialized).not.toContain('123-45-6789');
    expect(serialized).not.toContain('Jane Q. Public');
    expect(serialized).not.toContain('document_image');
  });

  it('/kyc/_set rejects requests WITHOUT the webhook secret (no store write)', async () => {
    // No Authorization header at all.
    const noSecret = await postKyc(
      '/kyc/_set',
      {
        address: account.address,
        status: 'verified',
        vendor_ref: 'clear:applicant-abc123',
      },
      null,
    );
    expect(noSecret.status).toBe(401);

    // Wrong secret.
    const wrongSecret = await postKyc(
      '/kyc/_set',
      {
        address: account.address,
        status: 'verified',
        vendor_ref: 'clear:applicant-abc123',
      },
      'not-the-secret',
    );
    expect(wrongSecret.status).toBe(401);

    // The store was never written: /userinfo still reports none.
    const accessToken = await loginForAccessToken();
    expect((await userinfo(accessToken)).kyc_status).toBe('none');
  });

  it('/kyc/_revoke also rejects requests without the secret', async () => {
    const res = await postKyc('/kyc/_revoke', { address: account.address }, 'wrong');
    expect(res.status).toBe(401);
  });
});

describe('IDP-KYC store semantics (unit)', () => {
  it('effectiveVerified is true only for a non-expired verified claim', () => {
    const future = new Date(Date.now() + 60_000).toISOString();
    const past = new Date(Date.now() - 60_000).toISOString();
    const base: KycClaim = { status: 'verified', vendor_ref: 'ref', expires_at: future };
    expect(effectiveVerified(base)).toBe(true);
    expect(effectiveVerified({ ...base, expires_at: past })).toBe(false);
    expect(effectiveVerified({ ...base, status: 'pending' })).toBe(false);
    expect(effectiveVerified({ ...base, status: 'revoked' })).toBe(false);
    expect(effectiveVerified(undefined)).toBe(false);
    // No expiry set → never expired.
    expect(effectiveVerified({ status: 'verified', vendor_ref: 'ref' })).toBe(true);
  });

  it('isExpired only fires for a past expires_at', () => {
    expect(isExpired({ status: 'verified', vendor_ref: 'r' })).toBe(false);
    expect(
      isExpired({ status: 'verified', vendor_ref: 'r', expires_at: new Date(Date.now() - 1).toISOString() }),
    ).toBe(true);
    expect(
      isExpired({ status: 'verified', vendor_ref: 'r', expires_at: new Date(Date.now() + 60_000).toISOString() }),
    ).toBe(false);
  });

  it('revoke preserves vendor_ref/verified_at but forces status revoked and clears expiry', () => {
    const store = new InMemoryKycStore();
    store.set('0xAbC', {
      status: 'verified',
      verified_at: '2026-01-01T00:00:00.000Z',
      expires_at: '2027-01-01T00:00:00.000Z',
      vendor_ref: 'clear:xyz',
    });
    store.revoke('0xAbC');
    const claim = store.get('0xabc')!; // case-insensitive key
    expect(claim.status).toBe('revoked');
    expect(claim.vendor_ref).toBe('clear:xyz');
    expect(claim.verified_at).toBe('2026-01-01T00:00:00.000Z');
    expect(claim.expires_at).toBeUndefined();
  });
});
