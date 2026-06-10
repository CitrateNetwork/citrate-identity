import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { privateKeyToAccount } from 'viem/accounts';
import type { Hex } from 'viem';
import { SiweMessage } from 'siwe';
import { createProvider } from '../src/server.js';
import {
  CITRATE_CHAIN_ID,
  InMemoryNonceStore,
  MAX_SIWE_EXPIRATION_MS,
  verifySiweLogin,
} from '../src/siwe.js';
import { jsonForScript } from '../src/siwe-routes.js';

/**
 * SECREM-02 — Phase 1 identity *issuer* hardening. Red tests for:
 *   - FUA-IDENTITY-01 — out-of-band direct ID-token mint (Path B) is OFF by
 *     default (fail closed); only the authorization-code flow works.
 *   - FUA-IDENTITY-04 — cross-site state-changing POSTs are refused (CSRF).
 *   - FUA-IDENTITY-07 — values injected into the interaction page's inline
 *     <script> are escaped so they cannot break out.
 *   - FUA-IDENTITY-09 — a SIWE message must set Expiration Time (bounded) and
 *     bind its uri to the authority.
 */

const account = privateKeyToAccount(`0x${'b2'.repeat(32)}` as Hex);

// ── FUA-IDENTITY-09: expiry + uri binding (unit, no server) ──────────────────
describe('FUA-IDENTITY-09 — SIWE expiry + uri binding required', () => {
  const expectedDomain = 'auth.citrate.ai';

  async function verify(overrides: Partial<{ expirationTime?: string; uri: string }>) {
    const store = new InMemoryNonceStore();
    const nonce = store.issue();
    const siwe = new SiweMessage({
      domain: expectedDomain,
      address: account.address,
      uri: overrides.uri ?? 'https://auth.citrate.ai',
      version: '1',
      chainId: CITRATE_CHAIN_ID,
      nonce,
      ...('expirationTime' in overrides
        ? { expirationTime: overrides.expirationTime }
        : { expirationTime: new Date(Date.now() + 10 * 60 * 1000).toISOString() }),
    });
    const message = siwe.prepareMessage();
    const signature = await account.signMessage({ message });
    return verifySiweLogin({ message, signature, expectedDomain, nonceStore: store });
  }

  it('rejects a message with NO expirationTime (would never expire)', async () => {
    await expect(verify({ expirationTime: undefined })).rejects.toMatchObject({
      reason: 'missing_expiration',
    });
  });

  it('rejects an expirationTime beyond the lifetime cap', async () => {
    const tooFar = new Date(Date.now() + MAX_SIWE_EXPIRATION_MS + 60_000).toISOString();
    await expect(verify({ expirationTime: tooFar })).rejects.toMatchObject({
      reason: 'expiration_too_far',
    });
  });

  it('rejects a message whose uri host is not the authority', async () => {
    await expect(verify({ uri: 'https://evil-phisher.example' })).rejects.toMatchObject({
      reason: 'uri_mismatch',
    });
  });

  it('accepts a well-formed, bounded, authority-bound message', async () => {
    const result = await verify({});
    expect(result.address).toBe(account.address);
  });
});

// ── FUA-IDENTITY-07: inline-script escaping (unit) ───────────────────────────
describe('FUA-IDENTITY-07 — jsonForScript neutralizes script breakout', () => {
  it('escapes </script> and angle brackets so a hostile value cannot break out', () => {
    const out = jsonForScript({ clientId: '</script><img src=x onerror=alert(1)>' });
    expect(out).not.toContain('</script>');
    expect(out).not.toContain('<');
    expect(out).not.toContain('>');
    // Still valid JSON once the \uXXXX escapes are parsed by a JS engine.
    expect(JSON.parse(out)).toEqual({
      clientId: '</script><img src=x onerror=alert(1)>',
    });
  });
});

// ── FUA-IDENTITY-01 + 04: HTTP behavior against a DEFAULT provider ───────────
describe('FUA-IDENTITY-01/04 — direct-token off by default; cross-site refused', () => {
  let server: Server;
  let baseUrl: string;
  let host: string;

  beforeAll(async () => {
    const probe = createServer();
    await new Promise<void>((res) => probe.listen(0, '127.0.0.1', res));
    const { port } = probe.address() as AddressInfo;
    probe.close();
    baseUrl = `http://127.0.0.1:${port}`;
    host = `127.0.0.1:${port}`;
    // NOTE: no allowDirectTokenGrant → Path B disabled (the production default).
    const provider = await createProvider(baseUrl);
    server = createServer(provider.callback());
    await new Promise<void>((res) => server.listen(port, '127.0.0.1', res));
  });

  afterAll(async () => {
    await new Promise<void>((res, rej) =>
      server.close((err) => (err ? rej(err) : res())),
    );
  });

  it('FUA-IDENTITY-01: /siwe/verify with no interaction refuses the direct token', async () => {
    const challenge = await fetch(`${baseUrl}/siwe/challenge`);
    const { nonce } = (await challenge.json()) as { nonce: string };
    const siwe = new SiweMessage({
      domain: host,
      address: account.address,
      statement: 'Sign in to Citrate',
      uri: baseUrl,
      version: '1',
      chainId: CITRATE_CHAIN_ID,
      nonce,
      issuedAt: new Date().toISOString(),
      expirationTime: new Date(Date.now() + 10 * 60 * 1000).toISOString(),
    });
    const message = siwe.prepareMessage();
    const signature = await account.signMessage({ message });

    const res = await fetch(`${baseUrl}/siwe/verify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ message, signature }),
    });
    // Signature is valid, but with no interaction and Path B disabled the
    // authority refuses rather than minting an out-of-band token.
    expect(res.status).toBe(400);
    const json = (await res.json()) as { reason?: string };
    expect(json.reason).toMatch(/disabled|authorization code/i);
  });

  it('FUA-IDENTITY-04: cross-site POST /consent/approve is refused (Origin)', async () => {
    const res = await fetch(`${baseUrl}/consent/approve`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        origin: 'https://evil-phisher.example',
      },
      body: '{}',
    });
    expect(res.status).toBe(403);
    const json = (await res.json()) as { reason?: string };
    expect(json.reason).toBe('cross_site_forbidden');
  });

  it('FUA-IDENTITY-04: cross-site POST /consent/approve is refused (Sec-Fetch-Site)', async () => {
    const res = await fetch(`${baseUrl}/consent/approve`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'sec-fetch-site': 'cross-site',
      },
      body: '{}',
    });
    expect(res.status).toBe(403);
  });

  it('FUA-IDENTITY-04: a same-origin POST passes the guard (no interaction → 400, not 403)', async () => {
    const res = await fetch(`${baseUrl}/consent/approve`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        origin: baseUrl,
        'sec-fetch-site': 'same-origin',
      },
      body: '{}',
    });
    // Passes the CSRF guard; fails only because there's no active interaction.
    expect(res.status).toBe(400);
    const json = (await res.json()) as { reason?: string };
    expect(json.reason).toMatch(/no active consent interaction/i);
  });
});
