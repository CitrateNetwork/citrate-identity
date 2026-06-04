import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createProvider } from '../src/server.js';

/**
 * IDP-S1 bootstrap gate (automated): the authority must publish OIDC discovery
 * and a JWKS with at least one active signing key.
 *
 *   gtm-spine/features/IDP-S1-authority-bootstrap.feature
 *     Scenario: OIDC discovery is published
 */

let server: Server;
let baseUrl: string;

beforeAll(async () => {
  // Start on an ephemeral port, then construct the provider with the real issuer
  // URL so discovery advertises correct absolute endpoints.
  const probe = createServer();
  await new Promise<void>((res) => probe.listen(0, '127.0.0.1', res));
  const { port } = probe.address() as AddressInfo;
  probe.close();

  baseUrl = `http://127.0.0.1:${port}`;
  const provider = await createProvider(baseUrl);
  server = createServer(provider.callback());
  await new Promise<void>((res) => server.listen(port, '127.0.0.1', res));
});

afterAll(async () => {
  await new Promise<void>((res, rej) =>
    server.close((err) => (err ? rej(err) : res())),
  );
});

describe('OIDC discovery (IDP-S1)', () => {
  it('publishes the standard discovery document', async () => {
    const res = await fetch(`${baseUrl}/.well-known/openid-configuration`);
    expect(res.status).toBe(200);

    const doc = (await res.json()) as Record<string, unknown>;
    expect(doc.issuer).toBe(baseUrl);
    expect(doc.authorization_endpoint).toBe(`${baseUrl}/auth`);
    expect(doc.token_endpoint).toBe(`${baseUrl}/token`);
    expect(typeof doc.jwks_uri).toBe('string');
    expect(doc.jwks_uri).toContain(baseUrl);
  });

  it('exposes a JWKS with at least one active signing key', async () => {
    const discovery = await fetch(
      `${baseUrl}/.well-known/openid-configuration`,
    );
    const doc = (await discovery.json()) as { jwks_uri: string };

    const res = await fetch(doc.jwks_uri);
    expect(res.status).toBe(200);

    const jwks = (await res.json()) as { keys?: unknown[] };
    expect(Array.isArray(jwks.keys)).toBe(true);
    expect(jwks.keys!.length).toBeGreaterThanOrEqual(1);

    const key = jwks.keys![0] as Record<string, unknown>;
    // Public JWKS must never leak private material.
    expect(key.d).toBeUndefined();
    expect(key.kty).toBe('RSA');
  });
});
