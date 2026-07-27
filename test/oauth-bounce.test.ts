import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createProvider } from '../src/server.js';
import {
  buildLoopbackRedirect,
  CORE_LOOPBACK_CALLBACK,
} from '../src/oauth-bounce.js';

/**
 * Hosted OAuth redirect bounce (src/oauth-bounce.ts): the https fallback that
 * lets Citrate Core sign in to providers (Notion) that reject the http-loopback
 * redirect. GET /oauth/callback 302s the browser back to the app's fixed loopback
 * listener, forwarding the authorization code/state unchanged, holding no state
 * and no secret.
 */

let server: Server;
let baseUrl: string;

async function listenProvider(): Promise<{ server: Server; baseUrl: string }> {
  // Reserve an ephemeral port the same way http-extras.test.ts does, so the
  // provider's issuer URL matches the socket it binds.
  const probe = createServer();
  await new Promise<void>((res) => probe.listen(0, '127.0.0.1', res));
  const { port } = probe.address() as AddressInfo;
  probe.close();
  const url = `http://127.0.0.1:${port}`;
  const provider = await createProvider(url);
  const s = createServer(provider.callback());
  await new Promise<void>((res) => s.listen(port, '127.0.0.1', res));
  return { server: s, baseUrl: url };
}

beforeAll(async () => {
  ({ server, baseUrl } = await listenProvider());
});

afterAll(async () => {
  await new Promise<void>((res, rej) =>
    server.close((err) => (err ? rej(err) : res())),
  );
});

describe('buildLoopbackRedirect (pure)', () => {
  it('appends code + state to the fixed loopback target, encoded', () => {
    const url = buildLoopbackRedirect('code=abc123&state=xyz789');
    const parsed = new URL(url);
    expect(`${parsed.protocol}//${parsed.host}${parsed.pathname}`).toBe(
      CORE_LOOPBACK_CALLBACK,
    );
    expect(parsed.searchParams.get('code')).toBe('abc123');
    expect(parsed.searchParams.get('state')).toBe('xyz789');
  });

  it('forwards a provider error response (user-denied) unchanged', () => {
    const url = buildLoopbackRedirect('error=access_denied&state=xyz');
    const parsed = new URL(url);
    expect(parsed.searchParams.get('error')).toBe('access_denied');
    expect(parsed.searchParams.get('state')).toBe('xyz');
  });

  it('emits no bare "?" when there is no query', () => {
    expect(buildLoopbackRedirect('')).toBe(CORE_LOOPBACK_CALLBACK);
  });

  it('cannot be steered off the fixed loopback host (closed redirect)', () => {
    // A hostile query trying to smuggle an alternate destination stays a mere
    // query param on 127.0.0.1 — the target host/port/path are constant.
    const url = buildLoopbackRedirect(
      'code=x&redirect_uri=https://evil.example.com',
    );
    const parsed = new URL(url);
    expect(parsed.host).toBe('127.0.0.1:8975');
    expect(parsed.protocol).toBe('http:');
  });

  it('neutralises CR/LF injection by re-encoding the query', () => {
    const url = buildLoopbackRedirect('state=a%0d%0aLocation:%20evil');
    // The decoded value round-trips as data; there is no raw CR/LF in the URL.
    expect(url).not.toMatch(/[\r\n]/);
    const parsed = new URL(url);
    expect(parsed.host).toBe('127.0.0.1:8975');
  });
});

describe('GET /oauth/callback (hosted bounce over the provider)', () => {
  it('302s to the loopback callback with the code/state carried through', async () => {
    const res = await fetch(
      `${baseUrl}/oauth/callback?code=deadbeef&state=nonce42`,
      { redirect: 'manual' },
    );
    expect(res.status).toBe(302);
    const loc = res.headers.get('location');
    expect(loc).not.toBeNull();
    const parsed = new URL(loc as string);
    expect(`${parsed.protocol}//${parsed.host}${parsed.pathname}`).toBe(
      CORE_LOOPBACK_CALLBACK,
    );
    expect(parsed.searchParams.get('code')).toBe('deadbeef');
    expect(parsed.searchParams.get('state')).toBe('nonce42');
  });

  it('never lets an authorization code be cached (Cache-Control: no-store)', async () => {
    const res = await fetch(`${baseUrl}/oauth/callback?code=x&state=y`, {
      redirect: 'manual',
    });
    expect(res.headers.get('cache-control')).toBe('no-store');
    expect(res.headers.get('referrer-policy')).toBe('no-referrer');
  });

  it('ships a no-JS fallback body with the manual finish link', async () => {
    const res = await fetch(`${baseUrl}/oauth/callback?code=x&state=y`, {
      redirect: 'manual',
    });
    const html = await res.text();
    expect(res.headers.get('content-type')).toContain('text/html');
    expect(html).toContain('127.0.0.1:8975/oauth/callback');
    expect(html).toContain('http-equiv="refresh"');
  });

  it('does not hijack unrelated paths (falls through to panva)', async () => {
    // The discovery document is a panva route; the bounce must not intercept it.
    const res = await fetch(
      `${baseUrl}/.well-known/openid-configuration`,
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(typeof body.issuer).toBe('string');
  });
});
