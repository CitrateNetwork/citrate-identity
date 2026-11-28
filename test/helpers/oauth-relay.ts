/**
 * Shared fixtures for the OAuth relay suites (Slack, LinkedIn, exact callbacks).
 *
 * Outbound HTTP goes through an injected fetch seam that records the URL the
 * relay asked for and forwards the request to a local fake upstream server
 * (test fixture only). The production provider table is never edited for tests.
 */
import { createServer, type IncomingMessage, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import type Provider from 'oidc-provider';
import { createProvider } from '../../src/server.js';
import { InMemoryRateLimiter } from '../../src/auth/rate-limit.js';
import type { OAuthRelayOptions, RelayLogger } from '../../src/oauth-relay/routes.js';

export interface Seen {
  /** The URL the relay asked fetch for (before the seam rewrote it). */
  requestedUrl: string;
  method: string;
  headers: IncomingMessage['headers'];
  body: string;
}

export interface Reply {
  status: number;
  body: string;
  contentType?: string;
}

export interface Upstream {
  server: Server;
  base: string;
  seen: Seen[];
  reply: (s: Seen) => Reply;
  pendingUrls: string[];
}

export async function startUpstream(): Promise<Upstream> {
  const up: Upstream = {
    server: undefined as unknown as Server,
    base: '',
    seen: [],
    reply: () => ({ status: 200, body: '{}' }),
    pendingUrls: [],
  };
  up.server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      const s: Seen = {
        requestedUrl: up.pendingUrls.shift() ?? '',
        method: req.method ?? '',
        headers: req.headers,
        body: Buffer.concat(chunks).toString('utf8'),
      };
      up.seen.push(s);
      const r = up.reply(s);
      res.writeHead(r.status, { 'content-type': r.contentType ?? 'application/json; charset=utf-8' });
      res.end(r.body);
    });
  });
  await new Promise<void>((res) => up.server.listen(0, '127.0.0.1', res));
  up.base = `http://127.0.0.1:${(up.server.address() as AddressInfo).port}`;
  return up;
}

/** Fetch seam: record the requested URL, send the request to the fake upstream. */
export function seamFetch(up: Upstream): typeof fetch {
  return (async (input: string | URL | Request, init?: RequestInit) => {
    const requested = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
    const u = new URL(requested);
    up.pendingUrls.push(requested);
    return fetch(`${up.base}${u.pathname}${u.search}`, init);
  }) as typeof fetch;
}

export function captureLogger(): { logger: RelayLogger; lines: string[] } {
  const lines: string[] = [];
  const mk = () => (...args: unknown[]) => {
    lines.push(args.map(String).join(' '));
  };
  return { logger: { info: mk(), warn: mk(), error: mk() }, lines };
}

export interface Authority {
  provider: Provider;
  server: Server;
  base: string;
}

export async function startAuthority(relay: OAuthRelayOptions): Promise<Authority> {
  const probe = createServer();
  await new Promise<void>((res) => probe.listen(0, '127.0.0.1', res));
  const { port } = probe.address() as AddressInfo;
  probe.close();
  const base = `http://127.0.0.1:${port}`;
  const provider = await createProvider(base, {
    rateLimiter: new InMemoryRateLimiter(),
    oauthRelay: relay,
  });
  const server = createServer(provider.callback());
  await new Promise<void>((res) => server.listen(port, '127.0.0.1', res));
  return { provider, server, base };
}

export async function stop(s: Server): Promise<void> {
  await new Promise<void>((res, rej) => s.close((e) => (e ? rej(e) : res())));
}

/** A real auth.citrate.ai access token, minted in the authority's own adapter. */
export async function mintAccessToken(provider: Provider, accountId: string, clientId = 'citrate-core'): Promise<string> {
  const client = await provider.Client.find(clientId);
  if (!client) throw new Error(`client ${clientId} not registered`);
  const at = new provider.AccessToken({
    accountId,
    client,
    scope: 'openid',
    gty: 'authorization_code',
    grantId: `test-grant-${accountId}`,
  } as never);
  return at.save();
}

export function post(a: Authority, path: string, body: unknown, token?: string): Promise<Response> {
  return fetch(`${a.base}${path}`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(body),
  });
}

/** GET without following redirects. */
export function getManual(a: Authority, path: string): Promise<Response> {
  return fetch(`${a.base}${path}`, { redirect: 'manual' });
}

export const VERIFIER = 'v'.repeat(20) + '-._~' + 'A1b2C3d4E5f6G7h8I9j0K'; // 45 chars, RFC 7636 alphabet
