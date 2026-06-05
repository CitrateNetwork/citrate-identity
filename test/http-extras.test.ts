import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createProvider } from '../src/server.js';
import { EXPLORER_ORIGIN, DASHBOARD_ORIGIN } from '../src/config.js';

/**
 * Deploy hardening: the operational HTTP extras mounted ahead of panva's router
 * (src/http-extras.ts):
 *
 *   - GET /health (+ /healthz alias) → 200 {status:"ok", redis?, db?}, lightweight
 *     and never-throwing. The LB / Caddy / devops curl hits this.
 *   - CORS on the cross-origin RP routes: an allow-listed RP origin gets its
 *     origin echoed in Access-Control-Allow-Origin (+ credentials); a random
 *     origin gets NO allow-origin header; an OPTIONS preflight is answered 204.
 */

// --- A) Default provider: no Redis / no Postgres wired (dev posture). ---
let baseServer: Server;
let baseUrl: string;

// --- B) Provider with injected health probes, to assert the redis/db fields. ---
let probedServer: Server;
let probedUrl: string;

async function listenProvider(
  factory: (baseUrl: string) => Promise<import('oidc-provider').default>,
): Promise<{ server: Server; baseUrl: string }> {
  const probe = createServer();
  await new Promise<void>((res) => probe.listen(0, '127.0.0.1', res));
  const { port } = probe.address() as AddressInfo;
  probe.close();
  const url = `http://127.0.0.1:${port}`;
  const provider = await factory(url);
  const server = createServer(provider.callback());
  await new Promise<void>((res) => server.listen(port, '127.0.0.1', res));
  return { server, baseUrl: url };
}

beforeAll(async () => {
  ({ server: baseServer, baseUrl } = await listenProvider((u) =>
    createProvider(u),
  ));
  ({ server: probedServer, baseUrl: probedUrl } = await listenProvider((u) =>
    createProvider(u, {
      pingRedis: async () => true,
      pingDb: async () => false,
    }),
  ));
});

afterAll(async () => {
  await new Promise<void>((res, rej) =>
    baseServer.close((err) => (err ? rej(err) : res())),
  );
  await new Promise<void>((res, rej) =>
    probedServer.close((err) => (err ? rej(err) : res())),
  );
});

describe('/health (liveness/readiness)', () => {
  it('returns 200 + {status:"ok"} with no Redis/PG configured (fields omitted)', async () => {
    const res = await fetch(`${baseUrl}/health`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.status).toBe('ok');
    // No probes wired → those fields are absent, not false.
    expect('redis' in body).toBe(false);
    expect('db' in body).toBe(false);
  });

  it('aliases /healthz to the same 200 {status:"ok"}', async () => {
    const res = await fetch(`${baseUrl}/healthz`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.status).toBe('ok');
  });

  it('reports the redis/db sub-fields when probes are wired, never throwing', async () => {
    const res = await fetch(`${probedUrl}/health`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.status).toBe('ok');
    expect(body.redis).toBe(true);
    // A failing dependency degrades to false — the endpoint still 200s.
    expect(body.db).toBe(false);
  });
});

describe('CORS (RP cross-origin)', () => {
  it('echoes an allow-listed RP origin with credentials', async () => {
    const res = await fetch(`${baseUrl}/health`, {
      headers: { origin: EXPLORER_ORIGIN },
    });
    expect(res.status).toBe(200);
    expect(res.headers.get('access-control-allow-origin')).toBe(EXPLORER_ORIGIN);
    expect(res.headers.get('access-control-allow-credentials')).toBe('true');
    expect(res.headers.get('vary')).toContain('Origin');
  });

  it('echoes the dashboard origin too (second allow-listed RP)', async () => {
    const res = await fetch(`${baseUrl}/health`, {
      headers: { origin: DASHBOARD_ORIGIN },
    });
    expect(res.headers.get('access-control-allow-origin')).toBe(DASHBOARD_ORIGIN);
  });

  it('does NOT echo a non-allow-listed origin (no wildcard, fail closed)', async () => {
    const res = await fetch(`${baseUrl}/health`, {
      headers: { origin: 'https://evil.example.com' },
    });
    expect(res.status).toBe(200);
    expect(res.headers.get('access-control-allow-origin')).toBeNull();
  });

  it('answers an OPTIONS preflight from an allowed origin with 204 + CORS headers', async () => {
    const res = await fetch(`${baseUrl}/siwe/verify`, {
      method: 'OPTIONS',
      headers: {
        origin: EXPLORER_ORIGIN,
        'access-control-request-method': 'POST',
        'access-control-request-headers': 'content-type',
      },
    });
    expect(res.status).toBe(204);
    expect(res.headers.get('access-control-allow-origin')).toBe(EXPLORER_ORIGIN);
    expect(res.headers.get('access-control-allow-methods')).toContain('POST');
    expect(res.headers.get('access-control-allow-headers')).toContain(
      'Authorization',
    );
  });

  it('answers an OPTIONS preflight from a disallowed origin 204 WITHOUT the echo', async () => {
    const res = await fetch(`${baseUrl}/siwe/verify`, {
      method: 'OPTIONS',
      headers: {
        origin: 'https://evil.example.com',
        'access-control-request-method': 'POST',
      },
    });
    expect(res.status).toBe(204);
    expect(res.headers.get('access-control-allow-origin')).toBeNull();
  });
});
