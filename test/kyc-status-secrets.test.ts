/**
 * GET /kyc/status secrets: dedicated, per caller, never the webhook secret.
 *
 * The webhook secret also authorizes POST /kyc/_set, which WRITES a "verified" record.
 * A status reader that held it could forge the very record it then re-checks, so
 * /kyc/status must never accept it:
 *   - no fallback to KYC_WEBHOOK_SECRET (unset status secrets → 503, endpoint off);
 *   - a status secret equal to the webhook secret → 503 (misconfigured, fail closed);
 *   - KYC_STATUS_SECRETS="name:secret,…" gives each caller its own secret, so one can
 *     be revoked without rotating the others; KYC_STATUS_SECRET stays as one more entry.
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type Provider from 'oidc-provider';
import { mountKycStatusRoute } from '../src/kyc-routes.js';
import { InMemoryKycStore, setKycStore, getKycStore } from '../src/kyc.js';

type Mw = (ctx: unknown, next: () => Promise<void>) => Promise<void>;
let server: Server | null = null;
let base = '';
const ENV_KEYS = ['KYC_STATUS_SECRET', 'KYC_STATUS_SECRETS', 'KYC_WEBHOOK_SECRET'] as const;
const saved: Record<string, string | undefined> = {};

/** Mount the route on a minimal Koa-shaped provider, with `env` as the process env. */
async function mount(env: Partial<Record<(typeof ENV_KEYS)[number], string>>): Promise<void> {
  for (const k of ENV_KEYS) { if (env[k] === undefined) delete process.env[k]; else process.env[k] = env[k]; }
  const mws: Mw[] = [];
  mountKycStatusRoute({ use: (fn: Mw) => { mws.push(fn); } } as unknown as Provider);
  server = createServer((req: IncomingMessage, res: ServerResponse) => {
    const u = new URL(req.url ?? '/', 'http://x');
    const ctx = { method: req.method, path: u.pathname, query: Object.fromEntries(u.searchParams), req, res };
    void mws[0]!(ctx, async () => { res.writeHead(404); res.end('{}'); });
  });
  await new Promise<void>((r) => server!.listen(0, '127.0.0.1', () => r()));
  base = `http://127.0.0.1:${(server!.address() as AddressInfo).port}`;
}
const get = async (secret: string | null, sub = 'u1') => {
  const res = await fetch(`${base}/kyc/status?sub=${sub}`, { headers: secret === null ? {} : { authorization: `Bearer ${secret}` } });
  return { status: res.status, json: (await res.json()) as Record<string, unknown> };
};

beforeEach(async () => {
  for (const k of ENV_KEYS) saved[k] = process.env[k];
  setKycStore(new InMemoryKycStore());
  await getKycStore().set('u1', { status: 'verified', vendor_ref: 'a', verified_at: '2026-06-18T00:00:00.000Z', expires_at: '2099-01-01T00:00:00.000Z' });
});
afterEach(async () => {
  for (const k of ENV_KEYS) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; }
  if (server) await new Promise<void>((r) => server!.close(() => r()));
  server = null;
});

describe('GET /kyc/status: no webhook-secret fallback', () => {
  it('is disabled (503) when only the webhook secret is set; the webhook secret is not accepted', async () => {
    await mount({ KYC_WEBHOOK_SECRET: 'webhook-secret-0123456789' });
    const r = await get('webhook-secret-0123456789');
    expect(r.status).toBe(503);
    expect(r.json.error).toBe('kyc_status_unconfigured');
  });

  it('refuses (503) when the status secret equals the webhook secret', async () => {
    await mount({ KYC_WEBHOOK_SECRET: 'same-secret-0123456789', KYC_STATUS_SECRET: 'same-secret-0123456789' });
    const r = await get('same-secret-0123456789');
    expect(r.status).toBe(503);
    expect(r.json.error).toBe('kyc_status_misconfigured');
  });

  it('refuses (503) when any per-caller secret equals the webhook secret', async () => {
    await mount({ KYC_WEBHOOK_SECRET: 'same-secret-0123456789', KYC_STATUS_SECRETS: 'membership:membership-secret-01234,signer:same-secret-0123456789' });
    expect((await get('membership-secret-01234')).status).toBe(503);
  });

  it('a dedicated status secret works; the webhook secret still does not', async () => {
    await mount({ KYC_WEBHOOK_SECRET: 'webhook-secret-0123456789', KYC_STATUS_SECRET: 'status-secret-0123456789' });
    expect((await get('status-secret-0123456789')).status).toBe(200);
    expect((await get('webhook-secret-0123456789')).status).toBe(401);
  });
});

describe('GET /kyc/status: per-caller secrets (KYC_STATUS_SECRETS)', () => {
  const SECRETS = 'membership:membership-secret-01234,treasury-signer:signer-secret-0123456';

  it('each listed caller authorizes with its own secret', async () => {
    await mount({ KYC_STATUS_SECRETS: SECRETS });
    const a = await get('membership-secret-01234');
    expect(a.status).toBe(200);
    expect(a.json.kyc_status).toBe('verified');
    expect((await get('signer-secret-0123456')).status).toBe(200);
    expect((await get('other-secret-000000000')).status).toBe(401);
    expect((await get(null)).status).toBe(401);
  });

  it('dropping one entry revokes that caller only', async () => {
    await mount({ KYC_STATUS_SECRETS: 'membership:membership-secret-01234' });
    expect((await get('membership-secret-01234')).status).toBe(200);
    expect((await get('signer-secret-0123456')).status).toBe(401);
  });

  it('KYC_STATUS_SECRET is accepted alongside the list', async () => {
    await mount({ KYC_STATUS_SECRETS: SECRETS, KYC_STATUS_SECRET: 'legacy-status-secret-0123' });
    expect((await get('legacy-status-secret-0123')).status).toBe(200);
    expect((await get('signer-secret-0123456')).status).toBe(200);
  });

  it.each([
    ['entry without a name', 'membership-secret-01234'],
    ['empty secret', 'membership:'],
    ['short secret', 'membership:short'],
    ['duplicate name', 'a:membership-secret-01234,a:signer-secret-0123456'],
    ['bad name', 'Bad Name!:membership-secret-01234'],
  ])('a malformed list (%s) disables the endpoint (503), it is not half-applied', async (_l, v) => {
    await mount({ KYC_STATUS_SECRETS: v });
    const r = await get('membership-secret-01234');
    expect(r.status).toBe(503);
    expect(r.json.error).toBe('kyc_status_misconfigured');
  });

  it('two callers may not share a secret (503)', async () => {
    await mount({ KYC_STATUS_SECRETS: 'a:shared-secret-0123456789,b:shared-secret-0123456789' });
    expect((await get('shared-secret-0123456789')).status).toBe(503);
  });
});
