/**
 * PBA-L3a-007 (MEDIUM) — in production, RP origins left unset fell back to their
 * `http://localhost:*` dev defaults, and the production config gate passed while
 * the credentialed-CORS allowlist held those localhost origins (on every path,
 * including /admin). The audit's evidence/pba-l3a-prod-defaults.mts is the PoC.
 *
 * Fix under test: production never falls back to a dev origin (an unset RP
 * origin is dropped: no CORS echo, no redirect URI); a SET origin must be https
 * and non-local or boot refuses; credentialed CORS is never applied to /admin.
 */
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { assertProductionConfig, type ConfigEnv } from '../src/config.js';

const PROD_BASE: ConfigEnv = {
  NODE_ENV: 'production',
  ISSUER_URL: 'https://auth.citrate.ai',
  COOKIE_KEYS: 'x'.repeat(40),
  DATABASE_URL: 'postgres://h/db',
  REDIS_URL: 'redis://h',
};
const RP_VARS = [
  'EXPLORER_ORIGIN', 'DASHBOARD_ORIGIN', 'MEMRIZZ_ORIGIN', 'ATLAS_ORIGIN', 'DATAROOM_ORIGIN', 'FEDERATION_ORIGIN',
  'COMMS_WEB_ORIGIN', 'ALF_PORTAL_ORIGIN', 'BUYER_WEBAPP_ORIGIN', 'RADAR_ORIGIN', 'CORE_MEMBERSHIP_ORIGIN',
] as const;

describe('PBA-L3a-007 production origins fail closed', () => {
  const saved = { ...process.env };
  afterEach(() => {
    process.env = { ...saved };
    vi.resetModules();
  });

  it('the audit PoC is dead: a production boot with only the gated vars carries NO localhost / http CORS origin', async () => {
    for (const k of RP_VARS) delete process.env[k];
    Object.assign(process.env, PROD_BASE);
    vi.resetModules();
    const cfg = await import('../src/config.js');
    expect(() => cfg.assertProductionConfig(process.env)).not.toThrow();
    const origins = [...cfg.ALLOWED_CORS_ORIGINS];
    expect(origins.filter((o) => !o.startsWith('https://'))).toEqual([]);
    expect(origins.some((o) => o.includes('localhost'))).toBe(false);
  });

  it('an unset RP origin registers no redirect URI for its client in production', async () => {
    for (const k of RP_VARS) delete process.env[k];
    Object.assign(process.env, PROD_BASE);
    vi.resetModules();
    const cfg = await import('../src/config.js');
    const conf = (await cfg.buildConfiguration()) as { clients: Array<{ client_id: string; redirect_uris: string[]; post_logout_redirect_uris?: string[] }> };
    for (const c of conf.clients) {
      for (const u of [...c.redirect_uris, ...(c.post_logout_redirect_uris ?? [])]) {
        expect(u, `${c.client_id}: ${u}`).not.toMatch(/localhost:300\d|undefined/);
        expect(['http:', 'https:'], `${c.client_id}: ${u}`).toContain(new URL(u).protocol);
      }
    }
  });

  for (const v of RP_VARS) {
    it(`${v}: a set-but-local or non-https value refuses production boot`, () => {
      expect(() => assertProductionConfig({ ...PROD_BASE, [v]: 'http://localhost:3004' })).toThrow(new RegExp(`${v} points at a local host`));
      // whitespace-only counts as unset (dropped + reported), not as a bad URL
      expect(assertProductionConfig({ ...PROD_BASE, [v]: '   ' }).warnings.join('\n')).toContain(`${v} is unset`);
      expect(() => assertProductionConfig({ ...PROD_BASE, [v]: 'http://app.citrate.ai' })).toThrow(new RegExp(`${v}.*https`));
      expect(() => assertProductionConfig({ ...PROD_BASE, [v]: 'https://app.citrate.ai' })).not.toThrow();
    });
  }

  it('unset RP origins are reported (not silently defaulted) in production', () => {
    const { warnings } = assertProductionConfig({ ...PROD_BASE });
    for (const v of RP_VARS) expect(warnings.join('\n')).toContain(v);
  });

  it('CITRATE_ENV=production alone also disables the dev fallback', async () => {
    for (const k of RP_VARS) delete process.env[k];
    delete process.env.NODE_ENV;
    process.env.CITRATE_ENV = 'production';
    vi.resetModules();
    const cfg = await import('../src/config.js');
    expect(cfg.EXPLORER_ORIGIN).toBeUndefined();
    expect([...cfg.ALLOWED_CORS_ORIGINS].some((o) => o.includes('localhost'))).toBe(false);
  });

  it('a blank value is unset: dropped in production, dev default otherwise; a set value is trimmed', async () => {
    process.env.EXPLORER_ORIGIN = '  ';
    Object.assign(process.env, PROD_BASE);
    vi.resetModules();
    expect((await import('../src/config.js')).EXPLORER_ORIGIN).toBeUndefined();
    delete process.env.NODE_ENV;
    delete process.env.CITRATE_ENV;
    vi.resetModules();
    expect((await import('../src/config.js')).EXPLORER_ORIGIN).toBe('http://localhost:3001');
    process.env.EXPLORER_ORIGIN = ' https://explorer.example ';
    vi.resetModules();
    expect((await import('../src/config.js')).EXPLORER_ORIGIN).toBe('https://explorer.example');
  });

  it('STUDIO_ORIGIN stays optional but must be https and non-local when set', () => {
    expect(() => assertProductionConfig({ ...PROD_BASE, STUDIO_ORIGIN: 'http://localhost:5173' })).toThrow(/STUDIO_ORIGIN points at a local host/);
    expect(() => assertProductionConfig({ ...PROD_BASE, STUDIO_ORIGIN: 'http://studio.citrate.ai' })).toThrow(/STUDIO_ORIGIN must be an https origin/);
    expect(() => assertProductionConfig({ ...PROD_BASE, STUDIO_ORIGIN: 'https://studio.citrate.ai' })).not.toThrow();
    expect(() => assertProductionConfig({ ...PROD_BASE, STUDIO_ORIGIN: '' })).not.toThrow();
  });

  it('dev keeps the localhost defaults', async () => {
    for (const k of RP_VARS) delete process.env[k];
    delete process.env.NODE_ENV;
    delete process.env.CITRATE_ENV;
    vi.resetModules();
    const cfg = await import('../src/config.js');
    expect(cfg.EXPLORER_ORIGIN).toBe('http://localhost:3001');
  });
});

describe('PBA-L3a-007 credentialed CORS is not applied to /admin', () => {
  let server: Server;
  let baseUrl: string;
  let allowed: string;
  beforeAll(async () => {
    const { createProvider } = await import('../src/server.js');
    const cfg = await import('../src/config.js');
    allowed = [...cfg.ALLOWED_CORS_ORIGINS][0]!;
    const probe = createServer();
    await new Promise<void>((r) => probe.listen(0, '127.0.0.1', r));
    const { port } = probe.address() as AddressInfo;
    probe.close();
    baseUrl = `http://127.0.0.1:${port}`;
    const provider = await createProvider(baseUrl, { googleEnabled: false });
    server = createServer(provider.callback());
    await new Promise<void>((r) => server.listen(port, '127.0.0.1', r));
  });
  afterAll(async () => { await new Promise<void>((r) => server.close(() => r())); });

  it('an allow-listed RP origin gets no Access-Control-Allow-Origin on /admin/* (GET or preflight)', async () => {
    const g = await fetch(`${baseUrl}/admin/kyc/cases`, { headers: { origin: allowed } });
    expect(g.headers.get('access-control-allow-origin')).toBeNull();
    expect(g.headers.get('vary')).toMatch(/Origin/);
    const bare = await fetch(`${baseUrl}/admin`, { headers: { origin: allowed } });
    expect(bare.headers.get('access-control-allow-origin')).toBeNull();
    const p = await fetch(`${baseUrl}/admin/kyc/adjudicate`, { method: 'OPTIONS', headers: { origin: allowed, 'access-control-request-method': 'POST' } });
    expect(p.headers.get('access-control-allow-origin')).toBeNull();
  });

  it('isCorsExcludedPath covers /admin and its subtree only', async () => {
    const { isCorsExcludedPath } = await import('../src/http-extras.js');
    expect(isCorsExcludedPath('/admin')).toBe(true);
    expect(isCorsExcludedPath('/admin/kyc/cases')).toBe(true);
    expect(isCorsExcludedPath('/administrator')).toBe(false);
    expect(isCorsExcludedPath('/userinfo')).toBe(false);
  });

  it('the RP routes still get CORS', async () => {
    const r = await fetch(`${baseUrl}/jwks`, { headers: { origin: allowed } });
    expect(r.headers.get('access-control-allow-origin')).toBe(allowed);
  });
});
