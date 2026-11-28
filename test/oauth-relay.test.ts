/**
 * L6-WP04: OAuth token relay on auth.citrate.ai (src/oauth-relay/).
 *
 * The desktop app never holds a provider client secret. It POSTs the
 * authorization code + PKCE verifier here with its auth.citrate.ai access token;
 * the relay adds the secret server side, calls the provider's FIXED token
 * endpoint, and hands the provider's answer back unchanged.
 *
 * Outbound HTTP goes through the injected fetch seam, which records the URL the
 * relay asked for and forwards the request to a local fake upstream server (test
 * fixture only). The production provider table is never edited for tests.
 */
import { createServer, type IncomingMessage, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import type Provider from 'oidc-provider';
import { createProvider } from '../src/server.js';
import { InMemoryRateLimiter } from '../src/auth/rate-limit.js';
import { CORE_LOOPBACK_CALLBACK } from '../src/oauth-bounce.js';
import { HOSTED_BOUNCE_REDIRECT } from '../src/oauth-relay/providers.js';
import type { OAuthRelayOptions, RelayLogger } from '../src/oauth-relay/routes.js';
import {
  InMemoryAccountEpochStore,
  getAccountEpochStore,
  setAccountEpochStore,
} from '../src/auth/account-epoch.js';

// ---- fixtures ---------------------------------------------------------------

const GH_ID = 'Iv1.testclientid0001';
const GH_SECRET = 'fixture-gh-' + 's'.repeat(32); // test-only, not a credential
const NOTION_ID = 'notion-test-client-id';
const NOTION_SECRET = 'fixture-notion-' + 'n'.repeat(32); // test-only, not a credential
const ENV_BOTH = {
  GITHUB_CLIENT_ID: GH_ID,
  GITHUB_CLIENT_SECRET: GH_SECRET,
  NOTION_CLIENT_ID: NOTION_ID,
  NOTION_CLIENT_SECRET: NOTION_SECRET,
};

const CODE = 'auth-code-7f3a9c1e2b4d';
const VERIFIER = 'v'.repeat(20) + '-._~' + 'A1b2C3d4E5f6G7h8I9j0K'; // 45 chars, RFC 7636 alphabet

interface Seen {
  /** The URL the relay asked fetch for (before the seam rewrote it). */
  requestedUrl: string;
  method: string;
  path: string;
  headers: IncomingMessage['headers'];
  body: string;
}

interface Upstream {
  server: Server;
  base: string;
  seen: Seen[];
  reply: (s: Seen) => { status: number; body: string; contentType?: string; headers?: Record<string, string> };
}

async function startUpstream(): Promise<Upstream> {
  const up: Upstream = {
    server: undefined as unknown as Server,
    base: '',
    seen: [],
    reply: () => ({ status: 200, body: '{}' }),
  };
  const pendingUrls: string[] = [];
  up.server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      const s: Seen = {
        requestedUrl: pendingUrls.shift() ?? '',
        method: req.method ?? '',
        path: req.url ?? '',
        headers: req.headers,
        body: Buffer.concat(chunks).toString('utf8'),
      };
      up.seen.push(s);
      const r = up.reply(s);
      res.writeHead(r.status, { 'content-type': r.contentType ?? 'application/json; charset=utf-8', ...(r.headers ?? {}) });
      res.end(r.body);
    });
  });
  await new Promise<void>((res) => up.server.listen(0, '127.0.0.1', res));
  up.base = `http://127.0.0.1:${(up.server.address() as AddressInfo).port}`;
  // Expose the seam's URL queue on the object so the fetch seam can push to it.
  (up as Upstream & { pendingUrls: string[] }).pendingUrls = pendingUrls;
  return up;
}

/** Fetch seam: record the requested URL, send the request to the fake upstream. */
function seamFetch(up: Upstream): typeof fetch {
  const queue = (up as Upstream & { pendingUrls: string[] }).pendingUrls;
  return (async (input: string | URL | Request, init?: RequestInit) => {
    const requested = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
    const u = new URL(requested);
    queue.push(requested);
    return fetch(`${up.base}${u.pathname}${u.search}`, init);
  }) as typeof fetch;
}

interface Logged {
  level: string;
  args: unknown[];
}

function captureLogger(): { logger: RelayLogger; lines: Logged[] } {
  const lines: Logged[] = [];
  const mk = (level: string) => (...args: unknown[]) => {
    lines.push({ level, args });
  };
  return { logger: { info: mk('info'), warn: mk('warn'), error: mk('error') }, lines };
}

interface Authority {
  provider: Provider;
  server: Server;
  base: string;
}

async function startAuthority(relay: OAuthRelayOptions): Promise<Authority> {
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

async function stop(s: Server): Promise<void> {
  await new Promise<void>((res, rej) => s.close((e) => (e ? rej(e) : res())));
}

/** A real auth.citrate.ai access token, minted in the authority's own adapter. */
async function mintAccessToken(
  provider: Provider,
  accountId: string,
  clientId = 'citrate-core',
  opts: { iat?: number; expiresIn?: number } = {},
): Promise<string> {
  const client = await provider.Client.find(clientId);
  if (!client) throw new Error(`client ${clientId} not registered`);
  const at = new provider.AccessToken({
    accountId,
    client,
    scope: 'openid',
    gty: 'authorization_code',
    grantId: `test-grant-${accountId}`,
    ...(opts.iat !== undefined ? { iat: opts.iat } : {}),
    ...(opts.expiresIn !== undefined ? { expiresIn: opts.expiresIn } : {}),
  } as never);
  return at.save();
}

function post(
  a: Authority,
  path: string,
  body: unknown,
  token?: string,
  extraHeaders: Record<string, string> = {},
): Promise<Response> {
  return fetch(`${a.base}${path}`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      ...extraHeaders,
    },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  });
}

const tokenBody = (over: Record<string, unknown> = {}) => ({
  code: CODE,
  code_verifier: VERIFIER,
  redirect_uri: CORE_LOOPBACK_CALLBACK,
  ...over,
});

// ---- shared authority (both providers configured) ----------------------------

let up: Upstream;
let auth: Authority;
let log: ReturnType<typeof captureLogger>;
let member: string;

beforeAll(async () => {
  up = await startUpstream();
  log = captureLogger();
  auth = await startAuthority({ fetch: seamFetch(up), env: ENV_BOTH, logger: log.logger });
  member = await mintAccessToken(auth.provider, 'member-shared');
});

afterAll(async () => {
  await stop(auth.server);
  await stop(up.server);
});

afterEach(() => {
  up.seen.length = 0;
  up.reply = () => ({ status: 200, body: '{}' });
  vi.restoreAllMocks();
});

const GH_TOKEN_RESPONSE = JSON.stringify({
  access_token: 'ghu_' + 'a'.repeat(36),
  expires_in: 28800,
  refresh_token: 'ghr_' + 'b'.repeat(76),
  refresh_token_expires_in: 15897600,
  scope: '',
  token_type: 'bearer',
});

// ---- the lane spec's 10 -------------------------------------------------------

describe('oauth relay: lane spec RED set', () => {
  it('unknown_provider_makes_no_outbound_call (404 unknown_provider)', async () => {
    const r = await post(auth, '/oauth/relay/v1/evil.example/token', tokenBody(), member);
    expect(r.status).toBe(404);
    expect(await r.json()).toMatchObject({ error: 'unknown_provider' });
    const r2 = await post(auth, '/oauth/relay/v1/__proto__/token', tokenBody(), member);
    expect(r2.status).toBe(404);
    expect(up.seen).toHaveLength(0);
  });

  it('redirect_uri_must_be_registered_value (400, no outbound call)', async () => {
    for (const redirect_uri of [
      'http://127.0.0.1:8976/oauth/callback',
      'http://localhost:8975/oauth/callback',
      'https://attacker.example/cb',
      HOSTED_BOUNCE_REDIRECT, // registered for Notion, not GitHub
      CORE_LOOPBACK_CALLBACK + '/',
    ]) {
      const r = await post(auth, '/oauth/relay/v1/github/token', tokenBody({ redirect_uri }), member);
      expect(r.status, redirect_uri).toBe(400);
      expect(await r.json()).toMatchObject({ error: 'bad_request' });
    }
    expect(up.seen).toHaveLength(0);
  });

  it('code_verifier_required (and must be RFC 7636 shaped)', async () => {
    const { code_verifier: _omit, ...noVerifier } = tokenBody();
    for (const body of [noVerifier, tokenBody({ code_verifier: 'short' }), tokenBody({ code_verifier: 'x'.repeat(129) }), tokenBody({ code_verifier: 'a b'.repeat(20) })]) {
      const r = await post(auth, '/oauth/relay/v1/github/token', body, member);
      expect(r.status).toBe(400);
      expect(await r.json()).toMatchObject({ error: 'bad_request' });
    }
    expect(up.seen).toHaveLength(0);
  });

  it('secret_added_server_side_only', async () => {
    up.reply = () => ({ status: 200, body: GH_TOKEN_RESPONSE });
    // A client-supplied client_id/client_secret is never forwarded.
    const r = await post(
      auth,
      '/oauth/relay/v1/github/token',
      tokenBody({ client_id: 'attacker-app', client_secret: 'attacker-secret' }),
      member,
    );
    expect(r.status).toBe(200);
    const text = await r.text();
    expect(text).not.toContain(GH_SECRET);
    expect(up.seen).toHaveLength(1);
    const out = new URLSearchParams(up.seen[0].body);
    expect(up.seen[0].requestedUrl).toBe('https://github.com/login/oauth/access_token');
    expect(up.seen[0].method).toBe('POST');
    expect(out.get('client_id')).toBe(GH_ID);
    expect(out.get('client_secret')).toBe(GH_SECRET);
    expect(out.get('code')).toBe(CODE);
    expect(out.get('code_verifier')).toBe(VERIFIER);
    expect(out.get('redirect_uri')).toBe(CORE_LOOPBACK_CALLBACK);
    expect(out.get('grant_type')).toBe('authorization_code');
    expect(up.seen[0].body).not.toContain('attacker');
    // The member's auth.citrate.ai token never goes upstream.
    expect(up.seen[0].headers.authorization).toBeUndefined();
    expect(up.seen[0].body).not.toContain(member);
  });

  it('response_passed_through_unchanged', async () => {
    const odd = '{"access_token":"gho_x","token_type":"bearer","scope":"repo","extra":{"nested":[1,2]}}';
    up.reply = () => ({ status: 200, body: odd });
    const r = await post(auth, '/oauth/relay/v1/github/token', tokenBody(), member);
    expect(r.status).toBe(200);
    expect(await r.text()).toBe(odd);
    expect(r.headers.get('content-type')).toMatch(/application\/json/);
  });

  it('no_body_logged (logger + console see no code, verifier, token or secret)', async () => {
    const consoleLines: string[] = [];
    for (const m of ['log', 'info', 'warn', 'error', 'debug'] as const) {
      vi.spyOn(console, m).mockImplementation((...a: unknown[]) => {
        consoleLines.push(a.map(String).join(' '));
      });
    }
    log.lines.length = 0;
    up.reply = () => ({ status: 200, body: GH_TOKEN_RESPONSE });
    await post(auth, '/oauth/relay/v1/github/token', tokenBody(), member);
    up.reply = () => ({ status: 400, body: '{"error":"invalid_grant","echo":"' + CODE + '"}' });
    await post(auth, '/oauth/relay/v1/notion/token', tokenBody({ redirect_uri: HOSTED_BOUNCE_REDIRECT }), member);
    await post(auth, '/oauth/relay/v1/github/refresh', { refresh_token: 'ghr_' + 'b'.repeat(76) }, member);
    up.reply = () => ({ status: 204, body: '' });
    await post(auth, '/oauth/relay/v1/github/revoke', { token: 'ghu_' + 'a'.repeat(36) }, member);

    const everything = [
      ...log.lines.map((l) => JSON.stringify(l.args)),
      ...consoleLines,
    ].join('\n');
    expect(log.lines.length).toBeGreaterThan(0); // it does log outcomes
    for (const secretish of [CODE, VERIFIER, GH_SECRET, NOTION_SECRET, 'ghu_', 'ghr_', member, 'access_token', 'refresh_token']) {
      expect(everything, secretish).not.toContain(secretish);
    }
  });

  it('cache_control_no_store on success and error', async () => {
    up.reply = () => ({ status: 200, body: GH_TOKEN_RESPONSE });
    const ok = await post(auth, '/oauth/relay/v1/github/token', tokenBody(), member);
    expect(ok.headers.get('cache-control')).toBe('no-store');
    expect(ok.headers.get('pragma')).toBe('no-cache');
    const bad = await post(auth, '/oauth/relay/v1/github/token', tokenBody({ redirect_uri: 'x' }), member);
    expect(bad.headers.get('cache-control')).toBe('no-store');
  });

  it('rate_limit_per_ip_and_install (per account, and per IP across accounts)', async () => {
    const a = await startAuthority({
      fetch: seamFetch(up),
      env: ENV_BOTH,
      logger: captureLogger().logger,
      limits: { perAccount: 2, perIp: 4 },
    });
    try {
      up.reply = () => ({ status: 200, body: GH_TOKEN_RESPONSE });
      const t1 = await mintAccessToken(a.provider, 'member-rl-1');
      const t2 = await mintAccessToken(a.provider, 'member-rl-2');
      expect((await post(a, '/oauth/relay/v1/github/token', tokenBody(), t1)).status).toBe(200);
      expect((await post(a, '/oauth/relay/v1/github/token', tokenBody(), t1)).status).toBe(200);
      const limited = await post(a, '/oauth/relay/v1/github/token', tokenBody(), t1);
      expect(limited.status).toBe(429);
      expect(await limited.json()).toMatchObject({ error: 'rate_limited' });
      // Same IP, a different account: one more call fits the IP budget (4: the 429 above counted too)...
      expect((await post(a, '/oauth/relay/v1/github/token', tokenBody(), t2)).status).toBe(200);
      // ...then the IP budget is spent for everyone on it.
      const ipLimited = await post(a, '/oauth/relay/v1/github/token', tokenBody(), t2);
      expect(ipLimited.status).toBe(429);
      expect(up.seen).toHaveLength(3);
    } finally {
      await stop(a.server);
    }
  });

  it('refresh_requires_refresh_token, then exchanges it with the secret', async () => {
    const r = await post(auth, '/oauth/relay/v1/github/refresh', {}, member);
    expect(r.status).toBe(400);
    expect(await r.json()).toMatchObject({ error: 'bad_request' });
    expect(up.seen).toHaveLength(0);

    up.reply = () => ({ status: 200, body: GH_TOKEN_RESPONSE });
    const ok = await post(auth, '/oauth/relay/v1/github/refresh', { refresh_token: 'ghr_abc' }, member);
    expect(ok.status).toBe(200);
    expect(await ok.text()).toBe(GH_TOKEN_RESPONSE);
    const out = new URLSearchParams(up.seen[0].body);
    expect(up.seen[0].requestedUrl).toBe('https://github.com/login/oauth/access_token');
    expect(out.get('grant_type')).toBe('refresh_token');
    expect(out.get('refresh_token')).toBe('ghr_abc');
    expect(out.get('client_secret')).toBe(GH_SECRET);
  });

  it('revoke_calls_provider_revocation_endpoint_when_present (GitHub), refuses where absent (Notion)', async () => {
    up.reply = () => ({ status: 204, body: '' });
    const r = await post(auth, '/oauth/relay/v1/github/revoke', { token: 'gho_tok' }, member);
    expect(r.status).toBe(200);
    expect(await r.json()).toEqual({ revoked: true, upstream_status: 204 });
    expect(up.seen).toHaveLength(1);
    expect(up.seen[0].requestedUrl).toBe(`https://api.github.com/applications/${GH_ID}/token`);
    expect(up.seen[0].method).toBe('DELETE');

    up.seen.length = 0;
    const n = await post(auth, '/oauth/relay/v1/notion/revoke', { token: 'x' }, member);
    expect(n.status).toBe(400);
    expect(await n.json()).toMatchObject({ error: 'unsupported_operation' });
    expect(up.seen).toHaveLength(0);
  });
});

// ---- the lead's additional set -------------------------------------------------

describe('oauth relay: additional required tests', () => {
  it('rejects_unregistered_redirect for Notion too (only the hosted bounce)', async () => {
    const r = await post(auth, '/oauth/relay/v1/notion/token', tokenBody({ redirect_uri: CORE_LOOPBACK_CALLBACK }), member);
    expect(r.status).toBe(400);
    expect(up.seen).toHaveLength(0);
  });

  it('rejects_unauthenticated (no bearer, garbage bearer, other RP client) with no outbound call', async () => {
    const none = await post(auth, '/oauth/relay/v1/github/token', tokenBody());
    expect(none.status).toBe(401);
    expect(await none.json()).toMatchObject({ error: 'not_signed_in' });
    const junk = await post(auth, '/oauth/relay/v1/github/token', tokenBody(), 'not-a-real-token');
    expect(junk.status).toBe(401);
    const explorerTok = await mintAccessToken(auth.provider, 'member-rp', 'citrate-explorer');
    const other = await post(auth, '/oauth/relay/v1/github/token', tokenBody(), explorerTok);
    expect(other.status).toBe(403);
    expect(await other.json()).toMatchObject({ error: 'client_not_permitted' });
    expect(up.seen).toHaveLength(0);
  });

  it('kill_switch OAUTH_RELAY=0 answers 503 relay_disabled with no outbound call', async () => {
    const a = await startAuthority({ fetch: seamFetch(up), env: { ...ENV_BOTH, OAUTH_RELAY: '0' } });
    try {
      const t = await mintAccessToken(a.provider, 'member-ks');
      const r = await post(a, '/oauth/relay/v1/github/token', tokenBody(), t);
      expect(r.status).toBe(503);
      expect(await r.json()).toMatchObject({ error: 'relay_disabled' });
      expect(up.seen).toHaveLength(0);
    } finally {
      await stop(a.server);
    }
  });

  it('unknown_provider_404 and unknown operation 404', async () => {
    const r = await post(auth, '/oauth/relay/v1/gitlab/token', tokenBody(), member);
    expect(r.status).toBe(404);
    expect(await r.json()).toMatchObject({ error: 'unknown_provider' });
    const op = await post(auth, '/oauth/relay/v1/github/authorize', tokenBody(), member);
    expect(op.status).toBe(404);
    const get = await fetch(`${auth.base}/oauth/relay/v1/github/token`);
    expect(get.status).toBe(405);
    expect(up.seen).toHaveLength(0);
  });

  it('missing_secret_503: a provider without a configured secret is never called', async () => {
    const a = await startAuthority({
      fetch: seamFetch(up),
      env: { GITHUB_CLIENT_ID: GH_ID, NOTION_CLIENT_ID: NOTION_ID, NOTION_CLIENT_SECRET: '  ' },
    });
    try {
      const t = await mintAccessToken(a.provider, 'member-ms');
      for (const p of ['github', 'notion']) {
        const r = await post(a, `/oauth/relay/v1/${p}/token`, tokenBody(), t);
        expect(r.status, p).toBe(503);
        const j = (await r.json()) as { error: string; reason: string };
        expect(j.error).toBe('not_configured');
        expect(j.reason).toContain(`${p.toUpperCase()}_CLIENT_SECRET`);
      }
      expect(up.seen).toHaveLength(0);
    } finally {
      await stop(a.server);
    }
  });

  it('rate_limited_429 carries retry-after', async () => {
    const a = await startAuthority({ fetch: seamFetch(up), env: ENV_BOTH, limits: { perAccount: 1 } });
    try {
      up.reply = () => ({ status: 200, body: GH_TOKEN_RESPONSE });
      const t = await mintAccessToken(a.provider, 'member-429');
      expect((await post(a, '/oauth/relay/v1/github/token', tokenBody(), t)).status).toBe(200);
      const r = await post(a, '/oauth/relay/v1/github/token', tokenBody(), t);
      expect(r.status).toBe(429);
      expect(r.headers.get('retry-after')).toMatch(/^\d+$/);
      expect(up.seen).toHaveLength(1);
    } finally {
      await stop(a.server);
    }
  });

  it('long_token_passthrough: a 400+ char access_token round-trips unchanged', async () => {
    const longToken = 'ghu_' + 'Zz9-_.~'.repeat(80) + 'end'; // 567 chars, mixed alphabet
    expect(longToken.length).toBeGreaterThan(400);
    const body = JSON.stringify({ access_token: longToken, token_type: 'bearer', scope: 'repo' });
    up.reply = () => ({ status: 200, body });
    const r = await post(auth, '/oauth/relay/v1/github/token', tokenBody(), member);
    expect(r.status).toBe(200);
    const text = await r.text();
    expect(text).toBe(body);
    expect((JSON.parse(text) as { access_token: string }).access_token).toBe(longToken);
  });

  it('revoke_uses_basic_auth with body {access_token} and no secret in the body', async () => {
    up.reply = () => ({ status: 204, body: '' });
    await post(auth, '/oauth/relay/v1/github/revoke', { token: 'gho_revoke_me' }, member);
    const s = up.seen[0];
    const expected = 'Basic ' + Buffer.from(`${GH_ID}:${GH_SECRET}`).toString('base64');
    expect(s.headers.authorization).toBe(expected);
    expect(JSON.parse(s.body)).toEqual({ access_token: 'gho_revoke_me' });
    expect(s.body).not.toContain(GH_SECRET);
    expect(s.headers.accept).toBe('application/vnd.github+json');
    expect(s.headers['x-github-api-version']).toBe('2022-11-28');
  });

  it('revoke reports an upstream failure honestly', async () => {
    up.reply = () => ({ status: 404, body: '{"message":"Not Found"}' });
    const r = await post(auth, '/oauth/relay/v1/github/revoke', { token: 'gho_gone' }, member);
    expect(r.status).toBe(502);
    expect(await r.json()).toEqual({ error: 'provider_rejected', revoked: false, upstream_status: 404 });
  });

  it('upstream error passthrough without secret echo', async () => {
    // A provider error passes through with its status and body...
    const err = '{"error":"invalid_grant","error_description":"bad code"}';
    up.reply = () => ({ status: 400, body: err });
    const r = await post(auth, '/oauth/relay/v1/notion/token', tokenBody({ redirect_uri: HOSTED_BOUNCE_REDIRECT }), member);
    expect(r.status).toBe(400);
    expect(await r.text()).toBe(err);
    // Notion: Basic auth, JSON body, no secret in the body.
    const s = up.seen[0];
    expect(s.requestedUrl).toBe('https://api.notion.com/v1/oauth/token');
    expect(s.headers.authorization).toBe('Basic ' + Buffer.from(`${NOTION_ID}:${NOTION_SECRET}`).toString('base64'));
    expect(JSON.parse(s.body)).toEqual({
      grant_type: 'authorization_code',
      code: CODE,
      code_verifier: VERIFIER,
      redirect_uri: HOSTED_BOUNCE_REDIRECT,
    });

    // ...but a response that echoes the secret is never relayed.
    up.reply = () => ({ status: 400, body: `{"error":"bad","client_secret":"${GH_SECRET}"}` });
    const echo = await post(auth, '/oauth/relay/v1/github/token', tokenBody(), member);
    expect(echo.status).toBe(502);
    const t = await echo.text();
    expect(t).not.toContain(GH_SECRET);
    expect(JSON.parse(t)).toMatchObject({ error: 'provider_rejected' });
    // GitHub's 200-with-error style also passes through as-is.
    const ghErr = '{"error":"bad_verification_code","error_description":"The code passed is incorrect or expired."}';
    up.reply = () => ({ status: 200, body: ghErr });
    const g = await post(auth, '/oauth/relay/v1/github/token', tokenBody(), member);
    expect(g.status).toBe(200);
    expect(await g.text()).toBe(ghErr);
  });

  it('body cap: more than 8 KiB is refused with no outbound call', async () => {
    const r = await post(auth, '/oauth/relay/v1/github/token', tokenBody({ pad: 'p'.repeat(8 * 1024) }), member);
    expect(r.status).toBe(413);
    expect(await r.json()).toMatchObject({ error: 'bad_request' });
    const notJson = await post(auth, '/oauth/relay/v1/github/token', 'code=abc', member);
    expect(notJson.status).toBe(400);
    expect(up.seen).toHaveLength(0);
  });

  it('resource (RFC 8707) is forwarded only when it is an https URL', async () => {
    up.reply = () => ({ status: 200, body: GH_TOKEN_RESPONSE });
    await post(auth, '/oauth/relay/v1/github/token', tokenBody({ resource: 'https://api.githubcopilot.com/mcp/' }), member);
    expect(new URLSearchParams(up.seen[0].body).get('resource')).toBe('https://api.githubcopilot.com/mcp/');
    const bad = await post(auth, '/oauth/relay/v1/github/token', tokenBody({ resource: 'http://insecure.example' }), member);
    expect(bad.status).toBe(400);
    expect(up.seen).toHaveLength(1);
  });

  it('upstream redirects are not followed (the secret never leaves the fixed URL)', async () => {
    // A 307 would replay the POST body (with the secret) to the Location.
    up.reply = (s) =>
      s.path === '/stolen'
        ? { status: 200, body: '{"access_token":"from-the-redirect-target"}' }
        : { status: 307, body: '', contentType: 'text/plain', headers: { location: `${up.base}/stolen` } };
    const r = await post(auth, '/oauth/relay/v1/github/token', tokenBody(), member);
    expect(r.status).toBe(502);
    expect(await r.json()).toMatchObject({ error: 'provider_rejected' });
    expect(up.seen).toHaveLength(1);
    expect(up.seen.some((x) => x.path === '/stolen')).toBe(false);
  });
});

// ---- #52 follow-ups -------------------------------------------------------------

describe('oauth relay: #52 follow-ups', () => {
  const nowSec = () => Math.floor(Date.now() / 1000);
  afterEach(() => setAccountEpochStore(new InMemoryAccountEpochStore()));

  it('account epoch: a token issued before a password reset / sign out everywhere is refused 401, no outbound call', async () => {
    up.reply = () => ({ status: 200, body: GH_TOKEN_RESPONSE });
    const old = await mintAccessToken(auth.provider, 'member-epoch-old', 'citrate-core', { iat: nowSec() - 60 });
    expect((await post(auth, '/oauth/relay/v1/github/token', tokenBody(), old)).status).toBe(200);
    up.seen.length = 0;

    await getAccountEpochStore().bump('member-epoch-old', nowSec());
    for (const op of ['token', 'refresh', 'revoke']) {
      const r = await post(auth, `/oauth/relay/v1/github/${op}`, op === 'token' ? tokenBody() : { refresh_token: 'r', token: 't' }, old);
      expect(r.status, op).toBe(401);
      expect(await r.json()).toMatchObject({ error: 'not_signed_in' });
    }
    expect(up.seen).toHaveLength(0);
  });

  it('account epoch: a token issued after the epoch works', async () => {
    up.reply = () => ({ status: 200, body: GH_TOKEN_RESPONSE });
    await getAccountEpochStore().bump('member-epoch-fresh', nowSec() - 30);
    const fresh = await mintAccessToken(auth.provider, 'member-epoch-fresh');
    const r = await post(auth, '/oauth/relay/v1/github/token', tokenBody(), fresh);
    expect(r.status).toBe(200);
    expect(await r.text()).toBe(GH_TOKEN_RESPONSE);
  });

  it('an expired access token is refused 401 with no outbound call', async () => {
    const short = await mintAccessToken(auth.provider, 'member-expired', 'citrate-core', { expiresIn: 60 });
    const realNow = Date.now();
    vi.spyOn(Date, 'now').mockImplementation(() => realNow + 120_000);
    const r = await post(auth, '/oauth/relay/v1/github/token', tokenBody(), short);
    expect(r.status).toBe(401);
    expect(await r.json()).toMatchObject({ error: 'not_signed_in' });
    expect(up.seen).toHaveLength(0);
  });

  it('an answer echoing the secret form-encoded (space as +, !\'()~ escaped) is withheld', async () => {
    const secret = "fixture secret (form)!~'" + 'f'.repeat(24); // test-only, not a credential
    const formEncoded = new URLSearchParams({ s: secret }).toString().slice(2);
    // The variant differs from both the raw and the encodeURIComponent forms.
    expect(formEncoded).not.toBe(encodeURIComponent(secret));
    expect(formEncoded).toContain('+');
    const a = await startAuthority({
      fetch: seamFetch(up),
      env: { GITHUB_CLIENT_ID: GH_ID, GITHUB_CLIENT_SECRET: secret },
      logger: captureLogger().logger,
    });
    try {
      const t = await mintAccessToken(a.provider, 'member-form-echo');
      up.reply = () => ({ status: 400, body: `error=bad&echo=${formEncoded}`, contentType: 'application/x-www-form-urlencoded' });
      const r = await post(a, '/oauth/relay/v1/github/token', tokenBody(), t);
      expect(r.status).toBe(502);
      const text = await r.text();
      expect(text).not.toContain(formEncoded);
      expect(JSON.parse(text)).toMatchObject({ error: 'provider_rejected' });
    } finally {
      await stop(a.server);
    }
  });

  it('x-content-type-options: nosniff on relayed answers and on errors', async () => {
    up.reply = () => ({ status: 200, body: GH_TOKEN_RESPONSE });
    const ok = await post(auth, '/oauth/relay/v1/github/token', tokenBody(), member);
    expect(ok.status).toBe(200);
    expect(ok.headers.get('x-content-type-options')).toBe('nosniff');
    up.reply = () => ({ status: 400, body: 'not json', contentType: 'text/html' });
    const relayedErr = await post(auth, '/oauth/relay/v1/github/token', tokenBody(), member);
    expect(relayedErr.status).toBe(400);
    expect(relayedErr.headers.get('x-content-type-options')).toBe('nosniff');
    const own = await post(auth, '/oauth/relay/v1/github/token', tokenBody());
    expect(own.status).toBe(401);
    expect(own.headers.get('x-content-type-options')).toBe('nosniff');
  });
});
