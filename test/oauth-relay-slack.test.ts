/**
 * L6 relay: Slack user OAuth v2 (Core Slack MCP user app).
 *
 * Slack's MCP server uses confidential OAuth against
 * https://slack.com/api/oauth.v2.user.access (docs.slack.dev/ai/mcp-server).
 * Slack answers HTTP 200 with `ok:false` on errors, so the relay inspects the
 * answer: ok:false maps to a clean error, an answer with a scope outside the
 * approved user set or any bot token is revoked (auth.revoke) and refused.
 */
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { CORE_LOOPBACK_CALLBACK } from '../src/oauth-bounce.js';
import {
  HOSTED_BOUNCE_REDIRECT,
  SLACK_APPROVED_USER_SCOPES,
  findRelayProvider,
} from '../src/oauth-relay/providers.js';
import {
  captureLogger,
  mintAccessToken,
  post,
  seamFetch,
  startAuthority,
  startUpstream,
  stop,
  VERIFIER,
  type Authority,
  type Seen,
  type Upstream,
} from './helpers/oauth-relay.js';

const SLACK_ID = '1234567890.0987654321';
const SLACK_SECRET = 'fixture-slack-' + 'k'.repeat(32); // test-only, not a credential
const ENV = { SLACK_CLIENT_ID: SLACK_ID, SLACK_CLIENT_SECRET: SLACK_SECRET };
const CODE = 'slack-code-1a2b3c';

const TOKEN_URL = 'https://slack.com/api/oauth.v2.user.access';
const REVOKE_URL = 'https://slack.com/api/auth.revoke';

/** Rotated user tokens are long; the relay must never trim them. */
const LONG_ACCESS = 'xoxe.xoxp-1-' + 'A9z'.repeat(700); // 2112 chars
const LONG_REFRESH = 'xoxe-1-' + 'r7Q'.repeat(500); // 1507 chars

const okUser = (over: Record<string, unknown> = {}) =>
  JSON.stringify({
    ok: true,
    access_token: LONG_ACCESS,
    token_type: 'user',
    expires_in: 43200,
    refresh_token: LONG_REFRESH,
    authed_user: { id: 'U12345', scope: 'search:read.public,channels:read,channels:history,users:read' },
    team: { id: 'T012345' },
    ...over,
  });

const slackBody = (over: Record<string, unknown> = {}) => ({
  code: CODE,
  code_verifier: VERIFIER,
  redirect_uri: HOSTED_BOUNCE_REDIRECT,
  ...over,
});

let up: Upstream;
let auth: Authority;
let log: ReturnType<typeof captureLogger>;
let member: string;

/** Answer token calls with `tokenAnswer`, revoke calls with ok:true. */
function script(tokenAnswer: string): void {
  up.reply = (s: Seen) =>
    s.requestedUrl === REVOKE_URL
      ? { status: 200, body: '{"ok":true,"revoked":true}' }
      : { status: 200, body: tokenAnswer };
}

const revokedTokens = () =>
  up.seen.filter((s) => s.requestedUrl === REVOKE_URL).map((s) => new URLSearchParams(s.body).get('token'));

beforeAll(async () => {
  up = await startUpstream();
  log = captureLogger();
  auth = await startAuthority({ fetch: seamFetch(up), env: ENV, logger: log.logger });
  member = await mintAccessToken(auth.provider, 'member-slack');
});

afterAll(async () => {
  await stop(auth.server);
  await stop(up.server);
});

afterEach(() => {
  up.seen.length = 0;
  up.reply = () => ({ status: 200, body: '{}' });
  log.lines.length = 0;
});

describe('slack relay row', () => {
  it('approved user scopes are exactly the four read scopes', () => {
    expect([...SLACK_APPROVED_USER_SCOPES].sort()).toEqual(
      ['channels:history', 'channels:read', 'search:read.public', 'users:read'],
    );
    const p = findRelayProvider('slack');
    expect(p?.tokenUrl).toBe(TOKEN_URL);
    expect(p?.refreshUrl).toBe(TOKEN_URL);
    expect(p?.redirectUris).toEqual([HOSTED_BOUNCE_REDIRECT]);
  });

  it('not configured without SLACK_CLIENT_ID and SLACK_CLIENT_SECRET (503, no outbound call)', async () => {
    const a = await startAuthority({ fetch: seamFetch(up), env: { SLACK_CLIENT_ID: SLACK_ID }, logger: log.logger });
    try {
      const t = await mintAccessToken(a.provider, 'member-slack-nc');
      const r = await post(a, '/oauth/relay/v1/slack/token', slackBody(), t);
      expect(r.status).toBe(503);
      expect(await r.json()).toMatchObject({ error: 'not_configured' });
      expect(up.seen).toHaveLength(0);
    } finally {
      await stop(a.server);
    }
  });
});

describe('slack token exchange (oauth.v2.user.access)', () => {
  it('posts the code with the secret as form fields to oauth.v2.user.access only', async () => {
    script(okUser());
    const r = await post(auth, '/oauth/relay/v1/slack/token', slackBody(), member);
    expect(r.status).toBe(200);
    expect(up.seen).toHaveLength(1);
    const s = up.seen[0];
    expect(s.requestedUrl).toBe(TOKEN_URL);
    expect(s.method).toBe('POST');
    expect(s.headers['content-type']).toMatch(/application\/x-www-form-urlencoded/);
    const out = new URLSearchParams(s.body);
    expect(out.get('client_id')).toBe(SLACK_ID);
    expect(out.get('client_secret')).toBe(SLACK_SECRET);
    expect(out.get('grant_type')).toBe('authorization_code');
    expect(out.get('code')).toBe(CODE);
    expect(out.get('code_verifier')).toBe(VERIFIER);
    expect(out.get('redirect_uri')).toBe(HOSTED_BOUNCE_REDIRECT);
    expect(s.headers.authorization).toBeUndefined();
  });

  it('long rotated tokens pass through untruncated, byte for byte', async () => {
    const answer = okUser();
    script(answer);
    const r = await post(auth, '/oauth/relay/v1/slack/token', slackBody(), member);
    expect(r.status).toBe(200);
    const text = await r.text();
    expect(text).toBe(answer);
    const j = JSON.parse(text) as { access_token: string; refresh_token: string };
    expect(j.access_token).toBe(LONG_ACCESS);
    expect(j.access_token.length).toBeGreaterThan(2000);
    expect(j.refresh_token).toBe(LONG_REFRESH);
    expect(text).not.toContain(SLACK_SECRET);
    expect(r.headers.get('cache-control')).toBe('no-store');
    expect(revokedTokens()).toHaveLength(0);
  });

  it('ok:false at HTTP 200 maps to a clean 400 provider_rejected with the Slack error code only', async () => {
    // Extra fields (here an echo of the code) are dropped. An answer carrying
    // the client secret is withheld earlier as 502 (see the next test).
    script(JSON.stringify({ ok: false, error: 'invalid_code', warning: `echo ${CODE}`, response_metadata: { messages: [CODE] } }));
    const r = await post(auth, '/oauth/relay/v1/slack/token', slackBody(), member);
    expect(r.status).toBe(400);
    const text = await r.text();
    expect(JSON.parse(text)).toEqual({ error: 'provider_rejected', provider_error: 'invalid_code' });
    expect(text).not.toContain(SLACK_SECRET);
    expect(text).not.toContain(CODE);
    expect(log.lines.join('\n')).not.toContain(CODE);
  });

  it('ok:false with a non-code error value is reported without echoing it', async () => {
    script(JSON.stringify({ ok: false, error: `bad ${SLACK_SECRET}` }));
    // (the secret echo is caught first; a non-code error without it is also 502:)
    const r0 = await post(auth, '/oauth/relay/v1/slack/token', slackBody(), member);
    expect(r0.status).toBe(502);
    script(JSON.stringify({ ok: false, error: 'Bad <thing> happened' }));
    const r = await post(auth, '/oauth/relay/v1/slack/token', slackBody(), member);
    expect(r.status).toBe(502);
    const text = await r.text();
    expect(text).not.toContain(SLACK_SECRET);
    expect(JSON.parse(text)).toMatchObject({ error: 'provider_rejected' });
  });

  it('non-JSON answer is refused (502 provider_rejected)', async () => {
    up.reply = () => ({ status: 200, body: '<html>oops</html>', contentType: 'text/html' });
    const r = await post(auth, '/oauth/relay/v1/slack/token', slackBody(), member);
    expect(r.status).toBe(502);
    expect(await r.json()).toMatchObject({ error: 'provider_rejected' });
  });

  it('a granted scope outside the approved set is revoked and refused', async () => {
    script(okUser({ authed_user: { id: 'U1', scope: 'search:read.public,chat:write' } }));
    const r = await post(auth, '/oauth/relay/v1/slack/token', slackBody(), member);
    expect(r.status).toBe(502);
    const text = await r.text();
    expect(JSON.parse(text)).toMatchObject({ error: 'provider_rejected', provider_error: 'scope_not_approved', revoked: true });
    expect(text).not.toContain(LONG_ACCESS);
    expect(text).not.toContain(LONG_REFRESH);
    expect(revokedTokens()).toEqual([LONG_ACCESS, LONG_REFRESH]);
    const rv = up.seen.find((s) => s.requestedUrl === REVOKE_URL)!;
    expect(rv.method).toBe('POST');
    expect(rv.body).not.toContain(SLACK_SECRET);
  });

  it('a wider top-level scope is refused too', async () => {
    script(okUser({ scope: 'users:read,admin' }));
    const r = await post(auth, '/oauth/relay/v1/slack/token', slackBody(), member);
    expect(r.status).toBe(502);
    expect(await r.json()).toMatchObject({ provider_error: 'scope_not_approved' });
    expect(revokedTokens()).toEqual([LONG_ACCESS, LONG_REFRESH]);
  });

  it('a strict subset of the approved scopes is accepted', async () => {
    script(okUser({ authed_user: { id: 'U1', scope: 'users:read' } }));
    const r = await post(auth, '/oauth/relay/v1/slack/token', slackBody(), member);
    expect(r.status).toBe(200);
    expect(revokedTokens()).toHaveLength(0);
  });

  it('an answer with no granted scope is refused fail-closed and revoked', async () => {
    script(okUser({ authed_user: { id: 'U1' } }));
    const r = await post(auth, '/oauth/relay/v1/slack/token', slackBody(), member);
    expect(r.status).toBe(502);
    expect(await r.json()).toMatchObject({ provider_error: 'scope_missing' });
    expect(revokedTokens()).toEqual([LONG_ACCESS, LONG_REFRESH]);
  });

  it('an answer that includes a bot token is revoked (every token) and refused', async () => {
    // Assembled at runtime so secret scanners do not read a fixture as a token.
    const bot = ['xoxb', 'fixture', 'not', 'a', 'token'].join('-');
    const userTok = ['xoxp', 'fixture', 'user'].join('-');
    script(
      JSON.stringify({
        ok: true,
        access_token: bot,
        token_type: 'bot',
        scope: 'commands',
        bot_user_id: 'U0KRQLJ9H',
        authed_user: { id: 'U1', scope: 'users:read', access_token: userTok, token_type: 'user' },
      }),
    );
    const r = await post(auth, '/oauth/relay/v1/slack/token', slackBody(), member);
    expect(r.status).toBe(502);
    const text = await r.text();
    expect(JSON.parse(text)).toMatchObject({ provider_error: 'bot_token_refused', revoked: true });
    expect(text).not.toContain(bot);
    expect(text).not.toContain(userTok);
    expect(revokedTokens().sort()).toEqual([bot, userTok].sort());
  });

  it('a rotating bot token by prefix alone is refused', async () => {
    const rotBot = 'xoxe.xoxb-1-' + 'b'.repeat(80);
    script(okUser({ access_token: rotBot, token_type: 'user' }));
    const r = await post(auth, '/oauth/relay/v1/slack/token', slackBody(), member);
    expect(r.status).toBe(502);
    expect(await r.json()).toMatchObject({ provider_error: 'bot_token_refused' });
    expect(revokedTokens()).toEqual([rotBot, LONG_REFRESH]);
  });

  it('a refusal whose revoke fails says revoked:false', async () => {
    up.reply = (s) =>
      s.requestedUrl === REVOKE_URL
        ? { status: 200, body: '{"ok":false,"error":"invalid_auth"}' }
        : { status: 200, body: okUser({ authed_user: { id: 'U1', scope: 'chat:write' } }) };
    const r = await post(auth, '/oauth/relay/v1/slack/token', slackBody(), member);
    expect(r.status).toBe(502);
    expect(await r.json()).toMatchObject({ provider_error: 'scope_not_approved', revoked: false });
  });

  it('no token, code or secret in any log line', async () => {
    script(okUser({ authed_user: { id: 'U1', scope: 'chat:write' } }));
    await post(auth, '/oauth/relay/v1/slack/token', slackBody(), member);
    script(okUser());
    await post(auth, '/oauth/relay/v1/slack/token', slackBody(), member);
    const all = log.lines.join('\n');
    expect(all).toContain('provider=slack');
    for (const s of [LONG_ACCESS, LONG_REFRESH, CODE, SLACK_SECRET, VERIFIER]) expect(all).not.toContain(s);
  });
});

describe('slack refresh (token rotation)', () => {
  it('grant_type=refresh_token at oauth.v2.user.access; long tokens untruncated both ways', async () => {
    const answer = JSON.stringify({
      ok: true,
      access_token: LONG_ACCESS,
      token_type: 'user',
      expires_in: 43200,
      refresh_token: LONG_REFRESH,
      scope: 'search:read.public,users:read',
    });
    script(answer);
    const r = await post(auth, '/oauth/relay/v1/slack/refresh', { refresh_token: LONG_REFRESH }, member);
    expect(r.status).toBe(200);
    expect(await r.text()).toBe(answer);
    const s = up.seen[0];
    expect(s.requestedUrl).toBe(TOKEN_URL);
    const out = new URLSearchParams(s.body);
    expect(out.get('grant_type')).toBe('refresh_token');
    expect(out.get('refresh_token')).toBe(LONG_REFRESH);
    expect(out.get('client_id')).toBe(SLACK_ID);
    expect(out.get('client_secret')).toBe(SLACK_SECRET);
  });

  it('a refresh answer with a widened scope is revoked and refused', async () => {
    script(JSON.stringify({ ok: true, access_token: LONG_ACCESS, token_type: 'user', scope: 'users:read,files:write' }));
    const r = await post(auth, '/oauth/relay/v1/slack/refresh', { refresh_token: LONG_REFRESH }, member);
    expect(r.status).toBe(502);
    expect(await r.json()).toMatchObject({ provider_error: 'scope_not_approved' });
    expect(revokedTokens()).toEqual([LONG_ACCESS]);
  });

  it('ok:false on refresh maps to 400 provider_rejected', async () => {
    script(JSON.stringify({ ok: false, error: 'invalid_refresh_token' }));
    const r = await post(auth, '/oauth/relay/v1/slack/refresh', { refresh_token: LONG_REFRESH }, member);
    expect(r.status).toBe(400);
    expect(await r.json()).toEqual({ error: 'provider_rejected', provider_error: 'invalid_refresh_token' });
  });
});

describe('slack revoke (auth.revoke)', () => {
  it('posts the token to auth.revoke without client credentials', async () => {
    script('{}');
    const r = await post(auth, '/oauth/relay/v1/slack/revoke', { token: LONG_ACCESS }, member);
    expect(r.status).toBe(200);
    expect(await r.json()).toMatchObject({ revoked: true });
    const s = up.seen[0];
    expect(s.requestedUrl).toBe(REVOKE_URL);
    expect(s.method).toBe('POST');
    expect(new URLSearchParams(s.body).get('token')).toBe(LONG_ACCESS);
    expect(s.body).not.toContain(SLACK_SECRET);
    expect(s.headers.authorization).toBeUndefined();
  });

  it('ok:false at HTTP 200 is revoked:false, not success', async () => {
    up.reply = () => ({ status: 200, body: '{"ok":false,"error":"invalid_auth"}' });
    const r = await post(auth, '/oauth/relay/v1/slack/revoke', { token: 'xoxp-1-dead' }, member);
    expect(r.status).toBe(502);
    expect(await r.json()).toMatchObject({ error: 'provider_rejected', revoked: false, provider_error: 'invalid_auth' });
  });
});

describe('slack redirect is the hosted bounce only', () => {
  it('rejects the loopback and every near miss (400, no outbound call)', async () => {
    for (const redirect_uri of [
      CORE_LOOPBACK_CALLBACK,
      'https://auth.citrate.ai/oauth/linkedin/callback',
      HOSTED_BOUNCE_REDIRECT + '/',
      HOSTED_BOUNCE_REDIRECT + '?x=1',
      'https://AUTH.citrate.ai/oauth/callback',
    ]) {
      const r = await post(auth, '/oauth/relay/v1/slack/token', slackBody({ redirect_uri }), member);
      expect(r.status, redirect_uri).toBe(400);
    }
    expect(up.seen).toHaveLength(0);
  });
});

describe('review fixes (#55): fail-closed edges', () => {
  it('an empty or whitespace scope is scope_missing, and the tokens are revoked', async () => {
    for (const scope of ['', ' , ', ',', '   ']) {
      up.seen.length = 0;
      script(okUser({ scope, authed_user: { id: 'U1', scope } }));
      const r = await post(auth, '/oauth/relay/v1/slack/token', slackBody(), member);
      expect(r.status, JSON.stringify(scope)).toBe(502);
      expect(await r.json()).toMatchObject({ provider_error: 'scope_missing', revoked: true });
      expect(revokedTokens()).toEqual([LONG_ACCESS, LONG_REFRESH]);
    }
  });

  it('refresh tokens are revoked too: an answer with only a refresh token and a bad scope revokes it', async () => {
    const userRefresh = 'xoxe-1-' + 'u'.repeat(40);
    script(
      JSON.stringify({
        ok: true,
        authed_user: { id: 'U1', scope: 'chat:write', refresh_token: userRefresh, token_type: 'user' },
        refresh_token: LONG_REFRESH,
      }),
    );
    const r = await post(auth, '/oauth/relay/v1/slack/token', slackBody(), member);
    expect(r.status).toBe(502);
    const text = await r.text();
    expect(JSON.parse(text)).toMatchObject({ provider_error: 'scope_not_approved', revoked: true });
    expect(text).not.toContain(LONG_REFRESH);
    expect(revokedTokens().sort()).toEqual([LONG_REFRESH, userRefresh].sort());
  });

  it('a token in an unknown field (enterprise.access_token) is refused and revoked', async () => {
    const hidden = ['xoxp', 'fixture', 'enterprise'].join('-');
    script(okUser({ enterprise: { id: 'E1', access_token: hidden } }));
    const r = await post(auth, '/oauth/relay/v1/slack/token', slackBody(), member);
    expect(r.status).toBe(502);
    const text = await r.text();
    expect(JSON.parse(text)).toMatchObject({ provider_error: 'unexpected_token_field', revoked: true });
    expect(text).not.toContain(hidden);
    expect(revokedTokens().sort()).toEqual([LONG_ACCESS, LONG_REFRESH, hidden].sort());
  });

  it('a Slack-looking token value under any other key is refused too', async () => {
    const stray = ['xoxa', 'fixture', 'stray'].join('-');
    script(okUser({ extra: [{ note: stray }] }));
    const r = await post(auth, '/oauth/relay/v1/slack/token', slackBody(), member);
    expect(r.status).toBe(502);
    expect(await r.json()).toMatchObject({ provider_error: 'unexpected_token_field' });
    expect(revokedTokens()).toContain(stray);
  });

  it('a token answer withheld for echoing the secret still has its tokens revoked', async () => {
    script(okUser({ debug: SLACK_SECRET }));
    const r = await post(auth, '/oauth/relay/v1/slack/token', slackBody(), member);
    expect(r.status).toBe(502);
    const text = await r.text();
    expect(text).not.toContain(SLACK_SECRET);
    expect(text).not.toContain(LONG_ACCESS);
    expect(JSON.parse(text)).toMatchObject({ error: 'provider_rejected', revoked: true });
    expect(revokedTokens()).toEqual([LONG_ACCESS, LONG_REFRESH]);
    for (const s of up.seen.filter((x) => x.requestedUrl === REVOKE_URL)) expect(s.body).not.toContain(SLACK_SECRET);
  });

  it('a token answer withheld for a 3xx still has its tokens revoked', async () => {
    up.reply = (s) =>
      s.requestedUrl === REVOKE_URL ? { status: 200, body: '{"ok":true,"revoked":true}' } : { status: 302, body: okUser() };
    const r = await post(auth, '/oauth/relay/v1/slack/token', slackBody(), member);
    expect(r.status).toBe(502);
    expect(await r.json()).toMatchObject({ error: 'provider_rejected', revoked: true });
    expect(revokedTokens()).toEqual([LONG_ACCESS, LONG_REFRESH]);
  });

  it('ratelimited maps to 429; internal_error and fatal_error map to 502', async () => {
    const cases: Array<[string, number, string]> = [
      ['ratelimited', 429, 'rate_limited'],
      ['internal_error', 502, 'provider_rejected'],
      ['fatal_error', 502, 'provider_rejected'],
      ['invalid_code', 400, 'provider_rejected'],
    ];
    for (const [code, status, error] of cases) {
      script(JSON.stringify({ ok: false, error: code }));
      const r = await post(auth, '/oauth/relay/v1/slack/token', slackBody(), member);
      expect(r.status, code).toBe(status);
      expect(await r.json(), code).toEqual({ error, provider_error: code });
    }
  });

  it('PKCE is required for Slack: an exchange without code_verifier is refused before any outbound call', async () => {
    const { code_verifier: _omit, ...noVerifier } = slackBody();
    for (const body of [noVerifier, slackBody({ code_verifier: '' }), slackBody({ code_verifier: 'short' })]) {
      const r = await post(auth, '/oauth/relay/v1/slack/token', body, member);
      expect(r.status).toBe(400);
      expect(await r.json()).toMatchObject({ error: 'bad_request' });
    }
    expect(up.seen).toHaveLength(0);
  });
});
