/**
 * L6 relay: LinkedIn social-identity relay, per citrate-core
 * docs/LINKEDIN_RELAY_SPEC.md section 2.
 *
 *   GET /oauth/linkedin/start?state&challenge&rd   -> 302 LinkedIn authorize
 *   GET /oauth/linkedin/callback?code&state        -> server-side exchange,
 *        userinfo read, 302 to the fixed loopback with state, handle, sub only.
 *
 * The LinkedIn token never leaves the relay and is never logged.
 */
import RedisMock from 'ioredis-mock';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { CORE_LOOPBACK_CALLBACK } from '../src/oauth-bounce.js';
import {
  InMemoryLinkedInStateStore,
  LINKEDIN_CALLBACK,
  LINKEDIN_STATE_TTL_MS,
  RedisLinkedInStateStore,
} from '../src/oauth-relay/linkedin.js';
import type { RedisLike } from '../src/redis.js';
import {
  captureLogger,
  getManual,
  post,
  mintAccessToken,
  seamFetch,
  startAuthority,
  startUpstream,
  stop,
  type Authority,
  type Seen,
  type Upstream,
} from './helpers/oauth-relay.js';

const LI_ID = '86abcdefghijkl';
const LI_SECRET = 'fixture-li-' + 'L'.repeat(24); // test-only, not a credential
const ENV = { LINKEDIN_CLIENT_ID: LI_ID, LINKEDIN_CLIENT_SECRET: LI_SECRET };

const AUTHORIZE = 'https://www.linkedin.com/oauth/v2/authorization';
const TOKEN_URL = 'https://www.linkedin.com/oauth/v2/accessToken';
const USERINFO_URL = 'https://api.linkedin.com/v2/userinfo';
const LI_TOKEN = 'AQV' + 'x'.repeat(600);
const LI_CODE = 'AQTli-code-' + 'c'.repeat(40);

let up: Upstream;
let auth: Authority;
let log: ReturnType<typeof captureLogger>;
let store: InMemoryLinkedInStateStore;
let clock = 1_800_000_000_000;
let n = 0;

const freshState = () => `st-${++n}-` + 'q'.repeat(30);

function happyUpstream(user: Record<string, unknown> = { sub: 'li-sub-123', name: 'Ada Lovelace' }): void {
  up.reply = (s: Seen) =>
    s.requestedUrl === TOKEN_URL
      ? { status: 200, body: JSON.stringify({ access_token: LI_TOKEN, expires_in: 5184000, scope: 'openid,profile' }) }
      : s.requestedUrl === USERINFO_URL
        ? { status: 200, body: JSON.stringify(user) }
        : { status: 404, body: '{}' };
}

async function start(state: string, extra = ''): Promise<Response> {
  return getManual(
    auth,
    `/oauth/linkedin/start?state=${encodeURIComponent(state)}&rd=${encodeURIComponent(CORE_LOOPBACK_CALLBACK)}${extra}`,
  );
}

beforeAll(async () => {
  up = await startUpstream();
  log = captureLogger();
  store = new InMemoryLinkedInStateStore(() => clock);
  auth = await startAuthority({ fetch: seamFetch(up), env: ENV, logger: log.logger, linkedinStates: store });
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

describe('GET /oauth/linkedin/start', () => {
  it('start_stores_state_with_ttl and 302s to LinkedIn authorize with the relay callback', async () => {
    const state = freshState();
    const r = await start(state, '&challenge=' + 'C'.repeat(43));
    expect(r.status).toBe(302);
    expect(r.headers.get('cache-control')).toBe('no-store');
    const loc = new URL(r.headers.get('location')!);
    expect(`${loc.origin}${loc.pathname}`).toBe(AUTHORIZE);
    expect(loc.searchParams.get('response_type')).toBe('code');
    expect(loc.searchParams.get('client_id')).toBe(LI_ID);
    expect(loc.searchParams.get('redirect_uri')).toBe(LINKEDIN_CALLBACK);
    expect(loc.searchParams.get('scope')).toBe('openid profile');
    expect(loc.searchParams.get('state')).toBe(state);
    expect(loc.toString()).not.toContain(LI_SECRET);
    expect(LINKEDIN_STATE_TTL_MS).toBe(5 * 60 * 1000);
    expect(store.peekExpiry(state)).toBe(clock + LINKEDIN_STATE_TTL_MS);
    expect(up.seen).toHaveLength(0);
  });

  it('start_allows_only_fixed_loopback_rd', async () => {
    for (const rd of [
      'http://127.0.0.1:8976/oauth/callback',
      'http://localhost:8975/oauth/callback',
      'https://attacker.example/cb',
      CORE_LOOPBACK_CALLBACK + '/',
      CORE_LOOPBACK_CALLBACK + '?x=1',
      '',
    ]) {
      const state = freshState();
      const r = await getManual(auth, `/oauth/linkedin/start?state=${state}&rd=${encodeURIComponent(rd)}`);
      expect(r.status, rd).toBe(400);
      expect(r.headers.get('location')).toBeNull();
      expect(store.peekExpiry(state)).toBeUndefined();
    }
  });

  it('refuses a missing or malformed state, and a reused state', async () => {
    for (const q of ['', 'state=short', `state=${'a b'.repeat(10)}`, `state=${'z'.repeat(300)}`]) {
      const r = await getManual(auth, `/oauth/linkedin/start?${q}&rd=${encodeURIComponent(CORE_LOOPBACK_CALLBACK)}`);
      expect(r.status, q).toBe(400);
    }
    const state = freshState();
    expect((await start(state)).status).toBe(302);
    expect((await start(state)).status).toBe(400);
  });

  it('503 when LINKEDIN_CLIENT_ID / LINKEDIN_CLIENT_SECRET are unset', async () => {
    const a = await startAuthority({ fetch: seamFetch(up), env: { LINKEDIN_CLIENT_ID: LI_ID }, logger: log.logger });
    try {
      const r = await getManual(a, `/oauth/linkedin/start?state=${freshState()}&rd=${encodeURIComponent(CORE_LOOPBACK_CALLBACK)}`);
      expect(r.status).toBe(503);
    } finally {
      await stop(a.server);
    }
  });

  it('rate-limits /start per IP (429)', async () => {
    const a = await startAuthority({ fetch: seamFetch(up), env: ENV, logger: log.logger, limits: { perIp: 2 } });
    try {
      const go = () => getManual(a, `/oauth/linkedin/start?state=${freshState()}&rd=${encodeURIComponent(CORE_LOOPBACK_CALLBACK)}`);
      expect((await go()).status).toBe(302);
      expect((await go()).status).toBe(302);
      expect((await go()).status).toBe(429);
    } finally {
      await stop(a.server);
    }
  });

  it('OAUTH_RELAY=0 turns the LinkedIn routes off', async () => {
    const a = await startAuthority({ fetch: seamFetch(up), env: { ...ENV, OAUTH_RELAY: '0' }, logger: log.logger });
    try {
      const r = await getManual(a, `/oauth/linkedin/start?state=${freshState()}&rd=${encodeURIComponent(CORE_LOOPBACK_CALLBACK)}`);
      expect(r.status).toBe(503);
    } finally {
      await stop(a.server);
    }
  });
});

describe('GET /oauth/linkedin/callback', () => {
  it('callback_exchanges_server_side_and_discards_token; no_token_in_redirect', async () => {
    happyUpstream();
    const state = freshState();
    await start(state);
    const r = await getManual(auth, `/oauth/linkedin/callback?code=${LI_CODE}&state=${state}`);
    expect(r.status).toBe(302);
    expect(r.headers.get('cache-control')).toBe('no-store');
    const loc = r.headers.get('location')!;
    const u = new URL(loc);
    expect(`${u.origin}${u.pathname}`).toBe(CORE_LOOPBACK_CALLBACK);
    expect([...u.searchParams.keys()].sort()).toEqual(['handle', 'state', 'sub']);
    expect(u.searchParams.get('state')).toBe(state);
    expect(u.searchParams.get('handle')).toBe('Ada Lovelace');
    expect(u.searchParams.get('sub')).toBe('li-sub-123');
    expect(loc).not.toContain(LI_TOKEN);
    expect(await r.text()).not.toContain(LI_TOKEN);

    expect(up.seen.map((s) => s.requestedUrl)).toEqual([TOKEN_URL, USERINFO_URL]);
    const tok = up.seen[0];
    expect(tok.method).toBe('POST');
    const form = new URLSearchParams(tok.body);
    expect(form.get('grant_type')).toBe('authorization_code');
    expect(form.get('code')).toBe(LI_CODE);
    expect(form.get('redirect_uri')).toBe(LINKEDIN_CALLBACK);
    expect(form.get('client_id')).toBe(LI_ID);
    expect(form.get('client_secret')).toBe(LI_SECRET);
    const ui = up.seen[1];
    expect(ui.method).toBe('GET');
    expect(ui.headers.authorization).toBe(`Bearer ${LI_TOKEN}`);

    const all = log.lines.join('\n');
    for (const s of [LI_TOKEN, LI_CODE, LI_SECRET, state]) expect(all).not.toContain(s);
  });

  it('prefers preferred_username over name for the handle', async () => {
    happyUpstream({ sub: 's2', name: 'Grace Hopper', preferred_username: 'ghopper' });
    const state = freshState();
    await start(state);
    const r = await getManual(auth, `/oauth/linkedin/callback?code=${LI_CODE}&state=${state}`);
    expect(new URL(r.headers.get('location')!).searchParams.get('handle')).toBe('ghopper');
  });

  it('state is single use: a replayed callback makes no outbound call', async () => {
    happyUpstream();
    const state = freshState();
    await start(state);
    expect((await getManual(auth, `/oauth/linkedin/callback?code=${LI_CODE}&state=${state}`)).status).toBe(302);
    up.seen.length = 0;
    const r = await getManual(auth, `/oauth/linkedin/callback?code=${LI_CODE}&state=${state}`);
    expect(r.status).toBe(400);
    expect(r.headers.get('location')).toBeNull();
    expect(up.seen).toHaveLength(0);
  });

  it('an unknown state is refused with no redirect and no outbound call', async () => {
    const r = await getManual(auth, `/oauth/linkedin/callback?code=${LI_CODE}&state=${freshState()}`);
    expect(r.status).toBe(400);
    expect(r.headers.get('location')).toBeNull();
    expect(up.seen).toHaveLength(0);
  });

  it('an expired state (past the 5 minute TTL) is refused', async () => {
    happyUpstream();
    const state = freshState();
    await start(state);
    clock += LINKEDIN_STATE_TTL_MS + 1;
    const r = await getManual(auth, `/oauth/linkedin/callback?code=${LI_CODE}&state=${state}`);
    expect(r.status).toBe(400);
    expect(up.seen).toHaveLength(0);
  });

  it('a LinkedIn error is returned to the loopback as a fixed error code, never echoed', async () => {
    const state = freshState();
    await start(state);
    const r = await getManual(
      auth,
      `/oauth/linkedin/callback?error=user_cancelled_login&error_description=${encodeURIComponent('<script>x</script>')}&state=${state}`,
    );
    expect(r.status).toBe(302);
    const u = new URL(r.headers.get('location')!);
    expect(`${u.origin}${u.pathname}`).toBe(CORE_LOOPBACK_CALLBACK);
    expect(Object.fromEntries(u.searchParams)).toEqual({ state, error: 'access_denied' });
    expect(up.seen).toHaveLength(0);
  });

  it('a failed exchange or userinfo returns error=server_error to the loopback, no token', async () => {
    for (const fail of ['token', 'userinfo', 'nosub'] as const) {
      up.reply = (s: Seen) => {
        if (s.requestedUrl === TOKEN_URL) {
          return fail === 'token'
            ? { status: 400, body: '{"error":"invalid_request"}' }
            : { status: 200, body: JSON.stringify({ access_token: LI_TOKEN }) };
        }
        return fail === 'userinfo' ? { status: 401, body: '{}' } : { status: 200, body: '{"name":"No Sub"}' };
      };
      const state = freshState();
      await start(state);
      const r = await getManual(auth, `/oauth/linkedin/callback?code=${LI_CODE}&state=${state}`);
      expect(r.status, fail).toBe(302);
      const loc = r.headers.get('location')!;
      expect(Object.fromEntries(new URL(loc).searchParams), fail).toEqual({ state, error: 'server_error' });
      expect(loc).not.toContain(LI_TOKEN);
    }
  });

  it('only the exact callback path is the LinkedIn callback', async () => {
    happyUpstream();
    const state = freshState();
    await start(state);
    for (const p of ['/oauth/linkedin/callback/', '/oauth/linkedin/Callback', '/oauth/linkedin/callback/x']) {
      const r = await getManual(auth, `${p}?code=${LI_CODE}&state=${state}`);
      expect(r.headers.get('location') ?? '', p).not.toContain('handle=');
    }
    expect(up.seen).toHaveLength(0);
    // The state is still live: the exact path completes the flow.
    const ok = await getManual(auth, `/oauth/linkedin/callback?code=${LI_CODE}&state=${state}`);
    expect(new URL(ok.headers.get('location')!).searchParams.get('handle')).toBe('Ada Lovelace');
  });

  it('LinkedIn is not a token relay provider: the token never reaches the desktop', async () => {
    const t = await mintAccessToken(auth.provider, 'member-li');
    const r = await post(auth, '/oauth/relay/v1/linkedin/token', { code: LI_CODE, code_verifier: 'v'.repeat(43), redirect_uri: LINKEDIN_CALLBACK }, t);
    expect(r.status).toBe(404);
    expect(await r.json()).toMatchObject({ error: 'unknown_provider' });
    expect(up.seen).toHaveLength(0);
  });
});

describe('RedisLinkedInStateStore', () => {
  it('stores with a PX TTL, refuses overwrite, and takes once', async () => {
    const redis = new RedisMock() as unknown as RedisLike & { pttl(k: string): Promise<number> };
    const s = new RedisLinkedInStateStore(redis);
    expect(await s.put('state-aaaaaaaaaaaaaaaa', { rd: CORE_LOOPBACK_CALLBACK })).toBe(true);
    expect(await s.put('state-aaaaaaaaaaaaaaaa', { rd: CORE_LOOPBACK_CALLBACK })).toBe(false);
    const ttl = await redis.pttl('oauth-linkedin:state:state-aaaaaaaaaaaaaaaa');
    expect(ttl).toBeGreaterThan(0);
    expect(ttl).toBeLessThanOrEqual(LINKEDIN_STATE_TTL_MS);
    expect(await s.take('state-aaaaaaaaaaaaaaaa')).toEqual({ rd: CORE_LOOPBACK_CALLBACK });
    expect(await s.take('state-aaaaaaaaaaaaaaaa')).toBeNull();
  });
});
