/**
 * LinkedIn social-identity relay (citrate-core docs/LINKEDIN_RELAY_SPEC.md §2).
 *
 *   GET /oauth/linkedin/start?state=<opaque>&rd=<loopback>[&challenge=<S256>]
 *     stores {state -> rd} for 5 minutes, 302s to LinkedIn's authorize.
 *   GET /oauth/linkedin/callback?code&state
 *     exchanges the code server side (with the secret), reads `sub` and a
 *     handle from userinfo, discards the LinkedIn token, and 302s to
 *     http://127.0.0.1:8975/oauth/callback?state&handle&sub.
 *
 * LinkedIn is a confidential client without public-client PKCE, and identity
 * needs only the handle plus proof of ownership, so the LinkedIn token never
 * reaches the desktop and is not a `/oauth/relay/v1` provider.
 *
 * Data source: LinkedIn OIDC endpoints below (fixed); `LINKEDIN_CLIENT_ID` /
 * `LINKEDIN_CLIENT_SECRET` from the deployment env; `state` in Redis (5 min TTL,
 * single use) when wired, else in process memory.
 *
 * SECURITY
 * - `rd` must equal the fixed loopback exactly; the browser can only ever be
 *   sent to LinkedIn's authorize or to that loopback.
 * - `state` is validated, single use and expires after 5 minutes. An unknown
 *   state gets a 400 page, not a redirect, and no outbound call.
 * - Exact paths: `/oauth/linkedin/callback` only; the `redirect_uri` sent to
 *   LinkedIn is the constant {@link LINKEDIN_CALLBACK}.
 * - LinkedIn errors reach the loopback as a fixed code, never echoed.
 * - Never logs a code, state, token, handle or secret. `Cache-Control: no-store`.
 * - Per-IP rate limit on both routes. `OAUTH_RELAY=0` turns them off.
 */
import type { ServerResponse } from 'node:http';
import type Provider from 'oidc-provider';
import { clientIp, type RateLimiter } from '../auth/rate-limit.js';
import { CORE_LOOPBACK_CALLBACK } from '../oauth-bounce.js';
import type { RedisLike } from '../redis.js';
import {
  callUpstream,
  noStoreHeaders,
  RELAY_LIMITS,
  sendJson,
  type OAuthRelayOptions,
  type RelayLimits,
  type RelayLogger,
  type UpstreamAnswer,
} from './routes.js';

export const LINKEDIN_START_PATH = '/oauth/linkedin/start';
export const LINKEDIN_CALLBACK_PATH = '/oauth/linkedin/callback';
/** Registered in the LinkedIn app as its only Authorized redirect URL. */
export const LINKEDIN_CALLBACK = 'https://auth.citrate.ai/oauth/linkedin/callback';
export const LINKEDIN_AUTHORIZE_URL = 'https://www.linkedin.com/oauth/v2/authorization';
export const LINKEDIN_TOKEN_URL = 'https://www.linkedin.com/oauth/v2/accessToken';
export const LINKEDIN_USERINFO_URL = 'https://api.linkedin.com/v2/userinfo';
export const LINKEDIN_SCOPE = 'openid profile';
export const LINKEDIN_STATE_TTL_MS = 5 * 60 * 1000;

/** Opaque desktop state: 16 to 128 unreserved characters. */
const STATE_RE = /^[A-Za-z0-9\-._~]{16,128}$/;
/** RFC 7636 S256 challenge: 43 base64url characters. */
const CHALLENGE_RE = /^[A-Za-z0-9\-_]{43}$/;
const MAX_HANDLE = 256;

export interface LinkedInStateRecord {
  rd: string;
  challenge?: string;
}

export interface LinkedInStateStore {
  /** Store once with the 5 minute TTL; false when the state already exists. */
  put(state: string, rec: LinkedInStateRecord): Promise<boolean>;
  /** Remove and return a live record; null when unknown or expired. */
  take(state: string): Promise<LinkedInStateRecord | null>;
}

export class InMemoryLinkedInStateStore implements LinkedInStateStore {
  private readonly m = new Map<string, { rec: LinkedInStateRecord; exp: number }>();
  constructor(
    private readonly now: () => number = Date.now,
    private readonly ttlMs: number = LINKEDIN_STATE_TTL_MS,
  ) {}

  async put(state: string, rec: LinkedInStateRecord): Promise<boolean> {
    const t = this.now();
    for (const [k, v] of this.m) if (v.exp <= t) this.m.delete(k);
    if (this.m.has(state)) return false;
    this.m.set(state, { rec, exp: t + this.ttlMs });
    return true;
  }

  async take(state: string): Promise<LinkedInStateRecord | null> {
    const v = this.m.get(state);
    this.m.delete(state);
    return v && v.exp > this.now() ? v.rec : null;
  }

  /** Expiry of a stored state (tests, observability). */
  peekExpiry(state: string): number | undefined {
    return this.m.get(state)?.exp;
  }
}

export class RedisLinkedInStateStore implements LinkedInStateStore {
  constructor(
    private readonly redis: RedisLike,
    private readonly ttlMs: number = LINKEDIN_STATE_TTL_MS,
  ) {}

  private key(state: string): string {
    return `oauth-linkedin:state:${state}`;
  }

  async put(state: string, rec: LinkedInStateRecord): Promise<boolean> {
    const r = await this.redis.set(this.key(state), JSON.stringify(rec), 'PX', this.ttlMs, 'NX');
    return r === 'OK';
  }

  async take(state: string): Promise<LinkedInStateRecord | null> {
    const raw = await this.redis.getdel(this.key(state));
    if (!raw) return null;
    try {
      const v = JSON.parse(raw) as LinkedInStateRecord;
      return typeof v?.rd === 'string' ? v : null;
    } catch {
      return null;
    }
  }
}

/** One value per name; a repeated or absent name counts as absent. */
function single(q: URLSearchParams, name: string): string | null {
  const all = q.getAll(name);
  return all.length === 1 && all[0] ? all[0] : null;
}

function asObject(body: Buffer): Record<string, unknown> | null {
  try {
    const v: unknown = JSON.parse(body.toString('utf8'));
    return v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

function redirect(res: ServerResponse, location: string): void {
  res.writeHead(302, { ...noStoreHeaders('text/plain; charset=utf-8'), location });
  res.end();
}

function page(res: ServerResponse, status: number, text: string): void {
  res.writeHead(status, noStoreHeaders('text/plain; charset=utf-8'));
  res.end(text);
}

/** The fixed loopback with only the given params. */
function loopback(params: Record<string, string>): string {
  const u = new URL(CORE_LOOPBACK_CALLBACK);
  for (const [k, v] of Object.entries(params)) u.searchParams.set(k, v);
  return u.toString();
}

export function mountLinkedInRelay(
  provider: Provider,
  opts: OAuthRelayOptions & { rateLimiter: RateLimiter; redis?: RedisLike },
): void {
  const env = opts.env ?? process.env;
  const enabled = env['OAUTH_RELAY'] !== '0';
  const doFetch = opts.fetch ?? fetch;
  const logger: RelayLogger = opts.logger ?? console;
  const limits: RelayLimits = { ...RELAY_LIMITS, ...(opts.limits ?? {}) };
  const store: LinkedInStateStore =
    opts.linkedinStates ?? (opts.redis ? new RedisLinkedInStateStore(opts.redis) : new InMemoryLinkedInStateStore());
  const note = (op: string, outcome: string, status: number, upstream?: number) =>
    logger[status < 400 ? 'info' : 'warn'](
      `[oauth-relay] provider=linkedin op=${op} outcome=${outcome} status=${status}` +
        (upstream !== undefined ? ` upstream_status=${upstream}` : ''),
    );
  const creds = () => {
    const clientId = env['LINKEDIN_CLIENT_ID']?.trim();
    const clientSecret = env['LINKEDIN_CLIENT_SECRET']?.trim();
    return clientId && clientSecret ? { clientId, clientSecret } : null;
  };

  provider.use(async (ctx, next) => {
    const isStart = ctx.path === LINKEDIN_START_PATH;
    const isCallback = ctx.path === LINKEDIN_CALLBACK_PATH;
    if (ctx.method !== 'GET' || (!isStart && !isCallback)) {
      await next();
      return;
    }
    const res = ctx.res;
    ctx.respond = false;
    const op = isStart ? 'start' : 'callback';

    if (!enabled) {
      sendJson(res, 503, { error: 'relay_disabled', reason: 'the OAuth relay is turned off on this authority' });
      return;
    }
    try {
      const ip = clientIp(ctx.req, provider.proxy === true);
      if (!(await opts.rateLimiter.hit(`oauth-linkedin:${op}:ip:${ip}`, limits.perIp, limits.windowMs))) {
        note(op, 'rate_limited_ip', 429);
        sendJson(res, 429, { error: 'rate_limited' }, { 'retry-after': String(Math.ceil(limits.windowMs / 1000)) });
        return;
      }
      const q = new URLSearchParams(ctx.querystring);
      const state = single(q, 'state');
      if (!state || !STATE_RE.test(state)) {
        note(op, 'bad_state', 400);
        page(res, 400, 'Missing or malformed state. Start the LinkedIn link again from Citrate Core.');
        return;
      }

      if (isStart) {
        const c = creds();
        if (!c) {
          note(op, 'not_configured', 503);
          sendJson(res, 503, {
            error: 'not_configured',
            reason: 'linkedin is not configured (LINKEDIN_CLIENT_ID and LINKEDIN_CLIENT_SECRET must both be set)',
          });
          return;
        }
        if (single(q, 'rd') !== CORE_LOOPBACK_CALLBACK) {
          note(op, 'bad_rd', 400);
          page(res, 400, 'Unsupported return address.');
          return;
        }
        const challenge = q.get('challenge');
        if (challenge !== null && (single(q, 'challenge') === null || !CHALLENGE_RE.test(challenge))) {
          note(op, 'bad_challenge', 400);
          page(res, 400, 'Malformed challenge.');
          return;
        }
        const rec: LinkedInStateRecord = { rd: CORE_LOOPBACK_CALLBACK, ...(challenge ? { challenge } : {}) };
        if (!(await store.put(state, rec))) {
          note(op, 'state_in_use', 400);
          page(res, 400, 'This sign-in was already started. Start the LinkedIn link again from Citrate Core.');
          return;
        }
        const auth = new URL(LINKEDIN_AUTHORIZE_URL);
        auth.searchParams.set('response_type', 'code');
        auth.searchParams.set('client_id', c.clientId);
        auth.searchParams.set('redirect_uri', LINKEDIN_CALLBACK);
        auth.searchParams.set('scope', LINKEDIN_SCOPE);
        auth.searchParams.set('state', state);
        note(op, 'redirected', 302);
        redirect(res, auth.toString().replace(/\+/g, '%20'));
        return;
      }

      // Callback.
      const rec = await store.take(state);
      if (!rec || rec.rd !== CORE_LOOPBACK_CALLBACK) {
        note(op, 'unknown_state', 400);
        page(res, 400, 'This sign-in link has expired or was already used. Start the LinkedIn link again from Citrate Core.');
        return;
      }
      const back = (params: Record<string, string>, outcome: string, upstream?: number) => {
        note(op, outcome, 302, upstream);
        redirect(res, loopback({ state, ...params }));
      };
      const lnError = q.get('error');
      if (lnError !== null) {
        const denied = /^(user_cancelled_login|user_cancelled_authorize|access_denied)$/.test(lnError);
        back({ error: denied ? 'access_denied' : 'server_error' }, 'provider_error');
        return;
      }
      const code = single(q, 'code');
      if (!code) return back({ error: 'invalid_request' }, 'missing_code');
      const c = creds();
      if (!c) return back({ error: 'server_error' }, 'not_configured');

      let tok: UpstreamAnswer;
      try {
        tok = await callUpstream(doFetch, {
          url: LINKEDIN_TOKEN_URL,
          method: 'POST',
          headers: { accept: 'application/json', 'content-type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            grant_type: 'authorization_code',
            code,
            redirect_uri: LINKEDIN_CALLBACK,
            client_id: c.clientId,
            client_secret: c.clientSecret,
          }).toString(),
        });
      } catch {
        return back({ error: 'server_error' }, 'token_unreachable');
      }
      const accessToken = tok.status === 200 ? asObject(tok.body)?.['access_token'] : undefined;
      if (typeof accessToken !== 'string' || !accessToken) {
        return back({ error: 'server_error' }, 'token_rejected', tok.status);
      }

      let ui: UpstreamAnswer;
      try {
        ui = await callUpstream(doFetch, {
          url: LINKEDIN_USERINFO_URL,
          method: 'GET',
          headers: { accept: 'application/json', authorization: `Bearer ${accessToken}` },
        });
      } catch {
        return back({ error: 'server_error' }, 'userinfo_unreachable');
      }
      // The LinkedIn token goes out of scope here; it is never stored or returned.
      const info = ui.status === 200 ? asObject(ui.body) : null;
      const sub = info?.['sub'];
      const pick = (v: unknown) => (typeof v === 'string' && v.trim() ? v.trim().slice(0, MAX_HANDLE) : null);
      const handle = pick(info?.['preferred_username']) ?? pick(info?.['name']);
      if (typeof sub !== 'string' || !sub || !handle) {
        return back({ error: 'server_error' }, 'userinfo_rejected', ui.status);
      }
      back({ handle, sub }, 'linked', ui.status);
    } catch {
      note(op, 'internal_error', 500);
      if (!res.headersSent) sendJson(res, 500, { error: 'internal_error' });
      else res.end();
    }
  });
}
