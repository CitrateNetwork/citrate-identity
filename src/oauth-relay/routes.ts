/**
 * OAuth token relay (L6-WP04, AR-E8.1 / F-20): the desktop app never holds a
 * provider client secret.
 *
 *   POST /oauth/relay/v1/{provider}/token    { code, code_verifier, redirect_uri, resource? }
 *   POST /oauth/relay/v1/{provider}/refresh  { refresh_token, resource? }
 *   POST /oauth/relay/v1/{provider}/revoke   { token }
 *   Authorization: Bearer <auth.citrate.ai access token>   (owner decision L6-Q5)
 *
 * The relay adds `client_id` + `client_secret` server side, calls the
 * provider's FIXED endpoint from `providers.ts`, and returns the provider's
 * token response byte for byte (status, body, content type). It stores
 * nothing.
 *
 * Data source: the provider token/revoke endpoints in `providers.ts`; client
 * credentials from `{PROVIDER}_CLIENT_ID` / `{PROVIDER}_CLIENT_SECRET` in the
 * deployment environment; member identity from this authority's own
 * AccessToken store (panva adapter, Redis in prod).
 *
 * SECURITY
 * - Not a proxy: the outbound URL is a table constant; the request only picks
 *   a row. Upstream redirects are not followed (`redirect: 'manual'`).
 * - Only whitelisted fields are forwarded. A client-supplied client_id or
 *   client_secret is ignored. The member's bearer never goes upstream.
 * - redirect_uri must exactly equal one of the provider's registered values.
 * - code_verifier is required on the code exchange (PKCE, RFC 7636 shape).
 * - JSON body only, capped at 8 KiB. Per-IP (pre-auth) and per-account
 *   budgets, shared across instances via Redis when wired.
 * - Never logs a body, code, verifier, token or secret: log lines carry only
 *   provider id, operation, outcome and status codes.
 * - A response that contains the client secret is replaced by a generic 502.
 * - `OAUTH_RELAY=0` disables every route (503 relay_disabled, no outbound
 *   call). A provider with no configured secret answers 503 not_configured.
 * - `Cache-Control: no-store` and `X-Content-Type-Options: nosniff` on every
 *   answer, relayed ones included.
 * - A bearer issued before the account's revocation epoch (password reset,
 *   sign out everywhere; `auth/account-epoch.ts`) is refused like an unknown
 *   one, so it stops working on the relay at once rather than at expiry.
 */
import type { IncomingMessage, ServerResponse } from 'node:http';
import type Provider from 'oidc-provider';
import { isRevokedByEpoch, tokenAuthSec } from '../auth/account-epoch.js';
import { clientIp, type RateLimiter } from '../auth/rate-limit.js';
import {
  findRelayProvider,
  providerCredentials,
  type BodyEncoding,
  type ProviderCredentials,
  type RelayProvider,
} from './providers.js';

export const RELAY_PATH_PREFIX = '/oauth/relay/v1/';
export const RELAY_MAX_BODY_BYTES = 8 * 1024;
/** Upstream answers larger than this are refused (a token response is small). */
export const RELAY_MAX_UPSTREAM_BYTES = 256 * 1024;
export const RELAY_UPSTREAM_TIMEOUT_MS = 15_000;

/** Only the desktop apps hold a loopback redirect; other RPs' tokens are refused. */
export const RELAY_CLIENT_IDS: ReadonlySet<string> = new Set(['citrate-core', 'citrate-gui-native']);

export interface RelayLimits {
  windowMs: number;
  /** Charged before authentication, so token guessing is bounded too. */
  perIp: number;
  perAccount: number;
}

export const RELAY_LIMITS: RelayLimits = Object.freeze({
  windowMs: 15 * 60 * 1000,
  perIp: 120,
  perAccount: 40,
});

export interface RelayLogger {
  info(...args: unknown[]): void;
  warn(...args: unknown[]): void;
  error(...args: unknown[]): void;
}

export interface OAuthRelayOptions {
  /** Outbound HTTP seam (tests). Defaults to the global fetch. */
  fetch?: typeof fetch;
  /** Environment to read OAUTH_RELAY and provider credentials from. Defaults to process.env. */
  env?: Readonly<Record<string, string | undefined>>;
  logger?: RelayLogger;
  limits?: Partial<RelayLimits>;
}

type Operation = 'token' | 'refresh' | 'revoke';
const OPERATIONS: ReadonlySet<string> = new Set(['token', 'refresh', 'revoke']);

/** RFC 7636 section 4.1: 43 to 128 chars of [A-Z a-z 0-9 - . _ ~]. */
const CODE_VERIFIER_RE = /^[A-Za-z0-9\-._~]{43,128}$/;

function noStoreHeaders(contentType: string): Record<string, string> {
  return {
    'content-type': contentType,
    'cache-control': 'no-store',
    pragma: 'no-cache',
    'referrer-policy': 'no-referrer',
    'x-content-type-options': 'nosniff',
  };
}

function sendJson(
  res: ServerResponse,
  status: number,
  body: unknown,
  extra: Record<string, string> = {},
): void {
  res.writeHead(status, { ...noStoreHeaders('application/json; charset=utf-8'), ...extra });
  res.end(JSON.stringify(body));
}

class BodyError extends Error {
  constructor(
    readonly status: number,
    readonly reason: string,
  ) {
    super(reason);
  }
}

async function readJsonBody(req: IncomingMessage): Promise<Record<string, unknown>> {
  const ct = String(req.headers['content-type'] ?? '').toLowerCase();
  if (!ct.startsWith('application/json')) {
    throw new BodyError(400, 'Content-Type must be application/json');
  }
  const declared = Number(req.headers['content-length']);
  if (Number.isFinite(declared) && declared > RELAY_MAX_BODY_BYTES) {
    throw new BodyError(413, 'request body exceeds 8 KiB');
  }
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    const buf = chunk as Buffer;
    size += buf.length;
    if (size > RELAY_MAX_BODY_BYTES) throw new BodyError(413, 'request body exceeds 8 KiB');
    chunks.push(buf);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    throw new BodyError(400, 'request body is not valid JSON');
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new BodyError(400, 'request body must be a JSON object');
  }
  return parsed as Record<string, unknown>;
}

function str(body: Record<string, unknown>, key: string): string | null {
  const v = body[key];
  return typeof v === 'string' && v.length > 0 ? v : null;
}

/**
 * Bearer access token issued by this authority, or null. A token issued before
 * the account's revocation epoch (PBA-L3a-008) counts as no token.
 */
async function resolveMember(
  provider: Provider,
  req: IncomingMessage,
): Promise<{ accountId: string; clientId: string } | null> {
  const auth = req.headers['authorization'];
  if (typeof auth !== 'string') return null;
  const m = /^Bearer\s+(\S+)$/i.exec(auth.trim());
  if (!m || !m[1]) return null;
  try {
    const token = await provider.AccessToken.find(m[1]);
    if (!token || token.isExpired) return null;
    if (typeof token.accountId !== 'string' || typeof token.clientId !== 'string') return null;
    if (await isRevokedByEpoch(token.accountId, tokenAuthSec(token))) return null;
    return { accountId: token.accountId, clientId: token.clientId };
  } catch {
    return null;
  }
}

/** Optional RFC 8707 resource: must be an absolute https URL without a fragment. */
function parseResource(body: Record<string, unknown>): string | null | undefined {
  if (body['resource'] === undefined) return undefined;
  const r = str(body, 'resource');
  if (!r) return null;
  try {
    const u = new URL(r);
    if (u.protocol !== 'https:' || u.hash) return null;
    return r;
  } catch {
    return null;
  }
}

function encode(encoding: BodyEncoding, fields: Record<string, string>): { body: string; contentType: string } {
  return encoding === 'json'
    ? { body: JSON.stringify(fields), contentType: 'application/json' }
    : { body: new URLSearchParams(fields).toString(), contentType: 'application/x-www-form-urlencoded' };
}

function basic(creds: ProviderCredentials): string {
  return 'Basic ' + Buffer.from(`${creds.clientId}:${creds.clientSecret}`).toString('base64');
}

interface OutboundRequest {
  url: string;
  method: 'POST' | 'DELETE';
  headers: Record<string, string>;
  body: string;
}

/** Build the token/refresh request; client credentials per the provider's auth style. */
function grantRequest(
  p: RelayProvider,
  creds: ProviderCredentials,
  url: string,
  grant: Record<string, string>,
): OutboundRequest {
  const fields: Record<string, string> =
    p.authStyle === 'body'
      ? { client_id: creds.clientId, client_secret: creds.clientSecret, ...grant }
      : { ...grant };
  const { body, contentType } = encode(p.encoding, fields);
  return {
    url,
    method: 'POST',
    headers: {
      ...p.headers,
      'content-type': contentType,
      ...(p.authStyle === 'basic' ? { authorization: basic(creds) } : {}),
    },
    body,
  };
}

interface UpstreamAnswer {
  status: number;
  contentType: string;
  body: Buffer;
}

class UpstreamError extends Error {}

async function callUpstream(doFetch: typeof fetch, req: OutboundRequest): Promise<UpstreamAnswer> {
  let res: Response;
  try {
    res = await doFetch(req.url, {
      method: req.method,
      headers: req.headers,
      body: req.body,
      redirect: 'manual',
      signal: AbortSignal.timeout(RELAY_UPSTREAM_TIMEOUT_MS),
    });
  } catch {
    throw new UpstreamError('unreachable');
  }
  const declared = Number(res.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > RELAY_MAX_UPSTREAM_BYTES) {
    throw new UpstreamError('oversized');
  }
  const chunks: Buffer[] = [];
  let size = 0;
  if (res.body) {
    try {
      for await (const chunk of res.body as unknown as AsyncIterable<Uint8Array>) {
        size += chunk.byteLength;
        if (size > RELAY_MAX_UPSTREAM_BYTES) throw new UpstreamError('oversized');
        chunks.push(Buffer.from(chunk));
      }
    } catch (e) {
      throw e instanceof UpstreamError ? e : new UpstreamError('unreadable');
    }
  }
  return {
    status: res.status,
    contentType: res.headers.get('content-type') ?? 'application/json; charset=utf-8',
    body: Buffer.concat(chunks),
  };
}

/** True when the upstream answer contains the client secret in any common form. */
function echoesSecret(answer: UpstreamAnswer, creds: ProviderCredentials): boolean {
  const text = answer.body.toString('utf8');
  return (
    text.includes(creds.clientSecret) ||
    text.includes(encodeURIComponent(creds.clientSecret)) ||
    // application/x-www-form-urlencoded: space as '+', and !'()~ escaped.
    text.includes(new URLSearchParams({ s: creds.clientSecret }).toString().slice(2)) ||
    text.includes(Buffer.from(`${creds.clientId}:${creds.clientSecret}`).toString('base64'))
  );
}

/**
 * Mount the relay. Installed before panva's router like the other custom
 * routes (`mountOAuthBounce`), so `/oauth/relay/v1/*` never reaches the OIDC
 * catch-all.
 */
export function mountOAuthRelay(
  provider: Provider,
  opts: OAuthRelayOptions & { rateLimiter: RateLimiter },
): void {
  const env = opts.env ?? process.env;
  const enabled = env['OAUTH_RELAY'] !== '0';
  const doFetch = opts.fetch ?? fetch;
  const logger: RelayLogger = opts.logger ?? console;
  const limits: RelayLimits = { ...RELAY_LIMITS, ...(opts.limits ?? {}) };
  const limiter = opts.rateLimiter;
  const retryAfter = String(Math.ceil(limits.windowMs / 1000));

  /** The only log line shape: no bodies, codes, tokens, secrets or account ids. */
  const note = (level: 'info' | 'warn', providerId: string, op: string, outcome: string, status: number, upstream?: number) =>
    logger[level](
      `[oauth-relay] provider=${providerId} op=${op} outcome=${outcome} status=${status}` +
        (upstream !== undefined ? ` upstream_status=${upstream}` : ''),
    );

  provider.use(async (ctx, next) => {
    if (!ctx.path.startsWith(RELAY_PATH_PREFIX)) {
      await next();
      return;
    }
    const res = ctx.res;
    // Respond directly on the raw response; koa must not touch it afterwards.
    ctx.respond = false;

    if (!enabled) {
      sendJson(res, 503, { error: 'relay_disabled', reason: 'the OAuth relay is turned off on this authority' });
      return;
    }

    const parts = ctx.path.slice(RELAY_PATH_PREFIX.length).split('/');
    const [providerId = '', op = ''] = parts;
    const p = parts.length === 2 ? findRelayProvider(providerId) : undefined;
    if (!p) {
      sendJson(res, 404, { error: 'unknown_provider' });
      return;
    }
    if (!OPERATIONS.has(op)) {
      sendJson(res, 404, { error: 'unknown_operation', reason: 'use token, refresh or revoke' });
      return;
    }
    const operation = op as Operation;
    if (ctx.method !== 'POST') {
      sendJson(res, 405, { error: 'method_not_allowed', reason: 'POST only' }, { allow: 'POST' });
      return;
    }

    try {
      const ip = clientIp(ctx.req, provider.proxy === true);
      if (!(await limiter.hit(`oauth-relay:ip:${ip}`, limits.perIp, limits.windowMs))) {
        note('warn', p.id, operation, 'rate_limited_ip', 429);
        sendJson(res, 429, { error: 'rate_limited' }, { 'retry-after': retryAfter });
        return;
      }

      const member = await resolveMember(provider, ctx.req);
      if (!member) {
        sendJson(res, 401, { error: 'not_signed_in', reason: 'a valid auth.citrate.ai access token is required' }, {
          'www-authenticate': 'Bearer realm="oauth-relay"',
        });
        return;
      }
      if (!RELAY_CLIENT_IDS.has(member.clientId)) {
        sendJson(res, 403, { error: 'client_not_permitted', reason: 'only the Citrate desktop app may use the relay' });
        return;
      }
      if (!(await limiter.hit(`oauth-relay:acct:${member.accountId}`, limits.perAccount, limits.windowMs))) {
        note('warn', p.id, operation, 'rate_limited_account', 429);
        sendJson(res, 429, { error: 'rate_limited' }, { 'retry-after': retryAfter });
        return;
      }

      const creds = providerCredentials(p, env);
      if (!creds) {
        note('warn', p.id, operation, 'not_configured', 503);
        sendJson(res, 503, {
          error: 'not_configured',
          reason: `${p.id} is not configured on the relay (${p.envPrefix}_CLIENT_ID and ${p.envPrefix}_CLIENT_SECRET must both be set)`,
        });
        return;
      }

      let body: Record<string, unknown>;
      try {
        body = await readJsonBody(ctx.req);
      } catch (e) {
        const be = e instanceof BodyError ? e : new BodyError(400, 'unreadable request body');
        sendJson(res, be.status, { error: 'bad_request', reason: be.reason });
        return;
      }

      const bad = (reason: string) => sendJson(res, 400, { error: 'bad_request', reason });
      const resource = parseResource(body);
      if (resource === null) return bad('resource must be an absolute https URL');
      const withResource = (g: Record<string, string>) => (resource ? { ...g, resource } : g);

      let outbound: OutboundRequest;
      if (operation === 'token') {
        const code = str(body, 'code');
        const verifier = str(body, 'code_verifier');
        const redirectUri = str(body, 'redirect_uri');
        if (!code) return bad('code is required');
        if (!verifier || !CODE_VERIFIER_RE.test(verifier)) {
          return bad('code_verifier is required (RFC 7636: 43 to 128 unreserved characters)');
        }
        if (!redirectUri || !p.redirectUris.includes(redirectUri)) {
          return bad('redirect_uri is not registered for this provider');
        }
        outbound = grantRequest(
          p,
          creds,
          p.tokenUrl,
          withResource({ grant_type: 'authorization_code', code, code_verifier: verifier, redirect_uri: redirectUri }),
        );
      } else if (operation === 'refresh') {
        if (!p.refreshUrl) {
          sendJson(res, 400, { error: 'unsupported_operation', reason: `${p.id} issues no refresh tokens` });
          return;
        }
        const refreshToken = str(body, 'refresh_token');
        if (!refreshToken) return bad('refresh_token is required');
        outbound = grantRequest(
          p,
          creds,
          p.refreshUrl,
          withResource({ grant_type: 'refresh_token', refresh_token: refreshToken }),
        );
      } else {
        if (!p.revoke) {
          sendJson(res, 400, { error: 'unsupported_operation', reason: `${p.id} has no revocation endpoint` });
          return;
        }
        const token = str(body, 'token');
        if (!token) return bad('token is required');
        const enc = encode(p.revoke.encoding, { [p.revoke.tokenField]: token });
        outbound = {
          url: p.revoke.url(creds.clientId),
          method: p.revoke.method,
          headers: { ...p.revoke.headers, 'content-type': enc.contentType, authorization: basic(creds) },
          body: enc.body,
        };
      }

      let answer: UpstreamAnswer;
      try {
        answer = await callUpstream(doFetch, outbound);
      } catch (e) {
        const why = e instanceof UpstreamError ? e.message : 'unreachable';
        note('warn', p.id, operation, `upstream_${why}`, 502);
        sendJson(res, 502, { error: 'provider_rejected', reason: `the provider could not be reached (${why})` });
        return;
      }

      if (echoesSecret(answer, creds)) {
        note('warn', p.id, operation, 'upstream_echoed_secret', 502, answer.status);
        sendJson(res, 502, { error: 'provider_rejected', reason: 'the provider answer was withheld' });
        return;
      }
      if (answer.status >= 300 && answer.status < 400) {
        note('warn', p.id, operation, 'upstream_redirect', 502, answer.status);
        sendJson(res, 502, { error: 'provider_rejected', reason: 'the provider answered with a redirect' });
        return;
      }

      if (operation === 'revoke') {
        const ok = answer.status >= 200 && answer.status < 300;
        note(ok ? 'info' : 'warn', p.id, operation, ok ? 'revoked' : 'provider_rejected', ok ? 200 : 502, answer.status);
        if (ok) sendJson(res, 200, { revoked: true, upstream_status: answer.status });
        else sendJson(res, 502, { error: 'provider_rejected', revoked: false, upstream_status: answer.status });
        return;
      }

      // Token and refresh: the provider's answer, unchanged.
      note(answer.status < 400 ? 'info' : 'warn', p.id, operation, 'relayed', answer.status, answer.status);
      res.writeHead(answer.status, noStoreHeaders(answer.contentType));
      res.end(answer.body);
    } catch {
      // Never echo the error: it could carry request material.
      note('warn', p.id, operation, 'internal_error', 500);
      if (!res.headersSent) sendJson(res, 500, { error: 'internal_error' });
      else res.end();
    }
  });
}
