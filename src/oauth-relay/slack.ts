/**
 * Slack answer policy for the OAuth relay (Core Slack MCP user app).
 *
 * Slack Web API methods answer HTTP 200 with `{"ok":false,"error":"..."}` on
 * failure, so status alone says nothing. And one OAuth exchange can mint a bot
 * token beside the user token. The relay therefore reads the answer before it
 * passes it on:
 *
 * - `ok` not true: a clean `provider_rejected` with Slack's error code when it
 *   is a plain code (`invalid_code`), otherwise no detail. Nothing else from
 *   the answer is echoed.
 * - any bot or app token, or a granted user scope outside the approved set, or
 *   no granted scope at all: every access token in the answer is revoked
 *   (`auth.revoke`) and the answer is withheld.
 *
 * Docs (checked 2026-11-27): docs.slack.dev/reference/methods/oauth.v2.user.access,
 * docs.slack.dev/authentication/using-token-rotation,
 * docs.slack.dev/reference/methods/auth.revoke.
 */
import type { SlackUserAnswerPolicy } from './providers.js';

export type SlackRefusal = 'scope_not_approved' | 'scope_missing' | 'bot_token_refused' | 'unexpected_token_field';

export type SlackVerdict =
  | { kind: 'pass' }
  /** `code` is Slack's error code when it is a plain code, else null. */
  | { kind: 'provider_error'; code: string | null }
  /** `tokens`: every Slack token in the answer (access and refresh), to revoke before refusing. */
  | { kind: 'refuse'; reason: SlackRefusal; tokens: string[] };

/** Slack error codes are short snake_case words; anything else is not echoed. */
const ERROR_CODE_RE = /^[a-z0-9_]{1,64}$/;
/** User access tokens: classic `xoxp-` or rotating `xoxe.xoxp-`. */
const USER_TOKEN_RE = /^(xoxe\.)?xoxp-/;
/** Rotation refresh tokens: `xoxe-`. */
const REFRESH_TOKEN_RE = /^xoxe-/;
/** Anything that looks like a Slack credential. */
const SLACK_TOKEN_RE = /^xox/;
const MAX_DEPTH = 8;

/** The only token-bearing fields an oauth.v2.user.access answer may carry. */
const ACCESS_PATHS: ReadonlySet<string> = new Set(['access_token', 'authed_user.access_token']);
const REFRESH_PATHS: ReadonlySet<string> = new Set(['refresh_token', 'authed_user.refresh_token']);
/** Known bot token location (classic installs); always refused. */
const BOT_PATHS: ReadonlySet<string> = new Set(['bot.bot_access_token']);

type Json = Record<string, unknown>;

function asObject(v: unknown): Json | null {
  return v && typeof v === 'object' && !Array.isArray(v) ? (v as Json) : null;
}

function parse(body: Buffer): Json | null {
  try {
    return asObject(JSON.parse(body.toString('utf8')));
  } catch {
    return null;
  }
}

function errorCode(j: Json): string | null {
  const e = j['error'];
  return typeof e === 'string' && ERROR_CODE_RE.test(e) ? e : null;
}

interface FoundToken {
  path: string;
  value: string;
}

/**
 * Every token-bearing string anywhere in the answer: a key ending in `token`
 * (not `token_type`) or a value that looks like a Slack credential.
 */
function findTokens(v: unknown, path: string, out: FoundToken[], depth: number): void {
  if (depth > MAX_DEPTH) return;
  if (Array.isArray(v)) {
    v.forEach((x, i) => findTokens(x, `${path}[${i}]`, out, depth + 1));
    return;
  }
  const o = asObject(v);
  if (!o) return;
  for (const [k, x] of Object.entries(o)) {
    const p = path ? `${path}.${k}` : k;
    if (typeof x === 'string') {
      if ((/token$/i.test(k) && x.length > 0) || SLACK_TOKEN_RE.test(x)) out.push({ path: p, value: x });
    } else {
      findTokens(x, p, out, depth + 1);
    }
  }
}

/** Slack credentials in an answer (access and refresh), for revocation. Empty when unparseable. */
export function slackTokensIn(body: Buffer): string[] {
  const j = parse(body);
  if (!j) return [];
  const found: FoundToken[] = [];
  findTokens(j, '', found, 0);
  return [...new Set(found.map((f) => f.value).filter((t) => SLACK_TOKEN_RE.test(t)))];
}

/** Judge a token or refresh answer from oauth.v2.user.access. */
export function judgeSlackAnswer(body: Buffer, policy: SlackUserAnswerPolicy): SlackVerdict {
  const j = parse(body);
  if (!j) return { kind: 'provider_error', code: null };
  if (j['ok'] !== true) return { kind: 'provider_error', code: errorCode(j) };

  const found: FoundToken[] = [];
  findTokens(j, '', found, 0);
  if (found.length === 0) return { kind: 'provider_error', code: null };
  const tokens = [...new Set(found.map((f) => f.value).filter((t) => SLACK_TOKEN_RE.test(t)))];
  const refuse = (reason: SlackRefusal): SlackVerdict => ({ kind: 'refuse', reason, tokens });

  const known = (f: FoundToken) => ACCESS_PATHS.has(f.path) || REFRESH_PATHS.has(f.path) || BOT_PATHS.has(f.path);
  if (found.some((f) => !known(f))) return refuse('unexpected_token_field');

  const user = asObject(j['authed_user']);
  const typeOk = (t: unknown) => t === undefined || t === 'user';
  const hasBot =
    !typeOk(j['token_type']) ||
    !typeOk(user?.['token_type']) ||
    j['bot_user_id'] !== undefined ||
    j['bot'] !== undefined ||
    j['incoming_webhook'] !== undefined ||
    found.some((f) => BOT_PATHS.has(f.path)) ||
    found.some((f) => ACCESS_PATHS.has(f.path) && !USER_TOKEN_RE.test(f.value));
  if (hasBot) return refuse('bot_token_refused');
  if (found.some((f) => REFRESH_PATHS.has(f.path) && !REFRESH_TOKEN_RE.test(f.value))) {
    return refuse('unexpected_token_field');
  }

  const granted = [j['scope'], user?.['scope']]
    .filter((s): s is string => typeof s === 'string')
    .flatMap((s) => s.split(/[,\s]+/))
    .filter((s) => s.length > 0);
  if (granted.length === 0) return refuse('scope_missing');
  if (granted.some((s) => !policy.approvedUserScopes.has(s))) return refuse('scope_not_approved');
  return { kind: 'pass' };
}

/**
 * HTTP status and relay `error` for a Slack `ok:false` code: `ratelimited`
 * is 429, Slack-side failures are 502, any other plain code is the caller's
 * (400), and an unreadable error is 502.
 */
export function slackErrorStatus(code: string | null): { status: number; error: 'rate_limited' | 'provider_rejected' } {
  if (code === 'ratelimited') return { status: 429, error: 'rate_limited' };
  if (code === null || code === 'internal_error' || code === 'fatal_error' || code === 'service_unavailable' || code === 'request_timeout') {
    return { status: 502, error: 'provider_rejected' };
  }
  return { status: 400, error: 'provider_rejected' };
}

/** Judge an auth.revoke answer: success needs `ok:true`, not just HTTP 200. */
export function judgeSlackRevoke(body: Buffer): { ok: boolean; code: string | null } {
  const j = parse(body);
  if (!j) return { ok: false, code: null };
  return j['ok'] === true ? { ok: true, code: null } : { ok: false, code: errorCode(j) };
}
