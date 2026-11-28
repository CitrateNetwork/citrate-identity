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

export type SlackRefusal = 'scope_not_approved' | 'scope_missing' | 'bot_token_refused';

export type SlackVerdict =
  | { kind: 'pass' }
  /** `code` is Slack's error code when it is a plain code, else null. */
  | { kind: 'provider_error'; code: string | null }
  /** `tokens`: every access token in the answer, to revoke before refusing. */
  | { kind: 'refuse'; reason: SlackRefusal; tokens: string[] };

/** Slack error codes are short snake_case words; anything else is not echoed. */
const ERROR_CODE_RE = /^[a-z0-9_]{1,64}$/;
/** User tokens: classic `xoxp-` or rotating `xoxe.xoxp-`. */
const USER_TOKEN_RE = /^(xoxe\.)?xoxp-/;

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

/** Judge a token or refresh answer from oauth.v2.user.access. */
export function judgeSlackAnswer(body: Buffer, policy: SlackUserAnswerPolicy): SlackVerdict {
  const j = parse(body);
  if (!j) return { kind: 'provider_error', code: null };
  if (j['ok'] !== true) return { kind: 'provider_error', code: errorCode(j) };

  const user = asObject(j['authed_user']);
  const bot = asObject(j['bot']);
  const tokens = [j['access_token'], user?.['access_token'], bot?.['bot_access_token']].filter(
    (t): t is string => typeof t === 'string' && t.length > 0,
  );
  if (tokens.length === 0) return { kind: 'provider_error', code: null };

  const typeOk = (t: unknown) => t === undefined || t === 'user';
  const hasBot =
    !typeOk(j['token_type']) ||
    !typeOk(user?.['token_type']) ||
    j['bot_user_id'] !== undefined ||
    j['bot'] !== undefined ||
    j['incoming_webhook'] !== undefined ||
    tokens.some((t) => !USER_TOKEN_RE.test(t));
  if (hasBot) return { kind: 'refuse', reason: 'bot_token_refused', tokens };

  const scopeStrings = [j['scope'], user?.['scope']].filter((s): s is string => typeof s === 'string');
  if (scopeStrings.length === 0) return { kind: 'refuse', reason: 'scope_missing', tokens };
  const granted = scopeStrings.flatMap((s) => s.split(/[,\s]+/)).filter((s) => s.length > 0);
  if (granted.some((s) => !policy.approvedUserScopes.has(s))) {
    return { kind: 'refuse', reason: 'scope_not_approved', tokens };
  }
  return { kind: 'pass' };
}

/** Judge an auth.revoke answer: success needs `ok:true`, not just HTTP 200. */
export function judgeSlackRevoke(body: Buffer): { ok: boolean; code: string | null } {
  const j = parse(body);
  if (!j) return { ok: false, code: null };
  return j['ok'] === true ? { ok: true, code: null } : { ok: false, code: errorCode(j) };
}
