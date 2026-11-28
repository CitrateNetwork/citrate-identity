/**
 * Slack answer policy for the OAuth relay (Core Slack MCP user app).
 *
 * Slack Web API methods answer HTTP 200 with `{"ok":false,"error":"..."}` on
 * failure, so status alone says nothing, and one OAuth exchange can mint a bot
 * token beside the user token. The relay therefore never relays Slack's raw
 * body. It parses it strictly (duplicate keys and nesting past
 * {@link MAX_JSON_DEPTH} are refused), validates it, and on success REBUILDS
 * the answer from an explicit allowlist of fields.
 *
 * - `ok` not true: a clean error with Slack's error code when it is a plain
 *   code (`invalid_code`), otherwise no detail.
 * - Refused, with every Slack token found anywhere in the bytes revoked
 *   (`auth.revoke`) first: a bot or app token; a token-looking string anywhere
 *   but the four known token fields (arrays, keys, any depth, JSON escapes
 *   included); a known field of the wrong type; a granted user scope outside
 *   the approved set; no granted scope.
 *
 * Docs (checked 2026-11-27): docs.slack.dev/reference/methods/oauth.v2.user.access,
 * docs.slack.dev/authentication/using-token-rotation,
 * docs.slack.dev/reference/methods/auth.revoke.
 */
import type { SlackUserAnswerPolicy } from './providers.js';

export type SlackRefusal =
  | 'scope_not_approved'
  | 'scope_missing'
  | 'bot_token_refused'
  | 'unexpected_token_field'
  | 'malformed_answer';

export type SlackVerdict =
  /** `body`: the answer rebuilt from the allowlist; the only bytes relayed. */
  | { kind: 'pass'; body: Buffer }
  /** `code`: Slack's error code when it is a plain code, else null. `tokens`: to revoke. */
  | { kind: 'provider_error'; code: string | null; tokens: string[] }
  /**
   * `tokens`: every Slack token in the answer, revoked before refusing.
   * `unrevocable`: a known token field held a value that is not a Slack token,
   * so revocation cannot be confirmed.
   */
  | { kind: 'refuse'; reason: SlackRefusal; tokens: string[]; unrevocable: boolean };

/** Nesting deeper than this is refused (a token answer is two levels deep). */
export const MAX_JSON_DEPTH = 32;

/** Slack error codes are short snake_case words; anything else is not echoed. */
const ERROR_CODE_RE = /^[a-z0-9_]{1,64}$/;
/** A Slack credential anywhere in a string: `xox?-...` or rotating `xoxe.` / `xoxe-`. */
const TOKEN_SCAN_RE = /xox[a-z]-[A-Za-z0-9._-]*|xoxe[.-][A-Za-z0-9._-]*/g;
const TOKEN_FULL_RE = /^(?:xox[a-z]-[A-Za-z0-9._-]*|xoxe[.-][A-Za-z0-9._-]*)$/;
/** User access tokens: classic `xoxp-` or rotating `xoxe.xoxp-`. */
const USER_TOKEN_RE = /^(xoxe\.)?xoxp-/;
/** Rotation refresh tokens. */
const REFRESH_TOKEN_RE = /^xoxe-/;

const ACCESS_PATHS: ReadonlySet<string> = new Set(['access_token', 'authed_user.access_token']);
const REFRESH_PATHS: ReadonlySet<string> = new Set(['refresh_token', 'authed_user.refresh_token']);
const BOT_KEYS = ['bot_user_id', 'bot', 'incoming_webhook'] as const;

type Json = Record<string, unknown>;

// ---- strict JSON ------------------------------------------------------------

class StrictJsonError extends Error {}

/**
 * JSON.parse with two extra refusals: a duplicate key in any object, and
 * nesting deeper than `maxDepth`. Objects are built with own properties only
 * (`__proto__` is an ordinary key).
 */
export function parseStrictJson(text: string, maxDepth: number = MAX_JSON_DEPTH): unknown {
  let i = 0;
  const fail = (why: string): never => {
    throw new StrictJsonError(why);
  };
  const ws = () => {
    while (i < text.length && (text[i] === ' ' || text[i] === '\t' || text[i] === '\n' || text[i] === '\r')) i++;
  };
  const str = (): string => {
    const start = i++;
    while (i < text.length) {
      const c = text.charCodeAt(i);
      if (c === 0x5c) i += 2;
      else if (c === 0x22) {
        i++;
        try {
          return JSON.parse(text.slice(start, i)) as string;
        } catch {
          return fail('bad string');
        }
      } else if (c < 0x20) return fail('control character');
      else i++;
    }
    return fail('unterminated string');
  };
  const NUM = /-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/y;
  const value = (depth: number): unknown => {
    if (depth > maxDepth) fail('too deep');
    ws();
    const c = text[i];
    if (c === '{') {
      i++;
      const o: Json = {};
      ws();
      if (text[i] === '}') {
        i++;
        return o;
      }
      for (;;) {
        ws();
        if (text[i] !== '"') fail('expected key');
        const k = str();
        if (Object.prototype.hasOwnProperty.call(o, k)) fail('duplicate key');
        ws();
        if (text[i++] !== ':') fail('expected colon');
        Object.defineProperty(o, k, { value: value(depth + 1), enumerable: true, writable: true, configurable: true });
        ws();
        if (text[i] === ',') i++;
        else if (text[i] === '}') {
          i++;
          return o;
        } else fail('expected , or }');
      }
    }
    if (c === '[') {
      i++;
      const a: unknown[] = [];
      ws();
      if (text[i] === ']') {
        i++;
        return a;
      }
      for (;;) {
        a.push(value(depth + 1));
        ws();
        if (text[i] === ',') i++;
        else if (text[i] === ']') {
          i++;
          return a;
        } else fail('expected , or ]');
      }
    }
    if (c === '"') return str();
    for (const [lit, v] of [['true', true], ['false', false], ['null', null]] as const) {
      if (text.startsWith(lit, i)) {
        i += lit.length;
        return v;
      }
    }
    NUM.lastIndex = i;
    const m = NUM.exec(text);
    if (!m) return fail('unexpected token');
    i += m[0].length;
    return Number(m[0]);
  };
  const v = value(0);
  ws();
  if (i !== text.length) fail('trailing data');
  return v;
}

function asObject(v: unknown): Json | null {
  return v && typeof v === 'object' && !Array.isArray(v) ? (v as Json) : null;
}

function strictObject(body: Buffer): Json | null {
  try {
    return asObject(parseStrictJson(body.toString('utf8')));
  } catch {
    return null;
  }
}

function errorCode(j: Json): string | null {
  const e = j['error'];
  return typeof e === 'string' && ERROR_CODE_RE.test(e) ? e : null;
}

// ---- token discovery --------------------------------------------------------

interface Occurrence {
  /** Dotted path (`authed_user.access_token`, `extra[0]`), or `key:<path>` for an object key. */
  path: string;
  value: string;
}

/** Every string (keys included) that contains a Slack token, at any depth. */
function walk(v: unknown, path: string, out: Occurrence[]): void {
  if (typeof v === 'string') {
    TOKEN_SCAN_RE.lastIndex = 0;
    if (TOKEN_SCAN_RE.test(v)) out.push({ path, value: v });
    return;
  }
  if (Array.isArray(v)) {
    v.forEach((x, idx) => walk(x, `${path}[${idx}]`, out));
    return;
  }
  const o = asObject(v);
  if (!o) return;
  for (const [k, x] of Object.entries(o)) {
    const p = path ? `${path}.${k}` : k;
    TOKEN_SCAN_RE.lastIndex = 0;
    if (TOKEN_SCAN_RE.test(k)) out.push({ path: `key:${p}`, value: k });
    walk(x, p, out);
  }
}

function scan(text: string): string[] {
  return text.match(TOKEN_SCAN_RE) ?? [];
}

/**
 * Every Slack token in an answer's bytes, for revocation: a raw scan of the
 * bytes (works on truncated or malformed answers) plus, when the bytes parse,
 * the decoded strings (catches JSON escapes).
 */
export function slackTokensIn(body: Buffer): string[] {
  const text = body.toString('utf8');
  const found = scan(text);
  try {
    const occ: Occurrence[] = [];
    walk(parseStrictJson(text), '', occ);
    for (const o of occ) found.push(...scan(o.value));
  } catch {
    // Unparseable: the raw scan is all there is.
  }
  return [...new Set(found)];
}

// ---- the allowlist ----------------------------------------------------------

type Kind = 'string' | 'number' | 'boolean';

const TOP_FIELDS: ReadonlyArray<readonly [string, Kind]> = [
  ['app_id', 'string'],
  ['scope', 'string'],
  ['token_type', 'string'],
  ['access_token', 'string'],
  ['expires_in', 'number'],
  ['refresh_token', 'string'],
  ['is_enterprise_install', 'boolean'],
];
const USER_FIELDS: ReadonlyArray<readonly [string, Kind]> = [
  ['id', 'string'],
  ['scope', 'string'],
  ['token_type', 'string'],
  ['access_token', 'string'],
  ['expires_in', 'number'],
  ['refresh_token', 'string'],
];
const ORG_FIELDS: ReadonlyArray<readonly [string, Kind]> = [
  ['id', 'string'],
  ['name', 'string'],
];

/** Copy the allowlisted fields; null when a present field has the wrong type. */
function pick(src: Json, fields: ReadonlyArray<readonly [string, Kind]>): Json | null {
  const out: Json = {};
  for (const [k, kind] of fields) {
    if (!Object.prototype.hasOwnProperty.call(src, k)) continue;
    const v = src[k];
    if (typeof v !== kind) return null;
    out[k] = v;
  }
  return out;
}

/** The rebuilt answer, or null when an allowlisted field has the wrong shape. */
function rebuild(j: Json): Json | null {
  const out: Json = { ok: true };
  const top = pick(j, TOP_FIELDS);
  if (!top) return null;
  if ('authed_user' in j) {
    const u = asObject(j['authed_user']);
    const pu = u && pick(u, USER_FIELDS);
    if (!pu) return null;
    out['authed_user'] = pu;
  }
  Object.assign(out, top);
  for (const k of ['team', 'enterprise'] as const) {
    if (!(k in j)) continue;
    if (j[k] === null) {
      out[k] = null;
      continue;
    }
    const o = asObject(j[k]);
    const po = o && pick(o, ORG_FIELDS);
    if (!po) return null;
    out[k] = po;
  }
  return out;
}

// ---- verdicts ---------------------------------------------------------------

/** Judge a token or refresh answer from oauth.v2.user.access. */
export function judgeSlackAnswer(body: Buffer, policy: SlackUserAnswerPolicy): SlackVerdict {
  const tokens = slackTokensIn(body);
  const j = strictObject(body);
  if (!j) {
    return tokens.length > 0
      ? { kind: 'refuse', reason: 'malformed_answer', tokens, unrevocable: false }
      : { kind: 'provider_error', code: null, tokens };
  }
  if (j['ok'] !== true) return { kind: 'provider_error', code: errorCode(j), tokens };

  const known = new Map<string, string>();
  for (const p of [...ACCESS_PATHS, ...REFRESH_PATHS]) {
    const [a, b] = p.split('.') as [string, string | undefined];
    const v = b === undefined ? j[a] : asObject(j[a])?.[b];
    if (typeof v === 'string') known.set(p, v);
  }
  const unrevocable = [...known.values()].some((v) => !TOKEN_FULL_RE.test(v));
  const refuse = (reason: SlackRefusal): SlackVerdict => ({ kind: 'refuse', reason, tokens, unrevocable });

  const rebuilt = rebuild(j);
  if (!rebuilt) return refuse('malformed_answer');

  const user = asObject(j['authed_user']);
  const typeOk = (t: unknown) => t === undefined || t === 'user';
  const accessValues = [...known].filter(([p]) => ACCESS_PATHS.has(p)).map(([, v]) => v);
  if (
    !typeOk(j['token_type']) ||
    !typeOk(user?.['token_type']) ||
    BOT_KEYS.some((k) => j[k] !== undefined) ||
    accessValues.some((v) => /^xox/.test(v) && !USER_TOKEN_RE.test(v))
  ) {
    return refuse('bot_token_refused');
  }

  // A token anywhere but a known field, or a known field that is not exactly one token.
  const occ: Occurrence[] = [];
  walk(j, '', occ);
  if (occ.some((o) => !known.has(o.path) || !TOKEN_FULL_RE.test(o.value))) return refuse('unexpected_token_field');
  if ([...known].some(([p, v]) => (ACCESS_PATHS.has(p) ? !USER_TOKEN_RE.test(v) : !REFRESH_TOKEN_RE.test(v)))) {
    return refuse('unexpected_token_field');
  }
  // The raw bytes must not hold a token the decoded known fields do not account for.
  const knownSet = new Set(known.values());
  if (scan(body.toString('utf8')).some((t) => !knownSet.has(t))) return refuse('unexpected_token_field');

  const granted = [j['scope'], user?.['scope']]
    .filter((s): s is string => typeof s === 'string')
    .flatMap((s) => s.split(/[,\s]+/))
    .filter((s) => s.length > 0);
  if (granted.length === 0) return refuse('scope_missing');
  if (granted.some((s) => !policy.approvedUserScopes.has(s))) return refuse('scope_not_approved');
  if (accessValues.length === 0) return refuse('malformed_answer');

  return { kind: 'pass', body: Buffer.from(JSON.stringify(rebuilt), 'utf8') };
}

/**
 * HTTP status and relay `error` for a Slack `ok:false` code: `ratelimited`
 * is 429, Slack-side failures are 502, any other plain code is the caller's
 * (400), and an unreadable error is 502.
 */
export function slackErrorStatus(code: string | null): { status: number; error: 'rate_limited' | 'provider_rejected' } {
  if (code === 'ratelimited') return { status: 429, error: 'rate_limited' };
  if (
    code === null ||
    code === 'internal_error' ||
    code === 'fatal_error' ||
    code === 'service_unavailable' ||
    code === 'request_timeout'
  ) {
    return { status: 502, error: 'provider_rejected' };
  }
  return { status: 400, error: 'provider_rejected' };
}

/** Judge an auth.revoke answer: success needs `ok:true`, not just HTTP 200. */
export function judgeSlackRevoke(body: Buffer): { ok: boolean; code: string | null } {
  const j = strictObject(body);
  if (!j) return { ok: false, code: null };
  return j['ok'] === true ? { ok: true, code: null } : { ok: false, code: errorCode(j) };
}
