/**
 * `POST /kyc/handoff` — the authenticated hand-off mint (item 2, backend work
 * order 2026-08-06; spec: IDENTITY_ACCOUNT_HANDOFF_2026-08-06.md §3a).
 *
 * The desktop app cannot present its OIDC session to a system-browser navigation,
 * so it proves who it is HERE with the access token it already holds. We validate
 * the Bearer token, mint a single-use nonce bound to the token's `sub`
 * ({@link HandoffStore}), and return a URL the app opens in the browser:
 *
 *   POST /kyc/handoff   Authorization: Bearer <app access token>
 *     body (optional JSON): { target?: "kyc"|"account", level?: "T3"|"T4", return_to?: <https url> }
 *     → 200 { url: "https://auth.citrate.ai/kyc/start?handoff=<nonce>[&level=..&return_to=..]" }
 *
 * The consuming page (`mountKycStartRoute` / `mountAccountRoute`) resolves the
 * subject from the nonce and IGNORES the browser cookie, so the surface always
 * opens for the app's subject — never whichever account the browser happens to
 * hold. `level`/`return_to` are forwarded verbatim; `/kyc/start` is the authority
 * that validates them (an allowed origin, a known level), so this route need not.
 *
 * Fails closed: a missing / invalid / expired token → 401. A light per-subject
 * rate limit caps mint abuse from a leaked token — defence-in-depth only, since a
 * nonce is single-use and can only ever start the SAME subject's own verification.
 */
import type { IncomingMessage, ServerResponse } from 'node:http';
import type Provider from 'oidc-provider';
import type { HandoffStore } from './handoff-store.js';

/** The authority's own origin — the hand-off URLs are always first-party. */
function selfOrigin(): string {
  return (process.env.ISSUER_URL || 'https://auth.citrate.ai').replace(/\/+$/, '');
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
  });
  res.end(JSON.stringify(body));
}

/** Bearer access token → accountId (sub), or null. Mirrors identity-registry's resolveSub. */
async function resolveToken(
  provider: Provider,
  req: IncomingMessage,
): Promise<{ sub: string; clientId: string } | null> {
  const auth = req.headers['authorization'];
  if (typeof auth !== 'string') return null;
  const m = /^Bearer\s+(.+)$/i.exec(auth.trim());
  if (!m || !m[1]) return null;
  try {
    const token = await provider.AccessToken.find(m[1].trim());
    if (!token || token.isExpired) return null;
    if (typeof token.accountId !== 'string' || typeof token.clientId !== 'string') return null;
    return { sub: token.accountId, clientId: token.clientId };
  } catch {
    return null;
  }
}

/**
 * PBA-L3a-005 variant: only the desktop apps mint hand-offs. A hand-off opens
 * /kyc/start or /account AS the token's subject in whichever browser follows
 * it, so a leaked token from any other RP must not be able to produce one.
 */
export const KYC_HANDOFF_CLIENT_IDS: ReadonlySet<string> = new Set(['citrate-core', 'citrate-gui-native']);

async function readJson(req: IncomingMessage, maxBytes = 16 * 1024): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    const buf = chunk as Buffer;
    size += buf.length;
    if (size > maxBytes) throw new Error('payload too large');
    chunks.push(buf);
  }
  if (chunks.length === 0) return {};
  const parsed = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  return parsed && typeof parsed === 'object' && !Array.isArray(parsed)
    ? (parsed as Record<string, unknown>)
    : {};
}

/**
 * In-memory sliding-window limiter, keyed by subject. Prod runs a single identity
 * container, so a process-local window is effectively global; it exists to blunt a
 * leaked-token mint flood, not as a hard security boundary (the nonce's single-use
 * + subject binding is the real guard). Window and cap are generous so the two
 * legitimate buttons (KYC + Manage account) never trip it.
 */
class SubjectRateLimiter {
  private readonly hits = new Map<string, number[]>();
  constructor(
    private readonly windowMs = 60_000,
    private readonly max = 20,
  ) {}

  allow(sub: string): boolean {
    const now = Date.now();
    const cutoff = now - this.windowMs;
    const recent = (this.hits.get(sub) ?? []).filter((t) => t > cutoff);
    if (recent.length >= this.max) {
      this.hits.set(sub, recent);
      return false;
    }
    recent.push(now);
    this.hits.set(sub, recent);
    return true;
  }
}

/** Build the browser URL the app opens, carrying the freshly-minted nonce. */
function handoffUrl(target: unknown, nonce: string, body: Record<string, unknown>): string {
  const base = target === 'account' ? '/account' : '/kyc/start';
  const params = new URLSearchParams({ handoff: nonce });
  const level = body['level'];
  if (level === 'T3' || level === 'T4') params.set('level', level);
  const returnTo = body['return_to'];
  // Forwarded verbatim; the consuming route re-validates it against its origin
  // allowlist, so a bad value can only ever be rejected downstream, never honored.
  if (typeof returnTo === 'string' && returnTo) params.set('return_to', returnTo);
  return `${selfOrigin()}${base}?${params.toString()}`;
}

/**
 * Mount `POST /kyc/handoff`. Installed before panva's router (same as the other
 * custom routes), so the path is matched here and never falls through to the OIDC
 * catch-all.
 */
export function mountKycHandoffRoute(provider: Provider, store: HandoffStore): void {
  const limiter = new SubjectRateLimiter();

  provider.use(async (ctx, next) => {
    if (ctx.path !== '/kyc/handoff') return next();
    if (ctx.method !== 'POST') {
      sendJson(ctx.res, 405, { error: 'method_not_allowed', reason: 'POST only' });
      return;
    }

    const caller = await resolveToken(provider, ctx.req);
    const sub = caller?.sub;
    if (!sub) {
      sendJson(ctx.res, 401, {
        error: 'unauthorized',
        reason: 'a valid Bearer access token is required to mint a hand-off',
      });
      return;
    }

    if (!KYC_HANDOFF_CLIENT_IDS.has(caller!.clientId)) {
      sendJson(ctx.res, 403, {
        error: 'client_not_permitted',
        reason: 'only the Citrate desktop app may mint a verification hand-off',
      });
      return;
    }

    if (!limiter.allow(sub)) {
      sendJson(ctx.res, 429, {
        error: 'rate_limited',
        reason: 'too many hand-off requests; try again shortly',
      });
      return;
    }

    let body: Record<string, unknown>;
    try {
      body = await readJson(ctx.req);
    } catch {
      // A malformed/oversized body is non-fatal — a hand-off with no options is
      // valid (defaults to a T3 KYC start). Treat it as empty rather than 400.
      body = {};
    }

    const nonce = await store.issue(sub);
    sendJson(ctx.res, 200, { url: handoffUrl(body['target'], nonce, body) });
  });
}
