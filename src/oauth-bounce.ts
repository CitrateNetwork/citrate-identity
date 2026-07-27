/**
 * Hosted OAuth redirect bounce for Citrate Core (desktop) MCP connections.
 *
 * WHY THIS EXISTS
 * ---------------
 * Citrate Core signs a member in to Google Drive / Notion / GitHub as MCP tools
 * using the RFC-8252 "OAuth for native apps" flow: a loopback listener the app
 * runs on `http://127.0.0.1:8975/oauth/callback` for the duration of one sign-in,
 * with PKCE (S256) + a `state` CSRF check. Google's and GitHub's "Desktop app"
 * client types accept that `http://` loopback redirect directly.
 *
 * Notion (and any provider that rejects a plaintext-`http` loopback redirect and
 * demands an `https://` URL) cannot point straight at the loopback. This endpoint
 * is the documented fallback (OAUTH_SETUP_RUNBOOK.md / ADR-3): the member registers
 *
 *     https://auth.citrate.ai/oauth/callback
 *
 * as the provider redirect URI; the provider sends the browser here with the
 * authorization `code` (+ `state`), and we 302 the browser straight back to the
 * app's loopback listener, carrying the query through unchanged.
 *
 * WHAT THIS IS NOT
 * ----------------
 * This is a pure, STATELESS browser bounce. The authority:
 *   - never sees or holds a provider client secret,
 *   - never performs the token exchange (the app does that directly, PKCE-bound),
 *   - keeps no per-flow state — the `state` CSRF value and the PKCE `code_verifier`
 *     live only in the desktop app and are validated there.
 * So the "secret never leaves the app" beta posture is preserved, and this same
 * URL is forward-compatible with the ADR-3 public-release model (a real
 * backend token-exchange proxy) — that swap does not change the redirect URI.
 *
 * SECURITY
 * --------
 * - CLOSED redirect. The Location host/port/path is a hardcoded constant; only the
 *   query string is forwarded. The incoming request cannot steer the browser
 *   anywhere but the fixed loopback — there is no `redirect_uri`-style passthrough,
 *   so this is not an open redirect.
 * - Query is RE-PARSED and RE-ENCODED via URLSearchParams before being reattached,
 *   which normalises every value and strips any CR/LF, neutralising header/response
 *   injection regardless of Node's own header validation.
 * - GET only; no body is read; `Cache-Control: no-store` so an authorization code
 *   is never cached by an intermediary.
 */
import type Provider from 'oidc-provider';

/**
 * The one loopback callback Citrate Core binds (RFC-8252). Fixed host/port/path —
 * MUST match `OAUTH_REDIRECT_URI` / `OAUTH_LOOPBACK_PORT` in citrate-core
 * (`src-tauri/src/connections.rs`). This is the ONLY place this endpoint will ever
 * send the browser; the query is appended, the target itself is constant.
 */
export const CORE_LOOPBACK_CALLBACK = 'http://127.0.0.1:8975/oauth/callback';

/** The public path providers redirect to (registered as the https redirect URI). */
export const HOSTED_BOUNCE_PATH = '/oauth/callback';

/**
 * Build the loopback URL the browser is bounced to. The incoming query string is
 * re-parsed and re-serialised so every value is percent-encoded and free of CR/LF
 * — the target host/port/path never come from the request.
 */
export function buildLoopbackRedirect(rawQuerystring: string): string {
  const target = new URL(CORE_LOOPBACK_CALLBACK);
  // URLSearchParams round-trip: normalises encoding + drops control chars. An
  // empty query yields an empty search, so we never append a bare "?".
  const params = new URLSearchParams(rawQuerystring);
  const search = params.toString();
  target.search = search;
  return target.toString();
}

/**
 * Minimal no-JS fallback page. A 302 with a `Location` header is what actually
 * moves the browser; this body is only rendered in the rare case a client does
 * not auto-follow the redirect (e.g. a top-level https→http-loopback navigation a
 * hardened browser surfaces for confirmation). The meta-refresh and the manual
 * link both point at the same fixed loopback URL. No external resources.
 */
function fallbackHtml(loopbackUrl: string): string {
  // loopbackUrl is our own constructed, encoded URL; still HTML-escape the few
  // characters that matter inside an attribute/text context, belt-and-suspenders.
  const esc = loopbackUrl
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="refresh" content="0;url=${esc}">
<title>Returning to Citrate Core…</title>
</head>
<body style="font-family:system-ui,-apple-system,sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem;color:#111">
<h1 style="font-size:1.1rem">Returning to Citrate Core…</h1>
<p>You can close this tab once the app takes over. If it doesn't,
<a href="${esc}">click here to finish signing in</a>.</p>
</body>
</html>`;
}

/**
 * Mount the hosted redirect bounce. Handles `GET /oauth/callback` and short-circuits
 * before panva's OIDC router (that path is not an OIDC-provider route, so there is
 * no collision). Every other request falls through untouched.
 *
 * Install this alongside the other pre-router extras (near {@link mountHttpExtras}).
 */
export function mountOAuthBounce(provider: Provider): void {
  provider.use(async (ctx, next) => {
    if (ctx.method !== 'GET' || ctx.path !== HOSTED_BOUNCE_PATH) {
      await next();
      return;
    }

    const loopbackUrl = buildLoopbackRedirect(ctx.querystring);
    ctx.status = 302;
    ctx.set('location', loopbackUrl);
    ctx.set('cache-control', 'no-store');
    ctx.set('referrer-policy', 'no-referrer');
    ctx.type = 'html';
    ctx.body = fallbackHtml(loopbackUrl);
    // handled — do not fall through to panva.
  });
}
