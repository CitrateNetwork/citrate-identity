/**
 * The pages panva renders for RP-initiated logout (`GET /session/end`).
 *
 * panva always renders a confirmation page while the browser has a session,
 * and its form, if submitted without `logout=yes`, only removes the calling
 * app's authorization and leaves the auth.citrate.ai session alive. Both made
 * "Sign out" on a Citrate site a no-op for the next sign-in.
 *
 * Here:
 *   - the form always carries `logout=yes`, so confirming ends the whole
 *     browser session (every app's authorization on this browser);
 *   - when the request carries a valid `id_token_hint` (panva has already
 *     verified its signature and audience, and that any
 *     `post_logout_redirect_uri` is registered for that client) for the
 *     account this browser is signed in as, the page submits itself with a
 *     nonce'd script, so the member lands back on the site with no extra
 *     click; a `<noscript>` button covers browsers without script;
 *   - otherwise (no hint, or a hint for a different account) the member is
 *     asked to confirm, since anyone can link to /session/end;
 *   - after a logout with no post-logout URI, a branded signed-out page links
 *     back to the join page.
 */
import { randomBytes } from 'node:crypto';

/** Where a signed-out member is sent back to. */
export const JOIN_URL = 'https://www.citrate.ai/join';

/** The subset of panva's koa context these renderers read. */
interface LogoutCtx {
  body?: unknown;
  set(field: string, value: string): void;
  oidc: {
    session?: { accountId?: string };
    entities: { IdTokenHint?: { payload?: { sub?: unknown } } };
    client?: { clientId: string; clientName?: string };
  };
}

function escapeHtml(v: string): string {
  return v
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function csp(nonce?: string): string {
  return [
    "default-src 'self'",
    nonce ? `script-src 'nonce-${nonce}'` : "script-src 'none'",
    "style-src 'unsafe-inline'",
    "img-src 'self' data:",
    "frame-ancestors 'none'",
    "base-uri 'none'",
    "form-action 'self' https:",
    "object-src 'none'",
  ].join('; ');
}

const CSS = `
:root{--paper:#f1eee6;--ink:#1a1a17;--muted:#6b675e;--line:#dcd7ca;--card:#fbfaf6;--green:#8ecc09}
*{box-sizing:border-box}body{margin:0;font-family:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;background:var(--paper);color:var(--ink);line-height:1.5}
.wrap{max-width:440px;margin:0 auto;padding:48px 20px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:20px}
h1{font-size:20px;margin:0 0 8px}p{margin:0 0 16px;color:var(--muted);font-size:14px}
.btn{display:block;width:100%;text-align:center;padding:11px 14px;border-radius:8px;border:1px solid var(--green);background:var(--green);color:var(--ink);font-weight:600;font-size:14px;text-decoration:none;cursor:pointer;margin-top:8px}
.btn.secondary{background:transparent;border-color:var(--line);font-weight:500}
`;

function page(title: string, body: string, nonce?: string, script?: string): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>${escapeHtml(title)}</title><style>${CSS}</style></head><body><div class="wrap"><div class="card">
${body}
</div></div>${script && nonce ? `<script nonce="${nonce}">${script}</script>` : ''}</body></html>`;
}

/** panva's form, made to end the whole browser session rather than one app's authorization. */
export function withWholeSessionLogout(form: string): string {
  return form.replace('</form>', '<input type="hidden" name="logout" value="yes"/></form>');
}

/** True when the hint panva validated names the account this browser is signed in as. */
export function hintMatchesSession(ctx: LogoutCtx): boolean {
  const accountId = ctx.oidc.session?.accountId;
  const sub = ctx.oidc.entities.IdTokenHint?.payload?.sub;
  return typeof accountId === 'string' && accountId !== '' && sub === accountId;
}

/** `features.rpInitiatedLogout.logoutSource` */
export async function logoutSource(ctx: LogoutCtx, form: string): Promise<void> {
  const fullForm = withWholeSessionLogout(form);
  const app = ctx.oidc.client ? ctx.oidc.client.clientName || ctx.oidc.client.clientId : undefined;
  if (hintMatchesSession(ctx)) {
    const nonce = randomBytes(16).toString('base64url');
    ctx.set('content-security-policy', csp(nonce));
    ctx.body = page(
      'Signing out',
      `<h1>Signing you out&hellip;</h1>
<p>Ending your Citrate session on this browser.</p>
${fullForm}
<noscript><button class="btn" type="submit" form="op.logoutForm">Continue</button></noscript>`,
      nonce,
      "document.getElementById('op.logoutForm').submit();",
    );
    return;
  }
  ctx.set('content-security-policy', csp());
  ctx.body = page(
    'Sign out of Citrate',
    `<h1>Sign out of Citrate?</h1>
<p>${app ? `${escapeHtml(app)} asked to sign you out. ` : ''}This ends your Citrate session on this browser, for every Citrate site and app.</p>
${fullForm}
<button class="btn" type="submit" form="op.logoutForm">Sign out</button>
<a class="btn secondary" href="/account">Stay signed in</a>`,
  );
}

/** `features.rpInitiatedLogout.postLogoutSuccessSource` */
export async function postLogoutSuccessSource(ctx: LogoutCtx): Promise<void> {
  ctx.set('content-security-policy', csp());
  ctx.body = page(
    'Signed out',
    `<h1>You're signed out</h1>
<p>You have signed out of Citrate on this browser.</p>
<a class="btn" href="${JOIN_URL}">Back to Citrate</a>`,
  );
}
