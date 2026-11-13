/**
 * Request checks for the state-changing actions on auth.citrate.ai's own
 * account page (/account): add a passkey, sign out, sign out of all sessions.
 *
 *   - a token bound to THIS browser session: HMAC-SHA256 under the cookie key
 *     (COOKIE_KEYS; every configured key verifies, so rotation keeps open
 *     pages working), so a token copied from one browser fails in another;
 *   - a cross-site browser request is refused (Sec-Fetch-Site, else Origin).
 * The session cookie is also SameSite=Lax, so a cross-site POST does not carry
 * it in the first place; these checks hold even where that does not apply.
 */
import { createHmac, timingSafeEqual } from 'node:crypto';
import type { IncomingMessage } from 'node:http';
import { cookieKeys } from './config.js';

function token(key: string, sessionId: string): string {
  return createHmac('sha256', key).update(`account-action:${sessionId}`).digest('base64url');
}

/** Token for this browser session, signed with the current cookie key. */
export function accountActionToken(sessionId: string): string {
  return token(cookieKeys()[0]!, sessionId);
}

/** True when `presented` is this session's token under any configured key. */
export function isValidAccountActionToken(sessionId: string, presented: unknown): boolean {
  if (typeof presented !== 'string' || presented.length === 0) return false;
  const got = Buffer.from(presented);
  return cookieKeys().some((key) => {
    const want = Buffer.from(token(key, sessionId));
    return want.length === got.length && timingSafeEqual(want, got);
  });
}

/** A browser request from another site. Non-browser clients send neither header. */
export function isCrossSite(req: IncomingMessage, issuerOrigin: string): boolean {
  const one = (v: string | string[] | undefined) => (Array.isArray(v) ? v[0] : v);
  const site = one(req.headers['sec-fetch-site']);
  if (site !== undefined) return site !== 'same-origin' && site !== 'none';
  const origin = one(req.headers['origin']);
  if (origin !== undefined) return origin !== issuerOrigin;
  return false;
}
