/**
 * The KYC operator console must be reachable by a human.
 *
 * WHY. `/admin/kyc` authorises off the IdP's own session cookie and, with no
 * session, answered a JSON 403 — correct for an API client, useless for an
 * operator: no link, no redirect, no way to obtain the session it demands. The
 * console was reachable only by first signing in to some unrelated app in the
 * same browser and then knowing to navigate here. Reported 2026-08-05 as
 * "it's an endpoint, it doesn't load a page".
 *
 * These pin the two properties that make it usable without making it weaker:
 * a BROWSER gets bounced through login, and everything else still gets JSON.
 * Authorisation is unchanged — logging in proves who you are, never that you
 * may adjudicate.
 */

import { describe, expect, it } from 'vitest';

import { __testing } from '../src/admin-kyc-routes.js';

const { wantsHtml, isConsolePath, readCookie, timingSafeEqualStr } = __testing;

const reqWith = (accept: string, cookie?: string) =>
  ({ headers: { accept, ...(cookie ? { cookie } : {}) } }) as never;

describe('admin console login bounce', () => {
  describe('wantsHtml — only humans get redirected', () => {
    it('is true for a browser navigation', () => {
      expect(
        wantsHtml({
          req: reqWith('text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'),
        }),
      ).toBe(true);
    });

    it('is false for fetch/XHR default Accept', () => {
      // Redirecting a programmatic caller to an HTML login turns a clean 403
      // into a confusing 302 — the failure this guard exists to prevent.
      expect(wantsHtml({ req: reqWith('*/*') })).toBe(false);
    });

    it('is false for an explicit JSON client', () => {
      expect(wantsHtml({ req: reqWith('application/json') })).toBe(false);
    });

    it('is false when Accept is absent', () => {
      expect(wantsHtml({ req: { headers: {} } as never })).toBe(false);
    });
  });

  describe('isConsolePath — only the console page bounces', () => {
    it('matches the console, with and without a trailing slash', () => {
      expect(isConsolePath('/admin/kyc')).toBe(true);
      expect(isConsolePath('/admin/kyc/')).toBe(true);
    });

    it('does NOT match the JSON sub-resources', () => {
      // These are consumed by the console's own fetch() calls. Bouncing them
      // would replace a data response with an HTML login page mid-render.
      for (const p of [
        '/admin/kyc/cases',
        '/admin/kyc/case',
        '/admin/kyc/audit',
        '/admin/kyc/dsar',
        '/admin/kyc/adjudicate',
      ]) {
        expect(isConsolePath(p)).toBe(false);
      }
    });

    it('does not match the callback (it has its own handler)', () => {
      expect(isConsolePath('/admin/kyc/callback')).toBe(false);
    });
  });

  describe('readCookie', () => {
    it('reads one cookie out of several', () => {
      expect(readCookie('a=1; _kyc_admin_state=abc123; b=2', '_kyc_admin_state')).toBe('abc123');
    });

    it('returns undefined when absent or when there is no header', () => {
      expect(readCookie('a=1; b=2', '_kyc_admin_state')).toBeUndefined();
      expect(readCookie(undefined, '_kyc_admin_state')).toBeUndefined();
    });

    it('does not confuse a cookie whose name merely ends with the target', () => {
      expect(readCookie('x_kyc_admin_state=nope', '_kyc_admin_state')).toBeUndefined();
    });

    it('preserves a value containing "="', () => {
      expect(readCookie('_kyc_admin_state=a=b=c', '_kyc_admin_state')).toBe('a=b=c');
    });
  });

  describe('timingSafeEqualStr — the state is a CSRF token', () => {
    it('accepts an exact match', () => {
      expect(timingSafeEqualStr('abc123', 'abc123')).toBe(true);
    });

    it('rejects a mismatch and a length mismatch without throwing', () => {
      // node's timingSafeEqual THROWS on unequal lengths; a forged callback
      // must produce a clean 400, not a 500.
      expect(timingSafeEqualStr('abc123', 'abc124')).toBe(false);
      expect(timingSafeEqualStr('abc', 'abcdef')).toBe(false);
      expect(timingSafeEqualStr('', 'x')).toBe(false);
    });
  });
});
