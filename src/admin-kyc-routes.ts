/**
 * VERI admin/compliance routes (VERI-S4) — a THIN wrapper over `admin-kyc-actions`.
 *
 * Every route is gated by the **session-subject allowlist** `KYC_ADMIN_SUBS` (same
 * pattern as `BUNDLER_KEY_ADMIN_SUBS`): the caller's live OIDC session `accountId`
 * must be in the list, else 403. MFA for admin sessions is a login-policy control
 * (NIST 800-171 3.5). Active only when `KYC_PROVIDER=inhouse`.
 *
 * Routes (all under /admin/kyc):
 *   GET  /cases?status=            list case metadata (no ciphertext)
 *   GET  /case?caseId=             one case's metadata + evidence metadata (audited)
 *   POST /adjudicate               {caseId, decision, reason} approve/reject a review
 *   POST /unlock/request           {caseId, reason} dual-control step 1
 *   POST /unlock/approve           {unlockId} dual-control step 2 → decrypt once
 *   POST /delete                   {sub} delete/tombstone a user (D3)
 *   POST /dsar/request             {sub, reason} DSAR dual-control step 1 (PBA-L3a-006)
 *   POST /dsar/approve             {requestId} step 2 by a DIFFERENT admin → export once
 *   GET  /audit?caseId=            audit log + chain-verification status
 */

import type Provider from 'oidc-provider';
import type { IncomingMessage, ServerResponse } from 'node:http';

import { getKycProvider } from './kyc-providers/index.js';
import { InhouseKycProvider } from './kyc-providers/inhouse.js';
import { renderAdminKycUI } from './admin-kyc-ui.js';
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { DEV_DEFAULT_COOKIE_KEY, ISSUER_URL } from './config.js';
import { getKycAuditLog } from './kyc-audit-pg.js';
import { parseAdminSubs } from './aa/bundler-keys.js';
import type { CaseStatus } from './kyc-cases-pg.js';
import {
  adjudicateCase,
  approveUnlock,
  approveDsar,
  deleteUser,
  listCases,
  requestDsar,
  requestUnlock,
} from './admin-kyc-actions.js';

/**
 * PBA-L3a-001: every state-changing admin route. Each one sits behind the CSRF
 * guard below (same-origin Origin + Sec-Fetch-Site, `application/json`, the
 * SameSite=Strict `_kyc_admin` cookie and the session-bound `x-csrf-token`).
 * The regression test scans this file and fails if a POST path is added here
 * without being listed (and therefore exercised).
 */
export const ADMIN_STATE_CHANGING_ROUTES: readonly string[] = [
  '/admin/kyc/adjudicate',
  '/admin/kyc/unlock/request',
  '/admin/kyc/unlock/approve',
  '/admin/kyc/delete',
  '/admin/kyc/dsar/request',
  '/admin/kyc/dsar/approve',
];

/** Read-only JSON routes: same-origin only and the strict admin cookie required. */
export const ADMIN_READ_ROUTES: readonly string[] = [
  '/admin/kyc/cases',
  '/admin/kyc/case',
  '/admin/kyc/audit',
];

/** SameSite=Strict, console-scoped cookie proving the request came from the console. */
const ADMIN_COOKIE = '_kyc_admin';
const ADMIN_COOKIE_MAX_AGE_SEC = 8 * 60 * 60;

/**
 * HMAC key for the admin cookie + CSRF token. It is the ACTIVE cookie-signing key
 * (COOKIE_KEYS[0]), which production already requires to be a ≥32-char secret
 * shared by every instance, so tokens verify on whichever instance serves the POST.
 */
function adminBindingKey(): string {
  const first = (process.env.COOKIE_KEYS ?? '')
    .split(',')
    .map((k) => k.trim())
    .find((k) => k.length > 0);
  return first ?? DEV_DEFAULT_COOKIE_KEY;
}

/** Session-bound value: HMAC(key, label || session uid). Distinct labels → distinct values. */
function adminBinding(label: 'cookie' | 'csrf', sessionKey: string): string {
  return createHmac('sha256', adminBindingKey()).update(`kyc-admin-${label}:${sessionKey}`).digest('base64url');
}

function header(req: IncomingMessage, name: string): string | undefined {
  const v = req.headers[name];
  const s = Array.isArray(v) ? v[0] : v;
  return typeof s === 'string' && s.length > 0 ? s : undefined;
}

/**
 * Same-origin check for admin API calls. A browser always labels a fetch with
 * Sec-Fetch-Site; anything but `same-origin` (cross-site, or a same-SITE sibling
 * such as explorer.citrate.ai) is refused. When Origin is present it must be the
 * issuer's own origin; `requireOrigin` (POSTs) refuses an absent one too.
 */
function isSameOrigin(req: IncomingMessage, issuerOrigin: string, requireOrigin: boolean): boolean {
  const site = header(req, 'sec-fetch-site');
  if (site !== undefined && site !== 'same-origin') return false;
  const origin = header(req, 'origin');
  if (origin === undefined) return !requireOrigin;
  return origin === issuerOrigin;
}

function isJsonContentType(req: IncomingMessage): boolean {
  const ct = header(req, 'content-type');
  if (!ct) return false;
  return ct.split(';')[0]!.trim().toLowerCase() === 'application/json';
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
  res.end(JSON.stringify(body));
}
async function readJson(req: IncomingMessage): Promise<Record<string, unknown> | null> {
  const chunks: Buffer[] = [];
  let total = 0;
  return new Promise((resolve) => {
    req.on('data', (c: Buffer) => {
      total += c.length;
      if (total > 1_000_000) { req.destroy(); resolve(null); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      if (!chunks.length) return resolve(null);
      try {
        const p = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        resolve(p && typeof p === 'object' ? (p as Record<string, unknown>) : null);
      } catch { resolve(null); }
    });
    req.on('error', () => resolve(null));
  });
}
const str = (v: unknown): string | undefined => (typeof v === 'string' && v.length > 0 ? v : undefined);

/** POST a signed decision to the local /kyc/webhook — the unchanged entitlement path. */
async function deliverDecision(signed: { body: Buffer; headers: Record<string, string> }): Promise<boolean> {
  const issuer = (process.env.ISSUER_URL ?? 'http://localhost:3000').replace(/\/+$/, '');
  try {
    const r = await fetch(`${issuer}/kyc/webhook`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...signed.headers },
      body: signed.body,
    });
    return r.ok;
  } catch {
    return false;
  }
}

export function mountAdminKycRoutes(provider: Provider): void {
  // R-2: warn loudly at boot if dual-control can't function (subpoena unlock is disabled).
  if (parseAdminSubs(process.env.KYC_ADMIN_SUBS).length < 2) {
    // eslint-disable-next-line no-console
    console.warn(
      '[kyc] DUAL-CONTROL DEGRADED — fewer than 2 admins in KYC_ADMIN_SUBS. The subpoena/' +
        'dispute unlock (two-person rule) is DISABLED until ≥2 distinct admins are provisioned.',
    );
  }
  provider.use(async (ctx, next) => {
    if (!ctx.path.startsWith('/admin/kyc')) return next();
    const p = getKycProvider();
    const ih = p instanceof InhouseKycProvider ? p : null;
    const audit = getKycAuditLog();
    if (!ih || !audit) return next(); // in-house KYC not configured → 404 downstream

    // --- admin auth: live session subject ∈ KYC_ADMIN_SUBS ---
    let accountId: string | undefined;
    try {
      accountId = (await provider.Session.get(ctx))?.accountId;
    } catch {
      accountId = undefined;
    }
    const admins = parseAdminSubs(process.env.KYC_ADMIN_SUBS);

    // --- login bounce: give an unauthenticated BROWSER a way in ------------
    //
    // The guard below authorises off the IdP's own session cookie. Without one
    // this route used to answer a JSON 403 — correct for an API client, useless
    // for a human: there was no link, no redirect, no way to obtain the session
    // it demands. The console was reachable only by first signing in to some
    // unrelated app in the same browser and then knowing to navigate here.
    //
    // So: a browser (Accept: text/html) with NO session is sent through a normal
    // authorization flow and lands back here with one. Anything else — an API
    // client, XHR, curl — still gets the JSON 403, because redirecting a
    // programmatic caller to an HTML login is its own kind of broken.
    //
    // This only ever establishes IDENTITY. Authorisation stays the
    // KYC_ADMIN_SUBS allowlist below, so a successful login by a non-admin still
    // ends in 403 — now an honest one, naming the signed-in subject.
    if (!accountId && ctx.method === 'GET' && wantsHtml(ctx) && isConsolePath(ctx.path)) {
      const state = randomBytes(32).toString('base64url');
      // Bind the state to THIS browser: the callback accepts it only if the
      // cookie matches, so a stray/forged callback cannot drive a redirect.
      // Host-only, SameSite=Lax (the IdP redirect is a top-level GET), and
      // scoped to the console path so it is not sent anywhere else.
      ctx.res.setHeader('set-cookie', [
        `_kyc_admin_state=${state}; Path=/admin/kyc; HttpOnly; Secure; SameSite=Lax; Max-Age=600`,
      ]);
      const authorize = new URL('/auth', ISSUER_URL);
      authorize.searchParams.set('client_id', 'kyc-admin-console');
      authorize.searchParams.set('response_type', 'code');
      authorize.searchParams.set('scope', 'openid');
      authorize.searchParams.set('redirect_uri', `${ISSUER_URL}/admin/kyc/callback`);
      authorize.searchParams.set('state', state);
      ctx.res.writeHead(302, { location: authorize.toString(), 'cache-control': 'no-store' });
      ctx.res.end();
      return;
    }

    // The landing leg. By the time the IdP redirects here the session cookie is
    // already set, so there is nothing to exchange — the authorization code is
    // deliberately ignored and left to expire. The console reads the SESSION,
    // never this client's tokens, so minting them would create a credential with
    // no consumer. Just verify the state and hand the browser back to the guard.
    if (ctx.method === 'GET' && ctx.path === '/admin/kyc/callback') {
      const expected = readCookie(ctx.req.headers.cookie, '_kyc_admin_state');
      const got = str(ctx.query['state']);
      const ok = !!expected && !!got && timingSafeEqualStr(expected, got);
      // Clear the one-shot state either way.
      ctx.res.setHeader('set-cookie', [
        '_kyc_admin_state=; Path=/admin/kyc; HttpOnly; Secure; SameSite=Lax; Max-Age=0',
      ]);
      if (!ok) {
        sendJson(ctx.res, 400, { error: 'invalid_state' });
        return;
      }
      ctx.res.writeHead(302, { location: '/admin/kyc', 'cache-control': 'no-store' });
      ctx.res.end();
      return;
    }

    if (!accountId || !admins.includes(accountId)) {
      sendJson(ctx.res, 403, {
        error: 'forbidden',
        reason: accountId
          ? 'signed in, but this subject is not in KYC_ADMIN_SUBS'
          : 'admin session required (KYC_ADMIN_SUBS)',
        ...(accountId ? { sub: accountId } : {}),
      });
      return;
    }
    const actor = accountId;

    // --- PBA-L3a-001: CSRF / cross-origin guard -----------------------------
    // Session key: the panva session's stable uid. The console cookie and the
    // CSRF token are both HMACs of it, so neither can be forged cross-site nor
    // replayed into another admin's session.
    let sessionKey: string | undefined;
    try {
      sessionKey = ((await provider.Session.get(ctx)) as { uid?: string } | undefined)?.uid;
    } catch {
      sessionKey = undefined;
    }
    if (!sessionKey) return sendJson(ctx.res, 403, { error: 'csrf_rejected', reason: 'no admin session' });
    const issuerOrigin = new URL(provider.issuer).origin;
    const isConsole = ctx.method === 'GET' && isConsolePath(ctx.path);
    if (!isConsole) {
      const csrfReject = (reason: string) => sendJson(ctx.res, 403, { error: 'csrf_rejected', reason });
      const isPost = ctx.method === 'POST';
      if (!isSameOrigin(ctx.req, issuerOrigin, isPost)) return csrfReject('admin routes are same-origin only');
      const cookie = readCookie(ctx.req.headers.cookie, ADMIN_COOKIE);
      if (!cookie || !timingSafeEqualStr(cookie, adminBinding('cookie', sessionKey))) {
        return csrfReject('open the admin console first (strict admin cookie missing)');
      }
      if (ctx.method !== 'GET') {
        if (!isJsonContentType(ctx.req)) return csrfReject('content-type must be application/json');
        const token = header(ctx.req, 'x-csrf-token');
        if (!token || !timingSafeEqualStr(token, adminBinding('csrf', sessionKey))) {
          return csrfReject('missing or invalid x-csrf-token');
        }
      }
    }

    const store = ih.caseStore;
    const getDek = (id: string) => ih.getCaseDek(id);
    const webhookSecret = process.env.KYC_INHOUSE_WEBHOOK_SECRET ?? '';

    // --- GET routes ---
    if (ctx.method === 'GET' && (ctx.path === '/admin/kyc' || ctx.path === '/admin/kyc/')) {
      ctx.res.writeHead(200, {
        'content-type': 'text/html; charset=utf-8',
        'cache-control': 'no-store',
        // Host-only, console-scoped, never sent on a cross-site request.
        'set-cookie': [
          `${ADMIN_COOKIE}=${adminBinding('cookie', sessionKey)}; Path=/admin/kyc; HttpOnly; Secure; SameSite=Strict; Max-Age=${ADMIN_COOKIE_MAX_AGE_SEC}`,
        ],
      });
      ctx.res.end(renderAdminKycUI(adminBinding('csrf', sessionKey)));
      return;
    }
    if (ctx.method === 'GET' && ctx.path === '/admin/kyc/cases') {
      const status = str(ctx.query['status']) as CaseStatus | undefined;
      return sendJson(ctx.res, 200, { cases: await listCases(store, status) });
    }
    if (ctx.method === 'GET' && ctx.path === '/admin/kyc/case') {
      const caseId = str(ctx.query['caseId']);
      if (!caseId) return sendJson(ctx.res, 400, { error: 'caseId_required' });
      const c = await store.getCase(caseId);
      if (!c) return sendJson(ctx.res, 404, { error: 'case_not_found' });
      await audit.record({ actor, action: 'case.view', caseId });
      const evidence = (await store.listEvidence(caseId)).map((e) => ({ kind: e.kind, tier: e.tier, present: !!e.ciphertext, destroyedAt: e.destroyedAt }));
      return sendJson(ctx.res, 200, {
        case: { caseId: c.caseId, externalUserId: c.externalUserId, status: c.status, decision: c.decision, screeningResult: c.screeningResult, legalHold: c.legalHold, verifiedAt: c.verifiedAt, expiresAt: c.expiresAt, retentionUntil: c.retentionUntil },
        evidence,
      });
    }
    if (ctx.method === 'GET' && ctx.path === '/admin/kyc/audit') {
      const caseId = str(ctx.query['caseId']);
      const [entries, chain] = await Promise.all([audit.list({ caseId }), audit.verifyChain()]);
      return sendJson(ctx.res, 200, { entries, chain });
    }

    // --- POST routes ---
    if (ctx.method === 'POST') {
      const body = await readJson(ctx.req);
      if (!body) return sendJson(ctx.res, 400, { error: 'invalid_body' });

      if (ctx.path === '/admin/kyc/adjudicate') {
        const caseId = str(body['caseId']);
        const decision = str(body['decision']);
        const reason = str(body['reason']) ?? '';
        if (!caseId || (decision !== 'verified' && decision !== 'rejected')) {
          return sendJson(ctx.res, 400, { error: 'caseId + decision(verified|rejected) required' });
        }
        const r = await adjudicateCase(store, audit, { actor, caseId, decision, reason, webhookSecret });
        if (r.ok) {
          // Deliver the decision to the unchanged /kyc/webhook entitlement path (D1)
          // so a `verified` adjudication mints the baseline entitlement claim.
          const granted = await deliverDecision(r.signedWebhook);
          return sendJson(ctx.res, 200, { ok: true, decision, entitlementDelivered: granted });
        }
        return sendJson(ctx.res, 400, r);
      }
      if (
        ctx.path === '/admin/kyc/unlock/request' ||
        ctx.path === '/admin/kyc/unlock/approve' ||
        ctx.path === '/admin/kyc/dsar/request' ||
        ctx.path === '/admin/kyc/dsar/approve'
      ) {
        // R-2: dual-control requires ≥2 DISTINCT admins provisioned, else approver≠requester
        // can never be satisfied. Fail CLOSED rather than silently non-functional.
        if (admins.length < 2) {
          return sendJson(ctx.res, 409, {
            error: 'dual_control_unavailable',
            reason: 'Subpoena/dispute unlock and DSAR export require ≥2 distinct admins in KYC_ADMIN_SUBS (two-person rule). Provision a second admin first.',
          });
        }
      }
      if (ctx.path === '/admin/kyc/unlock/request') {
        const caseId = str(body['caseId']);
        const reason = str(body['reason']);
        if (!caseId || !reason) return sendJson(ctx.res, 400, { error: 'caseId + reason required' });
        return sendJson(ctx.res, 200, await requestUnlock(store, audit, { actor, caseId, reason }));
      }
      if (ctx.path === '/admin/kyc/unlock/approve') {
        const unlockId = str(body['unlockId']);
        if (!unlockId) return sendJson(ctx.res, 400, { error: 'unlockId_required' });
        const r = await approveUnlock(store, audit, { approver: actor, unlockId, getDek });
        return sendJson(ctx.res, r.ok ? 200 : 400, r);
      }
      if (ctx.path === '/admin/kyc/dsar/request') {
        const sub = str(body['sub']);
        const reason = str(body['reason']);
        if (!sub || !reason) return sendJson(ctx.res, 400, { error: 'sub + reason required' });
        return sendJson(ctx.res, 200, await requestDsar(store, audit, { actor, sub, reason }));
      }
      if (ctx.path === '/admin/kyc/dsar/approve') {
        const requestId = str(body['requestId']);
        if (!requestId) return sendJson(ctx.res, 400, { error: 'requestId_required' });
        const r = await approveDsar(store, audit, { approver: actor, requestId, getDek });
        return sendJson(ctx.res, r.ok ? 200 : 400, r);
      }
      if (ctx.path === '/admin/kyc/delete') {
        const sub = str(body['sub']);
        if (!sub) return sendJson(ctx.res, 400, { error: 'sub_required' });
        return sendJson(ctx.res, 200, await deleteUser(store, audit, { actor, sub }));
      }
    }

    return next();
  });
}

// ── login-bounce helpers ────────────────────────────────────────────────────

/** Only the console's own GET surfaces get bounced; sub-resources stay JSON. */
function isConsolePath(path: string): boolean {
  return path === '/admin/kyc' || path === '/admin/kyc/';
}

/**
 * A human's browser, not a programmatic caller.
 *
 * Redirecting an API client to an HTML login turns a clean 403 into a confusing
 * 302, so the bounce is gated on the caller actually asking for HTML. `fetch`
 * and XHR send a wildcard Accept, which does not contain `text/html`, so a
 * programmatic caller keeps getting the JSON 403.
 */
function wantsHtml(ctx: { req: IncomingMessage }): boolean {
  const accept = String(ctx.req.headers['accept'] ?? '');
  return accept.includes('text/html');
}

/** Read one cookie by name from a Cookie header. */
function readCookie(header: string | undefined, name: string): string | undefined {
  if (!header) return undefined;
  for (const part of header.split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === name) return v.join('=');
  }
  return undefined;
}

/** Constant-time string compare — the state is a CSRF token, so leak no timing. */
function timingSafeEqualStr(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}


/**
 * Test-only surface for the login-bounce helpers.
 *
 * The bounce itself lives inside `provider.use`, which needs a full
 * oidc-provider to exercise. These are the decision points that carry the
 * security properties — who gets redirected, which paths bounce, and the
 * constant-time state compare — so they are exported for direct testing rather
 * than left implicitly covered.
 */
export const __testing = {
  adminBinding,
  isSameOrigin,
  isJsonContentType,
  wantsHtml,
  isConsolePath,
  readCookie,
  timingSafeEqualStr,
};
