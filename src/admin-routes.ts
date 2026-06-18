/**
 * AUTHSPINE S1-WP4 — admin entitlement API.
 *
 *   POST /admin/entitlements  { sub?|email?|wallet?, tier, citrateRole?, orgId?,
 *                               milestone?, expiresAt? }
 *
 * Service-guarded grant/raise/revoke of entitlement tiers + roles, replacing
 * hand-written SQL. Revoke = grant `public` (the roster is append-only; the
 * freshest matching row wins, and the insert is the audit record). KYC auto-grants
 * the baseline (S1-WP2); HIGHER tiers (academic / confidential) and ROLES are
 * issued only here.
 *
 * AUTH: shared secret in `Authorization: Bearer <ENTITLEMENTS_ADMIN_SECRET>` (or the
 * `X-Entitlements-Admin-Secret` header), constant-time compared. Fail-closed: 503
 * when unset, 401 on a bad secret. This is an operator endpoint, NOT user-facing.
 */
import type { IncomingMessage, ServerResponse } from 'node:http';
import { timingSafeEqual } from 'node:crypto';
import type Provider from 'oidc-provider';

import { grantEntitlement, TIERS, type EntitlementGrant } from './entitlements.js';

async function readJson(req: IncomingMessage, maxBytes = 16 * 1024): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    const b = chunk as Buffer;
    size += b.length;
    if (size > maxBytes) throw new Error('payload too large');
    chunks.push(b);
  }
  if (chunks.length === 0) return {};
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
  res.end(JSON.stringify(body));
}

function secretMatches(presented: string, expected: string): boolean {
  const a = Buffer.from(presented, 'utf8');
  const b = Buffer.from(expected, 'utf8');
  if (a.length !== b.length) {
    timingSafeEqual(b, b);
    return false;
  }
  return timingSafeEqual(a, b);
}

function presentedSecret(req: IncomingMessage): string | undefined {
  const auth = req.headers['authorization'];
  if (typeof auth === 'string' && auth.startsWith('Bearer ')) return auth.slice(7).trim();
  const h = req.headers['x-entitlements-admin-secret'];
  if (typeof h === 'string' && h.length > 0) return h;
  return undefined;
}

export interface AdminRouteOptions {
  /** Defaults to `process.env.ENTITLEMENTS_ADMIN_SECRET`. Unset → endpoint disabled (503). */
  adminSecret?: string;
}

/** Mount `POST /admin/entitlements`. */
export function mountAdminEntitlementsRoute(
  provider: Provider,
  options: AdminRouteOptions = {},
): void {
  const expected = options.adminSecret ?? process.env.ENTITLEMENTS_ADMIN_SECRET;

  provider.use(async (ctx, next) => {
    if (ctx.method !== 'POST' || ctx.path !== '/admin/entitlements') return next();

    if (!expected) {
      sendJson(ctx.res, 503, {
        error: 'admin_unconfigured',
        reason: 'ENTITLEMENTS_ADMIN_SECRET is not set; endpoint disabled',
      });
      return;
    }
    const presented = presentedSecret(ctx.req);
    if (!presented || !secretMatches(presented, expected)) {
      sendJson(ctx.res, 401, { error: 'unauthorized', reason: 'missing or invalid admin secret' });
      return;
    }

    let body: Record<string, unknown>;
    try {
      body = (await readJson(ctx.req)) as Record<string, unknown>;
    } catch {
      sendJson(ctx.res, 400, { error: 'invalid_request', reason: 'bad_body' });
      return;
    }

    const sub = typeof body.sub === 'string' && body.sub ? body.sub : null;
    const email = typeof body.email === 'string' && body.email ? body.email : null;
    const wallet = typeof body.wallet === 'string' && body.wallet ? body.wallet : null;
    if (!sub && !email && !wallet) {
      sendJson(ctx.res, 400, { error: 'invalid_request', reason: 'one of sub, email, or wallet is required' });
      return;
    }
    const tier = body.tier;
    if (typeof tier !== 'string' || !(TIERS as readonly string[]).includes(tier)) {
      sendJson(ctx.res, 400, { error: 'invalid_request', reason: `tier must be one of ${TIERS.join(', ')}` });
      return;
    }
    let expiresAt: string | null = null;
    if (body.expiresAt != null) {
      if (typeof body.expiresAt !== 'string' || Number.isNaN(Date.parse(body.expiresAt))) {
        sendJson(ctx.res, 400, { error: 'invalid_request', reason: 'expiresAt must be an ISO-8601 string' });
        return;
      }
      expiresAt = body.expiresAt;
    }

    const grant: EntitlementGrant = {
      sub, email, wallet,
      tier: tier as EntitlementGrant['tier'],
      citrateRole: typeof body.citrateRole === 'string' ? body.citrateRole : null,
      orgId: typeof body.orgId === 'string' ? body.orgId : null,
      milestone: typeof body.milestone === 'string' ? body.milestone : null,
      expiresAt,
    };
    const ok = await grantEntitlement(grant);
    if (!ok) {
      sendJson(ctx.res, 503, { error: 'no_store', reason: 'entitlements store not configured (no DATABASE_URL)' });
      return;
    }
    // eslint-disable-next-line no-console
    console.log(`[entitlements] admin grant: tier=${grant.tier} role=${grant.citrateRole ?? '-'} key=${sub ?? wallet ?? email}`);
    sendJson(ctx.res, 200, {
      ok: true,
      granted: { tier: grant.tier, citrateRole: grant.citrateRole ?? undefined, key: sub ?? wallet ?? email },
    });
  });
}
