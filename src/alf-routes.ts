/**
 * American Learning Federation enroll API.
 *
 *   POST /alf/enroll  { sub, email?, wallet? }
 *
 * The single, LEAST-PRIVILEGE grant path for the public cooperative flow on the
 * citrate-landing marketing site. Unlike `/admin/entitlements` (which can issue
 * any tier or role), this endpoint can do exactly one thing: grant the fixed
 * `{ tier: 'academic', orgId: 'alf' }` entitlement, and only to a principal whose
 * KYC is live-verified in the store right now. It re-reads KYC server-side, so the
 * landing app never decides who is verified and never holds a secret that could
 * mint `confidential` / auditor or touch a non-KYC'd account.
 *
 * AUTH: shared secret in `Authorization: Bearer <ALF_ENROLL_SECRET>` (or the
 * `X-ALF-Enroll-Secret` header), constant-time compared. Fail-closed: 503 when the
 * secret is unset, 401 on a bad secret. This is a service endpoint (landing
 * backend → authority), NOT user-facing.
 *
 * Responses:
 *   200 { granted: true, tier: 'academic', orgId: 'alf' }  — verified + granted
 *   409 { error: 'kyc_not_verified' }                      — not verified yet (retry after KYC)
 *   400 { error: 'bad_request' }                           — missing sub
 *   401 / 503                                              — auth / unconfigured
 */
import type { IncomingMessage, ServerResponse } from 'node:http';
import { timingSafeEqual } from 'node:crypto';
import type Provider from 'oidc-provider';

import { getKycStore, effectiveVerified } from './kyc.js';
import { grantEntitlement } from './entitlements.js';

const ALF_TIER = 'academic' as const;
const ALF_ORG_ID = 'alf';

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
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
  });
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
  const h = req.headers['x-alf-enroll-secret'];
  if (typeof h === 'string' && h.length > 0) return h;
  return undefined;
}

function str(v: unknown): string | undefined {
  return typeof v === 'string' && v.trim() !== '' ? v.trim() : undefined;
}

export interface AlfRouteOptions {
  /** Defaults to `process.env.ALF_ENROLL_SECRET`. Unset → endpoint disabled (503). */
  enrollSecret?: string;
}

/** Mount `POST /alf/enroll`. */
export function mountAlfEnrollRoute(
  provider: Provider,
  options: AlfRouteOptions = {},
): void {
  const expected = options.enrollSecret ?? process.env.ALF_ENROLL_SECRET;

  provider.use(async (ctx, next) => {
    if (ctx.method !== 'POST' || ctx.path !== '/alf/enroll') return next();

    if (!expected) {
      sendJson(ctx.res, 503, {
        error: 'alf_unconfigured',
        reason: 'ALF_ENROLL_SECRET is not set; endpoint disabled',
      });
      return;
    }
    const presented = presentedSecret(ctx.req);
    if (!presented || !secretMatches(presented, expected)) {
      sendJson(ctx.res, 401, { error: 'unauthorized', reason: 'missing or invalid enroll secret' });
      return;
    }

    let body: Record<string, unknown>;
    try {
      body = (await readJson(ctx.req)) as Record<string, unknown>;
    } catch {
      sendJson(ctx.res, 400, { error: 'bad_request', reason: 'invalid JSON body' });
      return;
    }

    const sub = str(body.sub);
    const email = str(body.email);
    const wallet = str(body.wallet);
    if (!sub) {
      sendJson(ctx.res, 400, { error: 'bad_request', reason: 'sub is required' });
      return;
    }

    // Re-read KYC server-side. The landing app never decides verification.
    const claim = await getKycStore().get(sub);
    if (!effectiveVerified(claim)) {
      sendJson(ctx.res, 409, {
        error: 'kyc_not_verified',
        reason: 'no live-verified KYC claim for this principal',
      });
      return;
    }

    // The one and only grant this endpoint can make.
    const granted = await grantEntitlement({
      sub,
      email: email ?? null,
      wallet: wallet ?? null,
      tier: ALF_TIER,
      orgId: ALF_ORG_ID,
    });
    if (!granted) {
      sendJson(ctx.res, 503, {
        error: 'entitlements_unconfigured',
        reason: 'no entitlement store configured',
      });
      return;
    }

    sendJson(ctx.res, 200, { granted: true, tier: ALF_TIER, orgId: ALF_ORG_ID });
  });
}
