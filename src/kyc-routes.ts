/**
 * KYC vendor-webhook routes (IDP-KYC).
 *
 * These two routes STAND IN for the real CLEAR/Sumsub webhook (which fires when a
 * user finishes — or loses — verification). In production the vendor POSTs here
 * (or to an equivalent handler) and we persist ONLY the claim record into the KYC
 * store; the vendor keeps the PII (ADR-2026-06-03 data-controller boundary).
 *
 *   POST /kyc/_set     → upsert {status, verified_at, expires_at, vendor_ref}
 *   POST /kyc/_revoke  → mark a wallet's KYC revoked immediately
 *
 * AUTH: both are guarded by a shared secret carried in `Authorization: Bearer
 * <KYC_WEBHOOK_SECRET>` (or the `X-KYC-Webhook-Secret` header). Without the
 * secret the request is rejected 401 and the store is NOT touched. The compare is
 * constant-time. Real vendors additionally HMAC-sign the body; the bearer shared
 * secret is the minimal real guard for this internal stand-in and the HMAC path
 * slots in at the same checkpoint.
 *
 * NO PII is ever accepted: only status/dates/vendor_ref are read off the body; any
 * other field is ignored, and the type system + store keep PII out.
 */
import type { IncomingMessage, ServerResponse } from 'node:http';
import { timingSafeEqual } from 'node:crypto';
import type Provider from 'oidc-provider';
import {
  getKycStore,
  type KycClaim,
  type KycStatus,
} from './kyc.js';

export interface KycRouteOptions {
  /**
   * Shared secret the vendor webhook must present. Defaults to
   * `process.env.KYC_WEBHOOK_SECRET`. When neither is set the endpoints fail
   * CLOSED (every request is rejected) so a misconfigured deploy can't be driven
   * by an unauthenticated caller.
   */
  webhookSecret?: string;
}

async function readJson(
  req: IncomingMessage,
  maxBytes = 64 * 1024,
): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    const buf = chunk as Buffer;
    size += buf.length;
    if (size > maxBytes) throw new Error('payload too large');
    chunks.push(buf);
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

/** Constant-time string compare that never short-circuits on length. */
function secretMatches(presented: string, expected: string): boolean {
  const a = Buffer.from(presented, 'utf8');
  const b = Buffer.from(expected, 'utf8');
  if (a.length !== b.length) {
    // Still run a compare against `b` to keep timing flat for unequal lengths.
    timingSafeEqual(b, b);
    return false;
  }
  return timingSafeEqual(a, b);
}

/** Extract the presented secret from `Authorization: Bearer` or the header. */
function presentedSecret(req: IncomingMessage): string | undefined {
  const auth = req.headers['authorization'];
  if (typeof auth === 'string' && auth.startsWith('Bearer ')) {
    return auth.slice('Bearer '.length).trim();
  }
  const header = req.headers['x-kyc-webhook-secret'];
  if (typeof header === 'string' && header.length > 0) return header;
  return undefined;
}

const VALID_STATUSES: readonly KycStatus[] = ['verified', 'pending', 'revoked'];

function isKycStatus(v: unknown): v is KycStatus {
  return typeof v === 'string' && (VALID_STATUSES as readonly string[]).includes(v);
}

/**
 * Mount `/kyc/_set` and `/kyc/_revoke` on the provider's Koa app. Both reject any
 * request that does not carry the shared secret. Updates land in the live KYC
 * store, so the very next `/userinfo` reflects them.
 */
export function mountKycRoutes(
  provider: Provider,
  options: KycRouteOptions = {},
): void {
  const expectedSecret = options.webhookSecret ?? process.env.KYC_WEBHOOK_SECRET;

  provider.use(async (ctx, next) => {
    const { method, path } = ctx;
    if (
      method !== 'POST' ||
      (path !== '/kyc/_set' && path !== '/kyc/_revoke')
    ) {
      await next();
      return;
    }

    // Fail CLOSED when no secret is configured: an unguarded webhook would let
    // anyone forge KYC status. Reject rather than silently accept.
    if (!expectedSecret) {
      sendJson(ctx.res, 503, {
        error: 'kyc_webhook_unconfigured',
        reason: 'KYC_WEBHOOK_SECRET is not set; endpoint disabled',
      });
      return;
    }

    const presented = presentedSecret(ctx.req);
    if (!presented || !secretMatches(presented, expectedSecret)) {
      sendJson(ctx.res, 401, {
        error: 'unauthorized',
        reason: 'missing or invalid webhook secret',
      });
      return;
    }

    let body: Record<string, unknown>;
    try {
      body = (await readJson(ctx.req)) as Record<string, unknown>;
    } catch {
      sendJson(ctx.res, 400, { error: 'invalid_request', reason: 'bad_body' });
      return;
    }

    const address = body['address'];
    if (typeof address !== 'string' || address.length === 0) {
      sendJson(ctx.res, 400, {
        error: 'invalid_request',
        reason: 'address is required',
      });
      return;
    }

    if (path === '/kyc/_revoke') {
      getKycStore().revoke(address);
      sendJson(ctx.res, 200, { address, kyc_status: 'revoked' });
      return;
    }

    // POST /kyc/_set — build a claim record. We read ONLY the four allowed
    // fields; any extra (PII or otherwise) on the body is ignored on purpose.
    const status = body['status'];
    if (!isKycStatus(status)) {
      sendJson(ctx.res, 400, {
        error: 'invalid_request',
        reason: `status must be one of ${VALID_STATUSES.join(', ')}`,
      });
      return;
    }
    const vendor_ref = body['vendor_ref'];
    if (typeof vendor_ref !== 'string' || vendor_ref.length === 0) {
      sendJson(ctx.res, 400, {
        error: 'invalid_request',
        reason: 'vendor_ref is required',
      });
      return;
    }

    const verified_at =
      typeof body['verified_at'] === 'string'
        ? (body['verified_at'] as string)
        : undefined;
    const expires_at =
      typeof body['expires_at'] === 'string'
        ? (body['expires_at'] as string)
        : undefined;

    const claim: KycClaim = { status, vendor_ref, verified_at, expires_at };
    getKycStore().set(address, claim);
    sendJson(ctx.res, 200, { address, kyc_status: status });
  });
}
