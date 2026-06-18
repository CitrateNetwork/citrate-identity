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
import { getKycProvider } from './kyc-providers/index.js';
import { KYC_LEVELS, type KycLevel } from './kyc-providers/level-hints.js';

export interface KycRouteOptions {
  /**
   * Shared secret the vendor webhook must present. Defaults to
   * `process.env.KYC_WEBHOOK_SECRET`. When neither is set the endpoints fail
   * CLOSED (every request is rejected) so a misconfigured deploy can't be driven
   * by an unauthenticated caller.
   */
  webhookSecret?: string;
}

/** Options for {@link mountKycStartRoute}. */
export interface KycStartRouteOptions {
  /**
   * Active vendor name — drives the SDK URL pattern when the provider's
   * `mintClientSession` doesn't return a hosted `redirectUrl` (Sumsub).
   * Defaults to `process.env.KYC_PROVIDER`. For `clear` the provider's
   * own `redirectUrl` is preferred; for `mock` a deterministic
   * `kyc-mock.invalid` URL is built; for `sumsub` the Sumsub idensic
   * URL is built from the token.
   */
  vendor?: string;
  /** TTL the WebSDK token is requested with (seconds). Default 600. */
  ttlSec?: number;
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
      await getKycStore().revoke(address);
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
    await getKycStore().set(address, claim);
    sendJson(ctx.res, 200, { address, kyc_status: status });
  });
}

/** Read the raw request body as a Buffer (HMAC needs the exact bytes). */
async function readRaw(
  req: IncomingMessage,
  maxBytes = 256 * 1024,
): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    const buf = chunk as Buffer;
    size += buf.length;
    if (size > maxBytes) throw new Error('payload too large');
    chunks.push(buf);
  }
  return Buffer.concat(chunks);
}

/** Lower-case every header name so adapters can read them case-insensitively. */
function lowerHeaders(req: IncomingMessage): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(req.headers)) {
    if (typeof v === 'string') out[k.toLowerCase()] = v;
    else if (Array.isArray(v)) out[k.toLowerCase()] = v.join(',');
  }
  return out;
}

/** Options for {@link mountKycWebhookRoute}. */
export interface KycWebhookRouteOptions {
  /** Verified-claim validity. Default 365 days; override via KYC_VERIFIED_TTL_MS. */
  verifiedTtlMs?: number;
}

/**
 * Mount `POST /kyc/webhook` — the REAL vendor webhook (Sumsub/CLEAR), as opposed
 * to the `/kyc/_set` bearer stand-in. The active {@link KycProvider} verifies the
 * vendor's signature over the RAW body (Sumsub: HMAC in `x-payload-digest`, keyed
 * by `SUMSUB_WEBHOOK_SECRET`), then `parseWebhookEvent` decodes it to the
 * vendor-neutral four-state {@link KycEventKind}. We persist ONLY the closed
 * {@link KycClaim} (no PII, ADR-2026-06-03), keyed on `externalUserId` — which IS
 * the OIDC accountId we handed Sumsub at `/kyc/start`, so `/userinfo` reflects it.
 *
 * Fails CLOSED: 503 when no provider is configured, 401 on a bad/missing
 * signature. Acks 2xx for events it can't key/act on so the vendor stops retrying.
 */
export function mountKycWebhookRoute(
  provider: Provider,
  options: KycWebhookRouteOptions = {},
): void {
  const verifiedTtlMs =
    options.verifiedTtlMs ??
    (Number(process.env.KYC_VERIFIED_TTL_MS) || 365 * 24 * 60 * 60 * 1000);

  provider.use(async (ctx, next) => {
    if (ctx.method !== 'POST' || ctx.path !== '/kyc/webhook') return next();

    const kycProvider = getKycProvider();
    if (!kycProvider) {
      sendJson(ctx.res, 503, {
        error: 'kyc_unconfigured',
        reason: 'KYC_PROVIDER is not set; webhook disabled',
      });
      return;
    }

    let raw: Buffer;
    try {
      raw = await readRaw(ctx.req);
    } catch {
      sendJson(ctx.res, 400, { error: 'invalid_request', reason: 'bad_body' });
      return;
    }

    // Authenticity FIRST: an unverified body is never parsed for effect.
    if (!kycProvider.verifyWebhook(lowerHeaders(ctx.req), raw)) {
      sendJson(ctx.res, 401, {
        error: 'unauthorized',
        reason: 'invalid or missing webhook signature',
      });
      return;
    }

    let event;
    try {
      event = await kycProvider.parseWebhookEvent(raw);
    } catch {
      sendJson(ctx.res, 400, { error: 'invalid_request', reason: 'unparseable_event' });
      return;
    }

    // externalUserId IS our OIDC accountId (set at /kyc/start). Without it we
    // can't key the claim — ack so the vendor stops retrying, but change nothing.
    const key = event.externalUserId;
    if (!key) {
      sendJson(ctx.res, 202, { ok: true, ignored: 'no externalUserId on event' });
      return;
    }

    const occurred = event.occurredAt ?? Date.now();
    const iso = (ms: number) => new Date(ms).toISOString();
    switch (event.kind) {
      case 'verified':
        await getKycStore().set(key, {
          status: 'verified',
          vendor_ref: event.applicantId,
          verified_at: iso(occurred),
          expires_at: iso(occurred + verifiedTtlMs),
        });
        break;
      case 'pending':
        await getKycStore().set(key, {
          status: 'pending',
          vendor_ref: event.applicantId,
        });
        break;
      case 'rejected':
      case 'reset':
        // Both leave the subject NOT verified; record as revoked (fail-closed),
        // preserving the vendor ref for audit.
        await getKycStore().set(key, {
          status: 'revoked',
          vendor_ref: event.applicantId,
        });
        break;
    }
    sendJson(ctx.res, 200, { ok: true, kind: event.kind });
  });
}

/**
 * Map the user-facing tier query (`?level=T3` / `?level=T4`) to the
 * vendor-neutral `levelHint` the {@link KycProvider} interface speaks.
 * Returns undefined for an unrecognised string so the caller can 400.
 */
function tierToKycLevel(tier: string | undefined): KycLevel | undefined {
  switch ((tier ?? 'T3').toUpperCase()) {
    case 'T3':
      return KYC_LEVELS.BASIC_INDIVIDUAL;
    case 'T4':
      return KYC_LEVELS.KYB_ENTITY;
    default:
      return undefined;
  }
}

/**
 * Build the URL the user-agent gets 303'd to after `mintClientSession`.
 * The provider may return its own hosted URL (CLEAR style); when it
 * doesn't (Sumsub, Mock), we construct one from the token. URL
 * construction is the route's responsibility so the provider interface
 * stays focused on credentials.
 */
function buildKycRedirectUrl(args: {
  vendor: string;
  token: string;
  applicantId: string;
  hostedRedirectUrl?: string;
}): string {
  if (args.hostedRedirectUrl) return args.hostedRedirectUrl;
  switch (args.vendor) {
    case 'sumsub':
      return `https://api.sumsub.com/idensic/l/#/?accessToken=${encodeURIComponent(args.token)}`;
    case 'mock':
      return (
        `https://kyc-mock.invalid/sdk?token=${encodeURIComponent(args.token)}` +
        `&applicantId=${encodeURIComponent(args.applicantId)}`
      );
    default:
      throw new Error(`buildKycRedirectUrl: no URL pattern for vendor "${args.vendor}"`);
  }
}

/**
 * Process-local cache of `accountId → applicantId`. The vendor side is
 * already idempotent on `externalUserId` (Sumsub returns the existing
 * applicantId; Mock does too), but caching here avoids the round-trip
 * when a user clicks "Verify identity" repeatedly. Mirrors the
 * webauthn challenge store's posture: process-local Map is sufficient
 * for the single-instance authority; multi-instance moves to Redis when
 * we move sessions there.
 */
class ApplicantCache {
  private readonly byAccountId = new Map<string, string>();
  get(accountId: string): string | undefined {
    return this.byAccountId.get(accountId);
  }
  set(accountId: string, applicantId: string): void {
    this.byAccountId.set(accountId, applicantId);
  }
}

/**
 * Mount `GET /kyc/start` — the user-facing identity-verification kickoff
 * endpoint (WP-C of the portal registration ladder).
 *
 * Contract:
 *   - Requires an active OIDC interaction (`provider.interactionDetails`)
 *     whose session carries an `accountId`. Without an interaction → 400.
 *     With an interaction but no accountId → 401 "sign in first".
 *   - Reads `?level=T3` (default) or `?level=T4`. T3 → BASIC_INDIVIDUAL;
 *     T4 → KYB_ENTITY. Other values → 400.
 *   - Calls `getKycProvider().createApplicant({externalUserId, levelHint})`
 *     (cached per session — see {@link ApplicantCache}), then
 *     `mintClientSession`, then 303s the browser to a vendor-shaped URL
 *     built from the token.
 *   - 503 if `KYC_PROVIDER` is unset (no provider installed); 501 if the
 *     adapter rejects the level (e.g. Sumsub's KYB-not-yet-configured).
 *
 * Per ADR-2026-06-03 data-controller boundary: this route only
 * brokers — it never sees PII. The user uploads documents directly to
 * the vendor; the verdict comes back over the webhook to `/kyc/_set`.
 */
export function mountKycStartRoute(
  provider: Provider,
  options: KycStartRouteOptions = {},
): void {
  const vendor = options.vendor ?? process.env.KYC_PROVIDER;
  const ttlSec = options.ttlSec ?? 600;
  const cache = new ApplicantCache();

  provider.use(async (ctx, next) => {
    if (ctx.method !== 'GET') return next();
    // Match the literal path AND any querystring on `?level=...`.
    const path = ctx.path;
    if (path !== '/kyc/start') return next();

    // Active interaction is required: this surface lives behind a
    // sign-in flow, exactly like /auth/webauthn/register-options.
    let interaction: Awaited<
      ReturnType<typeof provider.interactionDetails>
    > | null = null;
    try {
      interaction = await provider.interactionDetails(ctx.req, ctx.res);
    } catch {
      interaction = null;
    }
    if (!interaction) {
      sendJson(ctx.res, 400, {
        error: 'invalid_request',
        reason: 'no active interaction',
      });
      return;
    }

    const accountId = interaction.session?.accountId;
    if (!accountId) {
      sendJson(ctx.res, 401, {
        error: 'unauthorized',
        reason: 'sign in first, then start identity verification',
      });
      return;
    }

    const levelHint = tierToKycLevel(ctx.query['level'] as string | undefined);
    if (!levelHint) {
      sendJson(ctx.res, 400, {
        error: 'invalid_request',
        reason: 'level must be T3 (individual KYC) or T4 (entity KYB)',
      });
      return;
    }

    const kycProvider = getKycProvider();
    if (!kycProvider) {
      sendJson(ctx.res, 503, {
        error: 'kyc_unconfigured',
        reason:
          'KYC_PROVIDER is not set; user-facing identity verification disabled',
      });
      return;
    }
    if (!vendor) {
      // The singleton is installed but no vendor name to build the
      // SDK URL with. Fail closed — a runtime config mismatch.
      sendJson(ctx.res, 503, {
        error: 'kyc_unconfigured',
        reason: 'KYC vendor name unavailable for SDK URL construction',
      });
      return;
    }

    try {
      let applicantId = cache.get(accountId);
      if (!applicantId) {
        const created = await kycProvider.createApplicant({
          externalUserId: accountId,
          levelHint,
        });
        applicantId = created.applicantId;
        cache.set(accountId, applicantId);
      }
      const session = await kycProvider.mintClientSession({
        applicantId,
        externalUserId: accountId,
        ttlSec,
      });
      const url = buildKycRedirectUrl({
        vendor,
        token: session.token,
        applicantId,
        ...(session.redirectUrl ? { hostedRedirectUrl: session.redirectUrl } : {}),
      });
      ctx.res.writeHead(303, {
        location: url,
        'cache-control': 'no-store',
      });
      ctx.res.end();
      return;
    } catch (err) {
      const message = (err as Error).message ?? 'unknown error';
      // The Sumsub adapter throws a clear "not configured at COMP-S1"
      // for KYB today; surface that as 501 so the dashboard can render
      // a "coming soon" copy without guessing.
      if (
        message.includes('KYB_ENTITY not configured') ||
        message.includes('ENHANCED_INDIVIDUAL not configured')
      ) {
        sendJson(ctx.res, 501, {
          error: 'not_implemented',
          reason: message,
        });
        return;
      }
      sendJson(ctx.res, 502, {
        error: 'kyc_vendor_error',
        reason: message,
      });
      return;
    }
  });
}
