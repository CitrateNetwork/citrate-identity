/**
 * Cross-origin + operational HTTP extras for the Citrate OIDC authority.
 *
 * Two concerns, mounted as a SINGLE panva middleware so they run BEFORE every
 * other route (the SIWE / KYC / logout routes and panva's own router):
 *
 *   1. CORS — RPs (citrate-explorer / -dashboard / optionally -studio) call a
 *      handful of authority endpoints cross-origin from the browser:
 *        - `/siwe/*` (Path B direct-token + the challenge fetch),
 *        - `/sessions/events` (the logout SSE stream),
 *        - the standard OIDC `/token`, `/me` (userinfo), `/jwks`,
 *          `/token/introspection`, `/token/revocation`.
 *      We echo ONLY an allow-listed origin (never `*`), allow credentials so the
 *      session/interaction cookie + Authorization header ride along, and answer
 *      the preflight `OPTIONS` ourselves. A non-allow-listed origin gets NO CORS
 *      headers — the browser then blocks the cross-origin read (fail closed).
 *
 *   2. `/health` (+ `/healthz` alias) — a lightweight liveness/readiness probe
 *      for Caddy / the load balancer / devops `curl`. Returns 200 JSON
 *      `{status:"ok", redis?, db?}`. It pings Redis/PG when those were wired, but
 *      NEVER throws: a probe failure degrades a sub-field to `false`, it does not
 *      500 the endpoint (so the LB sees the process is up even if a dependency is
 *      briefly flapping; deeper checks belong in dependency-specific alerting).
 *
 * Both are mounted OUTSIDE panva's OIDC routing and short-circuit before
 * `next()`, so they never interfere with the protocol endpoints.
 */
import type { IncomingMessage, ServerResponse } from 'node:http';
import type Provider from 'oidc-provider';
import { isAllowedCorsOrigin } from './config.js';

/** Methods RPs use on the cross-origin authority routes. */
const ALLOWED_METHODS = 'GET, POST, OPTIONS';

/**
 * Request headers RPs send cross-origin: JSON content-type on /siwe/verify +
 * /token, and the Bearer Authorization header on /logout + /me + introspection.
 */
const ALLOWED_HEADERS = 'Content-Type, Authorization';

export interface HttpExtrasOptions {
  /**
   * Ping the Redis client backing the authority state. Resolves `true` when
   * reachable, `false` otherwise. Omitted when REDIS_URL is unset (dev), in which
   * case `/health` omits the `redis` field. MUST NOT throw — the caller wraps a
   * real `PING` and swallows errors into `false`.
   */
  pingRedis?: () => Promise<boolean>;
  /**
   * Ping the Postgres pool backing the KYC store. Same contract as
   * {@link pingRedis}; omitted when DATABASE_URL is unset (dev), in which case
   * `/health` omits the `db` field.
   */
  pingDb?: () => Promise<boolean>;
}

/**
 * Apply the CORS response headers for an allow-listed origin. Echoes the exact
 * origin (never `*`), permits credentials, and advertises the allowed methods +
 * headers. `Vary: Origin` keeps a shared cache from serving one RP's CORS headers
 * to another origin. No-ops for a non-allow-listed / same-origin request.
 */
function applyCorsHeaders(req: IncomingMessage, res: ServerResponse): boolean {
  const origin = req.headers['origin'];
  // `origin` can be string | string[] | undefined per Node's typings; CORS only
  // ever sends a single Origin header, so normalise to the first value.
  const value = Array.isArray(origin) ? origin[0] : origin;
  // Always Vary on Origin so caches don't cross-contaminate per-origin headers.
  res.setHeader('Vary', 'Origin');
  if (!isAllowedCorsOrigin(value)) return false;
  res.setHeader('Access-Control-Allow-Origin', value as string);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', ALLOWED_METHODS);
  res.setHeader('Access-Control-Allow-Headers', ALLOWED_HEADERS);
  res.setHeader('Access-Control-Max-Age', '600');
  return true;
}

/**
 * Mount the CORS + `/health` middleware on the provider's Koa app. Install this
 * FIRST (before the SIWE/KYC/logout routes) so CORS headers are present on those
 * cross-origin responses and the health probe answers without touching panva.
 */
export function mountHttpExtras(
  provider: Provider,
  options: HttpExtrasOptions = {},
): void {
  provider.use(async (ctx, next) => {
    const { method, path } = ctx;

    // CORS first, so every response we (or panva) emit for an allow-listed RP
    // origin — including /health and the preflight below — carries the headers.
    applyCorsHeaders(ctx.req, ctx.res);
    if (method === 'OPTIONS') {
      // Preflight: respond 204 with the CORS headers already set above. A
      // disallowed origin still gets a clean 204, just without the allow-origin
      // echo, which the browser treats as "not permitted" — fail closed.
      ctx.status = 204;
      ctx.set('content-length', '0');
      ctx.body = null;
      return;
    }

    // --- /health (+ /healthz alias) — never throws. ---
    if (method === 'GET' && (path === '/health' || path === '/healthz')) {
      const body: { status: 'ok'; redis?: boolean; db?: boolean } = {
        status: 'ok',
      };
      if (options.pingRedis) {
        try {
          body.redis = await options.pingRedis();
        } catch {
          body.redis = false;
        }
      }
      if (options.pingDb) {
        try {
          body.db = await options.pingDb();
        } catch {
          body.db = false;
        }
      }
      ctx.status = 200;
      ctx.set('cache-control', 'no-store');
      ctx.body = body;
      return; // handled — do not fall through to panva
    }

    await next();
  });
}
