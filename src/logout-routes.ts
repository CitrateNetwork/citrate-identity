/**
 * Logout + token revocation + session-bus cascade (IDP-S2 / TD-5, authority side).
 *
 *   gtm-spine/features/IDP-S2-revocation-and-logout-cascade.feature
 *     Scenario: revocation invalidates a token immediately
 *     Scenario: logout in one app cascades to the others
 *
 * Mounts two routes on the provider's Koa app:
 *
 *   POST /logout          → end the session for the presented access token,
 *                            REVOKE that token (panva AccessToken.destroy, so a
 *                            subsequent /token/introspection reports inactive and
 *                            /userinfo 401s), and PUBLISH a `logout` event on the
 *                            session bus for that `sub`. Fails CLOSED: no/invalid
 *                            token → 401, nothing is published.
 *
 *   GET  /sessions/events → Server-Sent Events stream of bus events. Relying
 *                            parties (or a thin proxy) subscribe here and reflect
 *                            logged-out state when a `logout` for the user arrives
 *                            ("cascades to the others"). Each connection subscribes
 *                            to the bus and unsubscribes on disconnect.
 *
 * This is the AUTHORITY half of the cascade. The RP half (explorer/dashboard
 * listening + dropping their local session) is the RP-side of TD-5, tracked
 * separately; the authority publishes the event the RPs consume.
 */
import type { IncomingMessage, ServerResponse } from 'node:http';
import type Provider from 'oidc-provider';
import { getSessionBus, type SessionEvent } from './session-bus.js';

export interface LogoutRouteOptions {
  /**
   * Heartbeat interval (ms) for the SSE stream so proxies don't time the
   * connection out. A comment ping is sent every interval. Default 25s.
   */
  sseHeartbeatMs?: number;
  /**
   * FUA-IDENTITY-05: maximum concurrent `/sessions/events` SSE connections.
   * Over the cap the endpoint returns 503 rather than accept unbounded
   * fan-out. Default 1000.
   */
  maxSseConnections?: number;
}

/** Live count of open `/sessions/events` streams (FUA-IDENTITY-05 cap). */
let activeSseConnections = 0;

/** Extract a Bearer access token from the Authorization header, if present. */
function bearerToken(req: IncomingMessage): string | undefined {
  const auth = req.headers['authorization'];
  if (typeof auth === 'string' && auth.startsWith('Bearer ')) {
    const token = auth.slice('Bearer '.length).trim();
    return token.length > 0 ? token : undefined;
  }
  return undefined;
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
  });
  res.end(JSON.stringify(body));
}

/**
 * The minimal shape of a panva AccessToken instance we rely on. `find` resolves a
 * presented opaque token; the instance carries the account + session ids and a
 * `destroy()` that revokes it (the adapter drops the record, so introspection
 * reports inactive and userinfo 401s).
 */
interface FoundAccessToken {
  accountId?: string;
  sessionUid?: string;
  sid?: string;
  grantId?: string;
  destroy(): Promise<void>;
}

/**
 * Mount `POST /logout` and `GET /sessions/events`. Returns nothing; the routes
 * are wired onto the provider's Koa middleware stack the same way the SIWE/KYC
 * routes are.
 */
export function mountLogoutRoutes(
  provider: Provider,
  options: LogoutRouteOptions = {},
): void {
  const heartbeatMs = options.sseHeartbeatMs ?? 25_000;
  const maxSseConnections = options.maxSseConnections ?? 1000;

  provider.use(async (ctx, next) => {
    const { method, path } = ctx;

    // --- GET /logout — convenience alias for RP-initiated (browser) logout. ---
    // The OIDC end-session endpoint is `/session/end` (advertised in discovery),
    // but some relying parties (e.g. memrizz) redirect the browser to `/logout`.
    // 302 to `/session/end`, preserving the query string so `id_token_hint` /
    // `post_logout_redirect_uri` / `state` flow through and the standard
    // post_logout_redirect_uri validation + seamless redirect apply. (Distinct
    // from `POST /logout`, the token-revoke API below.)
    if (method === 'GET' && path === '/logout') {
      const qs = ctx.querystring ? `?${ctx.querystring}` : '';
      ctx.redirect(`/session/end${qs}`);
      return;
    }

    // --- GET /sessions/events — SSE fan-out of session-bus events. ---
    if (method === 'GET' && path === '/sessions/events') {
      const res = ctx.res;

      // FUA-IDENTITY-02 (SECREM-02): require an authenticated subscriber and
      // scope the stream to that subscriber's own `sub`. Previously this was
      // unauthenticated and fanned out EVERY user's `sub` + `sid` to any client —
      // a real-time correlation leak from the IdP. Resolve the presented access
      // token (same path /logout uses); fail closed (401) if absent/invalid.
      const token = bearerToken(ctx.req);
      if (!token) {
        sendJson(ctx.res, 401, {
          error: 'invalid_request',
          reason: 'a Bearer access token is required to subscribe',
        });
        return;
      }
      let subscriberAt: FoundAccessToken | undefined;
      try {
        subscriberAt = (await provider.AccessToken.find(token)) as
          | FoundAccessToken
          | undefined;
      } catch {
        subscriberAt = undefined;
      }
      if (!subscriberAt || !subscriberAt.accountId) {
        sendJson(ctx.res, 401, {
          error: 'invalid_grant',
          reason: 'the presented token is not active',
        });
        return;
      }
      const subscriberSub = subscriberAt.accountId;

      // FUA-IDENTITY-05 (SSE-flood): cap concurrent streams; refuse over the cap.
      if (activeSseConnections >= maxSseConnections) {
        sendJson(ctx.res, 503, {
          error: 'temporarily_unavailable',
          reason: 'too many active subscriptions',
        });
        return;
      }
      activeSseConnections += 1;

      res.writeHead(200, {
        'content-type': 'text/event-stream; charset=utf-8',
        'cache-control': 'no-store',
        connection: 'keep-alive',
      });
      // Open the stream immediately so a client (and a test) knows it is live.
      res.write(': connected\n\n');

      const onEvent = (event: SessionEvent): void => {
        // FUA-IDENTITY-02: deliver ONLY this subscriber's own events.
        if (event.sub !== subscriberSub) return;
        // SSE framing: a named event with a JSON data line.
        res.write(`event: ${event.type}\n`);
        res.write(`data: ${JSON.stringify(event)}\n\n`);
      };
      const unsubscribe = getSessionBus().subscribe(onEvent);

      const heartbeat = setInterval(() => {
        res.write(': ping\n\n');
      }, heartbeatMs);
      // Don't let the heartbeat keep the process alive on its own.
      if (typeof heartbeat.unref === 'function') heartbeat.unref();

      let cleanedUp = false;
      const cleanup = (): void => {
        if (cleanedUp) return;
        cleanedUp = true;
        activeSseConnections -= 1;
        clearInterval(heartbeat);
        unsubscribe();
      };
      ctx.req.on('close', cleanup);
      ctx.req.on('error', cleanup);

      // Hand the socket to the SSE stream: tell Koa we've handled the response so
      // it does not try to write a body or close the connection.
      ctx.respond = false;
      return;
    }

    // --- POST /logout — revoke the presented token + publish a logout event. ---
    if (method === 'POST' && path === '/logout') {
      const token = bearerToken(ctx.req);
      if (!token) {
        // Fail closed: no token → nothing to revoke, nothing published.
        sendJson(ctx.res, 401, {
          error: 'invalid_request',
          reason: 'a Bearer access token is required to log out',
        });
        return;
      }

      let at: FoundAccessToken | undefined;
      try {
        at = (await provider.AccessToken.find(token)) as
          | FoundAccessToken
          | undefined;
      } catch {
        at = undefined;
      }
      if (!at || !at.accountId) {
        // Unknown / already-revoked / expired token → fail closed.
        sendJson(ctx.res, 401, {
          error: 'invalid_grant',
          reason: 'the presented token is not active',
        });
        return;
      }

      const sub = at.accountId;
      const sid = at.sid ?? at.sessionUid;

      // 1) End the session backing this login (if one exists) so a fresh /auth
      //    re-prompts rather than silently re-authenticating from a live cookie.
      if (at.sessionUid) {
        try {
          const session = await provider.Session.findByUid(at.sessionUid);
          if (session) await session.destroy();
        } catch {
          // A missing/already-gone session is fine — logout is idempotent.
        }
      }

      // 2) REVOKE the presented access token. destroy() drops the adapter record,
      //    so a later /token/introspection returns { active: false } and
      //    /userinfo with this token 401s — "invalidates a token immediately".
      await at.destroy();

      // 3) PUBLISH the logout on the session bus so the OTHER apps cascade.
      getSessionBus().publish(sub, { type: 'logout', sid, at: Date.now() });

      sendJson(ctx.res, 200, { ok: true, sub, sid });
      return;
    }

    await next();
  });
}
