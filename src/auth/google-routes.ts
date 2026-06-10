/**
 * Google federation routes (WP-6 slice C).
 *
 * Two GET endpoints mounted on the provider's Koa app:
 *
 *   GET /auth/google/start
 *     → start a PKCE-protected OIDC code flow at `accounts.google.com`.
 *       Reads the in-flight interaction cookie, stashes the
 *       interaction uid + a fresh `state` + `nonce` + `code_verifier`
 *       in an in-memory map, then 303s the browser to Google's
 *       authorization endpoint.
 *
 *   GET /auth/google/callback?code=...&state=...
 *     → Google sends the browser here. Pop the stashed state, exchange
 *       the code for an `id_token` at `oauth2.googleapis.com/token`,
 *       verify the JWT against Google's JWKS, look up the user by
 *       `google_sub` (and fall back to `email` for an existing
 *       email/password account, linking the `google_sub` to it), then
 *       drive `provider.interactionResult` and 303 to its `redirectTo`.
 *
 * Mounted from `server.ts` ONLY when both `CITRATE_AA_GOOGLE_CLIENT_ID`
 * AND `CITRATE_AA_GOOGLE_CLIENT_SECRET` are set; absent either, the
 * routes never register and the interaction page shows the "not
 * enabled" copy. The interaction-page rendering layer also reads
 * `googleEnabled` and only renders the active "Continue with Google"
 * button when the env is set — these gates have to stay in sync.
 */

import type { IncomingMessage, ServerResponse } from 'node:http';
import { createHash, randomBytes } from 'node:crypto';
import { createRemoteJWKSet, jwtVerify, type JWTPayload } from 'jose';
import type Provider from 'oidc-provider';

import { getUserStore } from './stores.js';

type Ctx = Parameters<Parameters<Provider['use']>[0]>[0];
type Next = Parameters<Parameters<Provider['use']>[0]>[1];

const GOOGLE_AUTH = 'https://accounts.google.com/o/oauth2/v2/auth';
const GOOGLE_TOKEN = 'https://oauth2.googleapis.com/token';
const GOOGLE_ISSUER = 'https://accounts.google.com';
const GOOGLE_JWKS = createRemoteJWKSet(
  new URL('https://www.googleapis.com/oauth2/v3/certs'),
);

/** State lookup TTL — Google's UX usually completes in seconds, but a slow
 * user may pause; 10 min matches the interaction TTL. */
const STATE_TTL_MS = 10 * 60 * 1000;

interface PendingState {
  /** Interaction uid we'll resume after Google sends the user back. */
  interactionUid: string;
  /** PKCE: the verifier we hand back to Google when exchanging the code. */
  codeVerifier: string;
  /** Replay defense: must match the `nonce` claim Google signs into the id_token. */
  nonce: string;
  expiresAt: number;
}

/**
 * Process-wide pending state. Single-instance only; HA would need Redis.
 * Cleaned up after a successful callback or by TTL expiry; lookups that
 * miss the TTL act as if the state never existed (fail-closed).
 */
class StateStore {
  private readonly entries = new Map<string, PendingState>();

  put(key: string, value: Omit<PendingState, 'expiresAt'>): void {
    this.entries.set(key, { ...value, expiresAt: Date.now() + STATE_TTL_MS });
  }

  take(key: string): PendingState | undefined {
    const e = this.entries.get(key);
    if (!e) return undefined;
    this.entries.delete(key);
    if (e.expiresAt < Date.now()) return undefined;
    return e;
  }
}

function b64url(buf: Buffer): string {
  return buf
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function pkceChallengeS256(verifier: string): string {
  return b64url(createHash('sha256').update(verifier).digest());
}

function redirect303(res: ServerResponse, location: string): void {
  res.writeHead(303, { location, 'cache-control': 'no-store' });
  res.end();
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
  });
  res.end(payload);
}

export interface GoogleRouteOptions {
  /** Google Cloud Console OAuth client id (web type). */
  clientId: string;
  /** Google Cloud Console OAuth client secret (web type). */
  clientSecret: string;
  /** Callback URL we registered with Google. Must be exact — Google
   * compares byte-for-byte against the registered redirect URIs. */
  redirectUri: string;
}

/**
 * Mount `GET /auth/google/{start,callback}` on the provider's Koa app.
 * Mount once at boot.
 */
export function mountGoogleRoutes(
  provider: Provider,
  options: GoogleRouteOptions,
): void {
  const states = new StateStore();
  const { clientId, clientSecret, redirectUri } = options;

  provider.use(async (ctx: Ctx, next: Next) => {
    if (ctx.method !== 'GET') return next();
    if (ctx.path !== '/auth/google/start' && ctx.path !== '/auth/google/callback') {
      return next();
    }

    if (ctx.path === '/auth/google/start') {
      // The interaction cookie must be present — `/auth/google/start` is the
      // login surface for an in-flight OIDC interaction; a bare hit with no
      // cookie has nothing to resume.
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

      const state = b64url(randomBytes(32));
      const nonce = b64url(randomBytes(32));
      const codeVerifier = b64url(randomBytes(64));
      states.put(state, {
        interactionUid: interaction.uid,
        codeVerifier,
        nonce,
      });

      const auth = new URL(GOOGLE_AUTH);
      auth.searchParams.set('client_id', clientId);
      auth.searchParams.set('redirect_uri', redirectUri);
      auth.searchParams.set('response_type', 'code');
      auth.searchParams.set('scope', 'openid email profile');
      auth.searchParams.set('state', state);
      auth.searchParams.set('nonce', nonce);
      auth.searchParams.set('code_challenge', pkceChallengeS256(codeVerifier));
      auth.searchParams.set('code_challenge_method', 'S256');
      // `prompt=select_account` lets the user pick which Google account
      // to use even if they're already signed in to one.
      auth.searchParams.set('prompt', 'select_account');
      redirect303(ctx.res, auth.toString());
      return;
    }

    // /auth/google/callback ────────────────────────────────────────
    const query = ctx.query ?? {};
    const code = typeof query.code === 'string' ? query.code : '';
    const state = typeof query.state === 'string' ? query.state : '';
    const error = typeof query.error === 'string' ? query.error : '';

    if (error) {
      // Google reports failures (user denied consent, invalid request, …)
      // via the `error` query parameter. Surface the literal so the operator
      // can debug a misconfigured client; the page's lede already shows the
      // user something helpful.
      sendJson(ctx.res, 400, {
        error: 'google_oauth_failed',
        reason: error,
      });
      return;
    }
    if (!code || !state) {
      sendJson(ctx.res, 400, {
        error: 'invalid_request',
        reason: 'missing code or state',
      });
      return;
    }
    const pending = states.take(state);
    if (!pending) {
      sendJson(ctx.res, 400, {
        error: 'invalid_request',
        reason: 'unknown or expired state',
      });
      return;
    }

    // Exchange the authorization code for tokens.
    const tokenBody = new URLSearchParams({
      code,
      client_id: clientId,
      client_secret: clientSecret,
      redirect_uri: redirectUri,
      grant_type: 'authorization_code',
      code_verifier: pending.codeVerifier,
    });
    const tokenRes = await fetch(GOOGLE_TOKEN, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: tokenBody,
    });
    if (!tokenRes.ok) {
      const text = await tokenRes.text();
      sendJson(ctx.res, 502, {
        error: 'google_token_exchange_failed',
        reason: text.slice(0, 200),
      });
      return;
    }
    const tokens = (await tokenRes.json()) as { id_token?: string };
    if (!tokens.id_token) {
      sendJson(ctx.res, 502, {
        error: 'google_token_exchange_failed',
        reason: 'no id_token in response',
      });
      return;
    }

    // Verify the id_token. jose checks signature against Google's JWKS,
    // enforces `iss=accounts.google.com` and `aud=our client id`, and
    // returns the parsed claims.
    let payload: JWTPayload;
    try {
      const verified = await jwtVerify(tokens.id_token, GOOGLE_JWKS, {
        issuer: GOOGLE_ISSUER,
        audience: clientId,
      });
      payload = verified.payload;
    } catch (err) {
      sendJson(ctx.res, 401, {
        error: 'invalid_id_token',
        reason: (err as Error).message,
      });
      return;
    }

    // Replay defense: `nonce` in the id_token must match the one we
    // generated at /auth/google/start.
    if (payload.nonce !== pending.nonce) {
      sendJson(ctx.res, 401, {
        error: 'invalid_id_token',
        reason: 'nonce mismatch',
      });
      return;
    }

    const googleSub = typeof payload.sub === 'string' ? payload.sub : '';
    const email = typeof payload.email === 'string' ? payload.email : undefined;
    if (!googleSub) {
      sendJson(ctx.res, 401, {
        error: 'invalid_id_token',
        reason: 'missing sub',
      });
      return;
    }

    // Look up: by google_sub first, then fall back to email for an
    // existing email/password account (link the google_sub to it so
    // future sign-ins find it directly). If neither matches, create.
    const store = getUserStore();
    let user = await store.findByGoogleSub(googleSub);
    if (!user && email) {
      user = await store.findByEmail(email);
      if (user) {
        try {
          await store.linkGoogleSub(user.id, googleSub);
          user.googleSub = googleSub;
        } catch {
          // Race: another callback linked first; pick up the now-linked record.
          user = await store.findByGoogleSub(googleSub);
        }
      }
    }
    if (!user) {
      user = await store.createWithGoogle({
        googleSub,
        ...(email !== undefined ? { email } : {}),
      });
    }

    const redirectTo = await provider.interactionResult(
      ctx.req,
      ctx.res,
      {
        login: {
          accountId: user.id,
          amr: ['google'],
          acr: 'urn:citrate:google',
        },
      },
      { mergeWithLastSubmission: false },
    );
    redirect303(ctx.res, redirectTo);
  });
}
