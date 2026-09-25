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

import { getUserStore, type UserStore } from './stores.js';
import type { UserRecord } from './users-pg.js';
import type { RedisLike } from '../redis.js';

type Ctx = Parameters<Parameters<Provider['use']>[0]>[0];
type Next = Parameters<Parameters<Provider['use']>[0]>[1];

/**
 * FWA-C6-01 (account-takeover) hardening: decide which email an id_token may be
 * trusted to assert.
 *
 * A signed Google id_token proves Google ISSUED it — NOT that the subject owns
 * the email it carries. Google emits `email_verified: false` for unverified
 * mailboxes (notably domain-unverified Workspace / Cloud Identity tenants an
 * attacker can provision). Trusting the bare `email` claim lets an attacker
 * assert a victim's address and have us link the attacker's google_sub onto, or
 * create an `emailVerified` account bound to, the victim's email → takeover.
 *
 * The email is usable for `findByEmail`-linking / `createWithGoogle(email)`
 * ONLY when `email_verified` is boolean `true` (Google has historically sent
 * the claim as the JSON string `"true"` as well, so accept both spellings).
 * Anything else (false, the string `"false"`, missing, non-string, non-boolean)
 * is treated as UNVERIFIED → the email is ignored entirely, matching the
 * passkey path (link by google_sub only / create with no email binding).
 */
export function trustedEmailFromIdToken(payload: JWTPayload): string | undefined {
  const email = typeof payload.email === 'string' ? payload.email : undefined;
  if (email === undefined) return undefined;
  const verified = payload.email_verified;
  const isVerified = verified === true || verified === 'true';
  return isVerified ? email : undefined;
}

/**
 * Resolve (or create) the local user for a verified Google id_token payload.
 * Extracted from the callback so the link/create decision — the locus of
 * FWA-C6-01 — is unit-testable without a live Google token/JWKS mock.
 *
 * Look-up order:
 *   1. by `google_sub` (a returning Google user) — always trusted; the sub is
 *      Google's stable, non-reassignable account identifier.
 *   2. else, IF and ONLY IF the id_token carries a VERIFIED email
 *      ({@link trustedEmailFromIdToken}), fall back to `findByEmail` and link
 *      the google_sub onto that existing account.
 *   3. else create a fresh account, binding the email ONLY when it is verified.
 *
 * Returns `undefined` for a missing/empty `sub` (the caller 401s).
 */
export async function resolveGoogleUser(
  payload: JWTPayload,
  store: UserStore,
): Promise<UserRecord | undefined> {
  const googleSub = typeof payload.sub === 'string' ? payload.sub : '';
  if (!googleSub) return undefined;
  // Only a verified email may bind to / link onto an account (FWA-C6-01).
  const trustedEmail = trustedEmailFromIdToken(payload);

  let user = await store.findByGoogleSub(googleSub);
  // PBA-L3a-010: link onto an existing email account only when THAT account's
  // email is verified too. An unverified row may be a squatter's pre-registration
  // of the victim's address; linking would hand the victim's Google login to it.
  // In that case the Google identity gets its own account WITHOUT the email (the
  // address is taken by the unverified row, which stays untouched).
  let emailTakenUnverified = false;
  if (!user && trustedEmail) {
    user = await store.findByEmail(trustedEmail);
    if (user && !user.emailVerified) {
      emailTakenUnverified = true;
      user = undefined;
    }
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
      ...(trustedEmail !== undefined && !emailTakenUnverified ? { email: trustedEmail } : {}),
    });
  }
  return user;
}

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

/** What we persist per state — without the in-memory bookkeeping `expiresAt`. */
type StateValue = Omit<PendingState, 'expiresAt'>;

/**
 * The state/nonce/code_verifier store seam. Single-use + TTL on BOTH backings:
 *
 *   - {@link InMemoryStateStore} for single-instance dev/test.
 *   - {@link RedisStateStore} for the mandated multi-instance HA posture
 *     (FWA-C6-02): a `/start` on instance A and its `/callback` on instance B
 *     must resolve the same pending state, and the cross-instance single-use /
 *     replay guarantee must hold — mirroring {@link RedisNonceStore}.
 *
 * `take` is destructive and at-most-once: whichever caller removes the entry
 * gets it; every later/racing attempt (replay) gets `undefined`. Expired or
 * unknown states are also absent → `undefined` (fail-closed).
 */
export interface StateStore {
  put(key: string, value: StateValue): Promise<void>;
  take(key: string): Promise<PendingState | undefined>;
}

/** Process-local store. Correct for single-instance dev/test only. */
export class InMemoryStateStore implements StateStore {
  private readonly entries = new Map<string, PendingState>();

  async put(key: string, value: StateValue): Promise<void> {
    this.entries.set(key, { ...value, expiresAt: Date.now() + STATE_TTL_MS });
  }

  async take(key: string): Promise<PendingState | undefined> {
    const e = this.entries.get(key);
    if (!e) return undefined;
    this.entries.delete(key); // single-use: delete-on-read
    if (e.expiresAt < Date.now()) return undefined;
    return e;
  }
}

/** Key prefix so Google state entries are namespaced from other authority keys. */
const STATE_PREFIX = 'google_state:';

/**
 * Redis-backed store for HA (FWA-C6-02). `put` writes the triple as JSON with a
 * `PX` TTL set in the SAME command (no window where state exists without an
 * expiry) and `NX` so a (astronomically unlikely) collision never silently
 * overwrites a live state. `take` consumes with an atomic single-command
 * `GETDEL` — the delete is what makes the state one-time ACROSS instances, the
 * same discipline {@link RedisNonceStore} uses for SIWE nonces. Redis enforces
 * the TTL, so an expired entry is simply absent → `undefined` (fail-closed).
 */
export class RedisStateStore implements StateStore {
  constructor(private readonly redis: RedisLike) {}

  async put(key: string, value: StateValue): Promise<void> {
    await this.redis.set(
      STATE_PREFIX + key,
      JSON.stringify(value),
      'PX',
      STATE_TTL_MS,
      'NX',
    );
  }

  async take(key: string): Promise<PendingState | undefined> {
    const raw = await this.redis.getdel(STATE_PREFIX + key);
    if (raw === null) return undefined;
    let parsed: StateValue;
    try {
      parsed = JSON.parse(raw) as StateValue;
    } catch {
      return undefined;
    }
    // Redis already enforced the TTL; reconstruct the shape callers expect.
    return { ...parsed, expiresAt: Date.now() + STATE_TTL_MS };
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
  /**
   * Shared Redis client (FWA-C6-02). When provided, the OAuth
   * `state`/`nonce`/`code_verifier` triple is stored in Redis (single-use via
   * GETDEL, TTL via PX) so a multi-instance auth.citrate.ai resolves the same
   * pending state regardless of which instance served `/start` vs `/callback`.
   * When omitted (single-instance dev/test), an in-process store with the same
   * single-use + TTL semantics is used.
   */
  redis?: RedisLike;
}

/**
 * Mount `GET /auth/google/{start,callback}` on the provider's Koa app.
 * Mount once at boot.
 */
export function mountGoogleRoutes(
  provider: Provider,
  options: GoogleRouteOptions,
): void {
  const { clientId, clientSecret, redirectUri, redis } = options;
  // HA (FWA-C6-02): Redis-backed when a shared client is wired (prod), else an
  // in-process store with the same single-use + TTL semantics (dev/test).
  const states: StateStore = redis
    ? new RedisStateStore(redis)
    : new InMemoryStateStore();

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
      try {
        await states.put(state, {
          interactionUid: interaction.uid,
          codeVerifier,
          nonce,
        });
      } catch {
        // Fail-closed (FWA-C6-02): if the shared state store is unreachable we
        // cannot guarantee the callback will find (and single-use-consume) this
        // state, so we refuse to start the flow rather than emit a state we
        // can't honor.
        sendJson(ctx.res, 503, {
          error: 'temporarily_unavailable',
          reason: 'state store unavailable',
        });
        return;
      }

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
    let pending: PendingState | undefined;
    try {
      pending = await states.take(state);
    } catch {
      // Fail-closed (FWA-C6-02): a state store we can't reach can neither
      // confirm the state is genuine nor enforce single-use, so we reject.
      sendJson(ctx.res, 503, {
        error: 'temporarily_unavailable',
        reason: 'state store unavailable',
      });
      return;
    }
    if (!pending) {
      sendJson(ctx.res, 400, {
        error: 'invalid_request',
        reason: 'unknown or expired state',
      });
      return;
    }

    // ID-B-002 (login-CSRF / session fixation): bind the OAuth `state` to the
    // browser/interaction that began the flow. `/auth/google/start` recorded the
    // originating `interactionUid` in the state; the cookie on THIS request names
    // the interaction `interactionResult` would resume. If they differ, someone is
    // completing THEIR Google login into a VICTIM's in-flight interaction — refuse
    // before any token exchange. (Mirrors the browser-cookie state binding the
    // KYC-admin login-bounce already enforces; SIWE/consent use a same-origin guard.)
    let cbInteraction: Awaited<
      ReturnType<typeof provider.interactionDetails>
    > | null = null;
    try {
      cbInteraction = await provider.interactionDetails(ctx.req, ctx.res);
    } catch {
      cbInteraction = null;
    }
    if (!cbInteraction || cbInteraction.uid !== pending.interactionUid) {
      sendJson(ctx.res, 400, {
        error: 'invalid_request',
        reason: 'interaction mismatch',
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

    if (typeof payload.sub !== 'string' || payload.sub === '') {
      sendJson(ctx.res, 401, {
        error: 'invalid_id_token',
        reason: 'missing sub',
      });
      return;
    }

    // Look up: by google_sub first, then fall back to email for an existing
    // account — but ONLY when the id_token's email is `email_verified` (a
    // signed token does not prove email ownership; see resolveGoogleUser /
    // FWA-C6-01). If neither matches, create (email bound only if verified).
    const store = getUserStore();
    const user = await resolveGoogleUser(payload, store);
    if (!user) {
      // Defensive: resolveGoogleUser only returns undefined for a missing sub,
      // which we already rejected above.
      sendJson(ctx.res, 401, {
        error: 'invalid_id_token',
        reason: 'missing sub',
      });
      return;
    }

    await store.setLastSigningMethod(user.id, 'google');
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
