/**
 * WebAuthn (passkey) HTTP routes (WP-6 slice B of EW-S1 + WP-A of the
 * portal registration ladder).
 *
 * Six POST endpoints mounted on the provider's Koa app:
 *
 *   POST /auth/webauthn/authenticate-options
 *     → start a sign-in: generate options with allowCredentials=[] (the
 *       browser picks any resident credential), store the challenge keyed
 *       to the interaction uid. Returns the options JSON.
 *
 *   POST /auth/webauthn/authenticate-verify   { response }
 *     → finish sign-in: replay the stored challenge, verify the assertion,
 *       look up the credential → user, drive provider.interactionResult.
 *       Returns { redirectTo }.
 *
 *   POST /auth/webauthn/signup-email   { email }
 *     → step 1 of "Create an account with a passkey": email a one-time code
 *       bound to THIS interaction. Creates nothing. Enumeration-safe.
 *
 *   POST /auth/webauthn/signup-options   { email, code }
 *     → step 2: consume the code (proving the email), then generate
 *       registration options for the account that email belongs to: the
 *       EXISTING account if there is one (the passkey is added to it), else
 *       a new account id. The passkey is named after the email. Without a
 *       valid code: 400 email_verification_required / 401, nothing happens.
 *
 *   POST /auth/webauthn/signup-verify   { response, deviceLabel? }
 *     → step 3: replay the stored challenge, verify the registration, then
 *       either add the credential to the existing account or create the
 *       account WITH its verified email, and drive provider.interactionResult
 *       so the member lands signed in. Returns 201 { userId, credentialId,
 *       redirectTo }.
 *
 * 2026-11-13 (owner report: passkey "sign-ins" created email-less accounts):
 * signup-options used to mint an account from any new passkey with no email,
 * and the sign-in page sent every failed or dismissed passkey prompt there.
 * Account creation now needs a verified email, and sign-in only ever signs in
 * to the account a registered passkey belongs to.
 *
 *   POST /auth/webauthn/register-options
 *     → start "add a passkey" (post-signin): the caller MUST already have
 *       a completed OIDC interaction session whose accountId resolves to
 *       a real user UUID. Generates registration options, stores challenge.
 *
 *   POST /auth/webauthn/register-verify   { response, deviceLabel? }
 *     → finish "add a passkey": verify the registration response, persist
 *       the credential bound to the session's user. Returns { ok: true }.
 *
 * {@link mountAccountPasskeyRoutes} adds the same "add a passkey" to the
 * account page (/account), authorised by the browser session itself.
 *
 * Challenge storage is in-memory (process-local). For the WP-A acceptance
 * surface this is sufficient: panva sticks a browser to a single instance
 * during an interaction via its session cookie, and authority deploys are
 * Redis-backed when REDIS_URL is wired (PBA-L3a-013); was a follow-up
 * mirror of {@link RedisNonceStore}.
 */

import { createHash, randomUUID } from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type Provider from 'oidc-provider';
import type {
  AuthenticationResponseJSON,
  RegistrationResponseJSON,
} from '@simplewebauthn/server';

import {
  buildAuthenticationOptions,
  buildRegistrationOptions,
  verifyAuthentication,
  verifyRegistration,
  type RelyingPartyConfig,
} from './webauthn.js';
import { getUserStore, getWebAuthnStore } from './stores.js';
import { predictedWalletForAccount } from '../aa/wallet-claims.js';
import type { RedisLike } from '../redis.js';
import { CODE_TTL_MS, getEmailVerificationStore } from './email-verification-pg.js';
import { sendVerificationCode } from '../email-send.js';
import {
  clientIp,
  InMemoryRateLimiter,
  LOGIN_LIMITS,
  LOGIN_WINDOW_MS,
  type RateLimiter,
} from './rate-limit.js';
import { isCrossSite, isValidAccountActionToken } from '../account-csrf.js';

/** Minimum email shape (same as the password routes). */
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const CODE_RE = /^[0-9]{6}$/;

/** The passkey-signup code is bound to its interaction, apart from password codes. */
function signupBinding(interactionUid: string): string {
  return createHash('sha256').update(`passkey-signup:${interactionUid}`).digest('hex');
}

type Ctx = Parameters<Parameters<Provider['use']>[0]>[0];
type Next = Parameters<Parameters<Provider['use']>[0]>[1];

/** Challenge TTL: the WebAuthn `navigator.credentials.*` UI is fast; 5 min is plenty. */
const CHALLENGE_TTL_MS = 5 * 60 * 1000;

interface PendingChallenge {
  challenge: string;
  userId?: string;
  /** Passkey signup: the email the code proved, and whether it has an account. */
  email?: string;
  existing?: boolean;
  expiresAt: number;
}

/** Extra facts a signup challenge carries to its verify step. */
export interface ChallengeExtra {
  email?: string;
  existing?: boolean;
}

/**
 * Challenge store. Keyed by `<flow>:<interactionUid>` so an authentication and a
 * registration challenge for the same interaction don't collide. Single-use +
 * TTL. PBA-L3a-013: Redis-backed when REDIS_URL is wired (a challenge issued by
 * one instance must be consumable on another behind the load balancer), in
 * memory otherwise.
 */
export interface ChallengeStore {
  put(key: string, challenge: string, userId?: string, extra?: ChallengeExtra): Promise<void>;
  take(key: string): Promise<PendingChallenge | undefined>;
}

export class InMemoryChallengeStore implements ChallengeStore {
  private readonly entries = new Map<string, PendingChallenge>();

  async put(key: string, challenge: string, userId?: string, extra: ChallengeExtra = {}): Promise<void> {
    this.entries.set(key, {
      challenge,
      ...(userId !== undefined ? { userId } : {}),
      ...extra,
      expiresAt: Date.now() + CHALLENGE_TTL_MS,
    });
  }

  async take(key: string): Promise<PendingChallenge | undefined> {
    const e = this.entries.get(key);
    if (!e) return undefined;
    this.entries.delete(key);
    if (e.expiresAt < Date.now()) return undefined;
    return e;
  }
}

/** Key prefix, namespaced away from nonces / OAuth state / hand-offs. */
const CHALLENGE_PREFIX = 'webauthn_challenge:';

export class RedisChallengeStore implements ChallengeStore {
  constructor(private readonly redis: RedisLike) {}

  async put(key: string, challenge: string, userId?: string, extra: ChallengeExtra = {}): Promise<void> {
    await this.redis.set(
      CHALLENGE_PREFIX + key,
      JSON.stringify({ challenge, ...(userId !== undefined ? { userId } : {}), ...extra }),
      'PX',
      CHALLENGE_TTL_MS,
    );
  }

  async take(key: string): Promise<PendingChallenge | undefined> {
    const raw = await this.redis.getdel(CHALLENGE_PREFIX + key); // single-use across instances
    if (raw === null) return undefined;
    try {
      const v = JSON.parse(raw) as { challenge?: unknown; userId?: unknown; email?: unknown; existing?: unknown };
      if (typeof v.challenge !== 'string') return undefined;
      return {
        challenge: v.challenge,
        ...(typeof v.userId === 'string' ? { userId: v.userId } : {}),
        ...(typeof v.email === 'string' ? { email: v.email } : {}),
        ...(typeof v.existing === 'boolean' ? { existing: v.existing } : {}),
        expiresAt: Date.now() + CHALLENGE_TTL_MS, // Redis enforced the TTL
      };
    } catch {
      return undefined;
    }
  }
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

function respondJson(
  res: ServerResponse,
  status: number,
  body: unknown,
): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
  });
  res.end(payload);
}

export interface WebAuthnRouteOptions {
  /** Relying party identity Citrate's WebAuthn uses (rpID + origin). */
  rp: RelyingPartyConfig;
  /** PBA-L3a-013: shared challenge store (Redis in production). */
  challengeStore?: ChallengeStore;
  /** Budgets on signup code issuance + guesses (Redis-backed in production). */
  rateLimiter?: RateLimiter;
}

/**
 * Mount the four WebAuthn endpoints on the provider's Koa app. Mount once
 * at boot.
 */
export function mountWebauthnRoutes(
  provider: Provider,
  options: WebAuthnRouteOptions,
): void {
  const challenges: ChallengeStore = options.challengeStore ?? new InMemoryChallengeStore();
  const limiter = options.rateLimiter ?? new InMemoryRateLimiter();
  const { rp } = options;
  const allow = async (checks: Array<[string, number]>): Promise<boolean> => {
    for (const [key, limit] of checks) {
      if (!(await limiter.hit(key, limit, LOGIN_WINDOW_MS))) return false;
    }
    return true;
  };

  provider.use(async (ctx: Ctx, next: Next) => {
    if (ctx.method !== 'POST') return next();
    if (!ctx.path.startsWith('/auth/webauthn/')) return next();

    // All four endpoints require an active interaction cookie — they are
    // surfaces on the login page, not headless endpoints.
    let interaction: Awaited<
      ReturnType<typeof provider.interactionDetails>
    > | null = null;
    try {
      interaction = await provider.interactionDetails(ctx.req, ctx.res);
    } catch {
      interaction = null;
    }
    if (!interaction) {
      respondJson(ctx.res, 400, {
        error: 'invalid_request',
        reason: 'no active interaction',
      });
      return;
    }
    const interactionUid = interaction.uid;

    if (ctx.path === '/auth/webauthn/authenticate-options') {
      const opts = await buildAuthenticationOptions({ rp });
      await challenges.put(`auth:${interactionUid}`, opts.challenge);
      respondJson(ctx.res, 200, opts);
      return;
    }

    if (ctx.path === '/auth/webauthn/authenticate-verify') {
      const pending = await challenges.take(`auth:${interactionUid}`);
      if (!pending) {
        respondJson(ctx.res, 400, {
          error: 'invalid_request',
          reason: 'no challenge in flight (start over)',
        });
        return;
      }
      let body: { response?: unknown };
      try {
        body = (await readJson(ctx.req)) as typeof body;
      } catch {
        respondJson(ctx.res, 400, {
          error: 'invalid_request',
          reason: 'bad_body',
        });
        return;
      }
      const response = body.response as AuthenticationResponseJSON | undefined;
      if (!response || typeof response.id !== 'string') {
        respondJson(ctx.res, 400, {
          error: 'invalid_request',
          reason: 'response is required',
        });
        return;
      }

      let credentialId: Buffer;
      try {
        credentialId = Buffer.from(response.id, 'base64url');
      } catch {
        respondJson(ctx.res, 400, {
          error: 'invalid_request',
          reason: 'response.id is not a base64url string',
        });
        return;
      }

      const credStore = getWebAuthnStore();
      const stored = await credStore.findByCredentialId(credentialId);
      if (!stored) {
        respondJson(ctx.res, 401, {
          error: 'invalid_grant',
          reason: 'credential not registered',
        });
        return;
      }

      let verified;
      try {
        verified = await verifyAuthentication({
          rp,
          expectedChallenge: pending.challenge,
          response,
          storedCredential: {
            credentialId: stored.credentialId,
            publicKeyCose: stored.publicKeyCose,
            signCount: stored.signCount,
          },
        });
      } catch (err) {
        respondJson(ctx.res, 401, {
          error: 'invalid_grant',
          reason: (err as Error).message,
        });
        return;
      }
      await credStore.recordAssertion(stored.credentialId, verified.newSignCount);

      const userStore = getUserStore();
      const user = await userStore.findById(stored.userId);
      if (!user) {
        respondJson(ctx.res, 500, {
          error: 'server_error',
          reason: 'credential references unknown user',
        });
        return;
      }

      await userStore.setLastSigningMethod(user.id, 'passkey');
      const redirectTo = await provider.interactionResult(
        ctx.req,
        ctx.res,
        {
          login: {
            accountId: user.id,
            amr: ['webauthn'],
            acr: 'urn:citrate:webauthn',
          },
        },
        { mergeWithLastSubmission: false },
      );
      const walletAddress = predictedWalletForAccount(user.id);
      respondJson(ctx.res, 200, {
        userId: user.id,
        redirectTo,
        ...(walletAddress ? { walletAddress } : {}),
      });
      return;
    }

    // ── Signup ("Create an account with a passkey") ─────────────────────
    // Three explicit steps; nothing is created until a passkey is attested
    // for an email the member proved with a one-time code (see module doc).
    if (ctx.path === '/auth/webauthn/signup-email' || ctx.path === '/auth/webauthn/signup-options') {
      let body: { email?: unknown; code?: unknown };
      try {
        body = (await readJson(ctx.req)) as typeof body;
      } catch {
        respondJson(ctx.res, 400, { error: 'invalid_request', reason: 'bad_body' });
        return;
      }
      const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
      const ip = clientIp(ctx.req, provider.proxy === true);
      const binding = signupBinding(interactionUid);

      if (ctx.path === '/auth/webauthn/signup-email') {
        if (!EMAIL_RE.test(email)) {
          respondJson(ctx.res, 400, { error: 'invalid_request', reason: 'invalid email' });
          return;
        }
        if (!(await allow([[`pk-issue:ip:${ip}`, LOGIN_LIMITS.issuePerIp]]))) {
          respondJson(ctx.res, 429, { error: 'too_many_requests', reason: 'too many attempts' });
          return;
        }
        const { code, rateLimited } = await getEmailVerificationStore().issue(email, undefined, binding);
        if (rateLimited || !code) {
          respondJson(ctx.res, 429, { error: 'too_many_requests', reason: 'too many verification emails' });
          return;
        }
        if (!(await sendVerificationCode(email, code, Math.round(CODE_TTL_MS / 60_000)))) {
          respondJson(ctx.res, 503, { error: 'email_unavailable', reason: 'could not send the verification email' });
          return;
        }
        respondJson(ctx.res, 200, {
          status: 'verification_required',
          message: 'Enter the 6-digit code we emailed you to continue.',
        });
        return;
      }

      // signup-options: the code is required. No code, no account.
      const code = typeof body.code === 'string' ? body.code.trim() : '';
      if (!EMAIL_RE.test(email) || !CODE_RE.test(code)) {
        respondJson(ctx.res, 400, {
          error: 'email_verification_required',
          reason: 'creating an account needs a verified email: request a code, then send it with the email',
        });
        return;
      }
      if (
        !(await allow([
          [`pk-verify:ip:${ip}`, LOGIN_LIMITS.verifyPerIp],
          [`pk-verify:acct-ip:${email}|${ip}`, LOGIN_LIMITS.verifyPerAccountIp],
          [`pk-verify:acct:${email}`, LOGIN_LIMITS.verifyPerAccount],
        ]))
      ) {
        respondJson(ctx.res, 429, { error: 'too_many_requests', reason: 'too many attempts' });
        return;
      }
      const { ok } = await getEmailVerificationStore().consume(email, code, binding);
      if (!ok) {
        respondJson(ctx.res, 401, { error: 'invalid_grant', reason: 'invalid or expired code' });
        return;
      }
      // The email is proven. If it already has an account, the passkey is
      // added to THAT account; only an unknown email gets a new one.
      const existing = await getUserStore().findByEmail(email);
      const userId = existing?.id ?? randomUUID();
      const known = existing ? await getWebAuthnStore().listByUserId(existing.id) : [];
      const opts = await buildRegistrationOptions({
        rp,
        userId,
        userName: email,
        userDisplayName: email,
        excludeCredentialIds: known.map((c) => c.credentialId),
      });
      await challenges.put(`signup:${interactionUid}`, opts.challenge, userId, {
        email,
        existing: Boolean(existing),
      });
      respondJson(ctx.res, 200, opts);
      return;
    }

    if (ctx.path === '/auth/webauthn/signup-verify') {
      const pending = await challenges.take(`signup:${interactionUid}`);
      if (!pending || !pending.userId || !pending.email) {
        respondJson(ctx.res, 400, {
          error: 'invalid_request',
          reason: 'no challenge in flight (start over)',
        });
        return;
      }
      let body: { response?: unknown; deviceLabel?: unknown };
      try {
        body = (await readJson(ctx.req)) as typeof body;
      } catch {
        respondJson(ctx.res, 400, {
          error: 'invalid_request',
          reason: 'bad_body',
        });
        return;
      }
      const response = body.response as RegistrationResponseJSON | undefined;
      if (!response) {
        respondJson(ctx.res, 400, {
          error: 'invalid_request',
          reason: 'response is required',
        });
        return;
      }

      let verified;
      try {
        verified = await verifyRegistration({
          rp,
          expectedChallenge: pending.challenge,
          response,
        });
      } catch (err) {
        respondJson(ctx.res, 400, {
          error: 'invalid_grant',
          reason: (err as Error).message,
        });
        return;
      }

      const credStore = getWebAuthnStore();
      const collision = await credStore.findByCredentialId(verified.credentialId);
      if (collision) {
        respondJson(ctx.res, 409, {
          error: 'conflict',
          reason: 'credential already registered',
        });
        return;
      }

      const userStore = getUserStore();
      let user;
      if (pending.existing) {
        user = await userStore.findById(pending.userId);
        if (!user || user.email !== pending.email) {
          respondJson(ctx.res, 409, { error: 'conflict', reason: 'account changed, start over' });
          return;
        }
      } else {
        if (await userStore.findByEmail(pending.email)) {
          // Someone created this email's account since the code was checked.
          respondJson(ctx.res, 409, { error: 'conflict', reason: 'account changed, start over' });
          return;
        }
        user = await userStore.createWithPasskey({ id: pending.userId, email: pending.email });
      }
      await userStore.markEmailVerified(user.id);
      const rec = await credStore.insertCredential({
        userId: user.id,
        credentialId: verified.credentialId,
        publicKeyCose: verified.publicKeyCose,
        signCount: verified.signCount,
        transports: verified.transports,
        ...(verified.aaguid !== undefined ? { aaguid: verified.aaguid } : {}),
        ...(typeof body.deviceLabel === 'string'
          ? { deviceLabel: body.deviceLabel }
          : {}),
      });

      await userStore.setLastSigningMethod(user.id, 'passkey');
      const redirectTo = await provider.interactionResult(
        ctx.req,
        ctx.res,
        {
          login: {
            accountId: user.id,
            amr: ['webauthn'],
            acr: 'urn:citrate:webauthn',
          },
        },
        { mergeWithLastSubmission: false },
      );
      const walletAddress = predictedWalletForAccount(user.id);
      respondJson(ctx.res, 201, {
        userId: user.id,
        credentialId: rec.id,
        redirectTo,
        ...(walletAddress ? { walletAddress } : {}),
      });
      return;
    }

    // ── Registration (post-signin "add a passkey") ──────────────────────
    // Both register endpoints REQUIRE the interaction session to already
    // carry an authenticated accountId; this is the dashboard's "add
    // passkey" surface, not first-time enrollment.
    const accountId = interaction.session?.accountId;
    if (!accountId) {
      respondJson(ctx.res, 401, {
        error: 'unauthorized',
        reason: 'sign in first, then register a passkey',
      });
      return;
    }

    if (ctx.path === '/auth/webauthn/register-options') {
      const credStore = getWebAuthnStore();
      const existing = await credStore.listByUserId(accountId);
      const opts = await buildRegistrationOptions({
        rp,
        userId: accountId,
        userName: accountId,
        excludeCredentialIds: existing.map((c) => c.credentialId),
      });
      await challenges.put(`reg:${interactionUid}`, opts.challenge, accountId);
      respondJson(ctx.res, 200, opts);
      return;
    }

    if (ctx.path === '/auth/webauthn/register-verify') {
      const pending = await challenges.take(`reg:${interactionUid}`);
      if (!pending || pending.userId !== accountId) {
        respondJson(ctx.res, 400, {
          error: 'invalid_request',
          reason: 'no challenge in flight (start over)',
        });
        return;
      }
      let body: { response?: unknown; deviceLabel?: unknown };
      try {
        body = (await readJson(ctx.req)) as typeof body;
      } catch {
        respondJson(ctx.res, 400, {
          error: 'invalid_request',
          reason: 'bad_body',
        });
        return;
      }
      const response = body.response as RegistrationResponseJSON | undefined;
      if (!response) {
        respondJson(ctx.res, 400, {
          error: 'invalid_request',
          reason: 'response is required',
        });
        return;
      }

      let verified;
      try {
        verified = await verifyRegistration({
          rp,
          expectedChallenge: pending.challenge,
          response,
        });
      } catch (err) {
        respondJson(ctx.res, 400, {
          error: 'invalid_grant',
          reason: (err as Error).message,
        });
        return;
      }

      const credStore = getWebAuthnStore();
      const rec = await credStore.insertCredential({
        userId: accountId,
        credentialId: verified.credentialId,
        publicKeyCose: verified.publicKeyCose,
        signCount: verified.signCount,
        transports: verified.transports,
        ...(verified.aaguid !== undefined ? { aaguid: verified.aaguid } : {}),
        ...(typeof body.deviceLabel === 'string'
          ? { deviceLabel: body.deviceLabel }
          : {}),
      });
      respondJson(ctx.res, 200, { ok: true, credentialId: rec.id });
      return;
    }

    return next();
  });
}

/**
 * The account page's "Add a passkey" (2026-11-13). A member signed in to
 * auth.citrate.ai with any method (email, Google, an earlier passkey) adds a
 * passkey to THAT account, so the next sign-in can use it instead of
 * creating another account:
 *
 *   GET  /account/passkey.js        the page script (same-origin; the page's
 *                                   CSP allows only 'self' scripts)
 *   POST /account/passkey/options   { csrf }            → registration options
 *   POST /account/passkey/verify    { csrf, response }  → { ok, credentialId }
 *
 * Authorised by the browser session (not an interaction), plus the
 * session-bound account-action token and a same-origin check
 * (account-csrf.ts). Only accounts with a user record (email, Google or
 * passkey accounts) can hold a passkey; a wallet-only (SIWE) identity has no
 * user row and is refused.
 */
export function mountAccountPasskeyRoutes(
  provider: Provider,
  options: { rp: RelyingPartyConfig; challengeStore?: ChallengeStore },
): void {
  const challenges: ChallengeStore = options.challengeStore ?? new InMemoryChallengeStore();
  const { rp } = options;
  const issuerOrigin = new URL(provider.issuer).origin;

  provider.use(async (ctx: Ctx, next: Next) => {
    if (ctx.method === 'GET' && ctx.path === '/account/passkey.js') {
      ctx.res.writeHead(200, {
        'content-type': 'text/javascript; charset=utf-8',
        'cache-control': 'no-cache',
        'x-content-type-options': 'nosniff',
      });
      ctx.res.end(ACCOUNT_PASSKEY_JS);
      return;
    }
    if (ctx.method !== 'POST' || (ctx.path !== '/account/passkey/options' && ctx.path !== '/account/passkey/verify')) {
      return next();
    }
    if (isCrossSite(ctx.req, issuerOrigin)) {
      respondJson(ctx.res, 403, { error: 'invalid_request', reason: 'cross_site_forbidden' });
      return;
    }
    let session: { jti: string; accountId?: string } | undefined;
    try {
      session = (await provider.Session.get(ctx)) as unknown as { jti: string; accountId?: string };
    } catch {
      session = undefined;
    }
    if (!session?.accountId) {
      respondJson(ctx.res, 401, { error: 'unauthorized', reason: 'sign in first, then add a passkey' });
      return;
    }
    let body: { csrf?: unknown; response?: unknown; deviceLabel?: unknown };
    try {
      body = (await readJson(ctx.req)) as typeof body;
    } catch {
      respondJson(ctx.res, 400, { error: 'invalid_request', reason: 'bad_body' });
      return;
    }
    if (!isValidAccountActionToken(session.jti, body.csrf)) {
      respondJson(ctx.res, 403, { error: 'invalid_request', reason: 'invalid_csrf_token' });
      return;
    }
    const accountId = session.accountId;
    let user;
    try {
      user = await getUserStore().findById(accountId);
    } catch {
      user = undefined; // a wallet (SIWE) subject is not a user UUID
    }
    if (!user) {
      respondJson(ctx.res, 409, { error: 'invalid_request', reason: 'this account cannot hold a passkey' });
      return;
    }
    const key = `acct-reg:${session.jti}`;

    if (ctx.path === '/account/passkey/options') {
      const known = await getWebAuthnStore().listByUserId(user.id);
      const opts = await buildRegistrationOptions({
        rp,
        userId: user.id,
        userName: user.email ?? user.id,
        userDisplayName: user.email ?? 'Citrate account',
        excludeCredentialIds: known.map((c) => c.credentialId),
      });
      await challenges.put(key, opts.challenge, user.id);
      respondJson(ctx.res, 200, opts);
      return;
    }

    const pending = await challenges.take(key);
    if (!pending || pending.userId !== user.id) {
      respondJson(ctx.res, 400, { error: 'invalid_request', reason: 'no challenge in flight (start over)' });
      return;
    }
    const response = body.response as RegistrationResponseJSON | undefined;
    if (!response) {
      respondJson(ctx.res, 400, { error: 'invalid_request', reason: 'response is required' });
      return;
    }
    let verified;
    try {
      verified = await verifyRegistration({ rp, expectedChallenge: pending.challenge, response });
    } catch (err) {
      respondJson(ctx.res, 400, { error: 'invalid_grant', reason: (err as Error).message });
      return;
    }
    const credStore = getWebAuthnStore();
    if (await credStore.findByCredentialId(verified.credentialId)) {
      respondJson(ctx.res, 409, { error: 'conflict', reason: 'credential already registered' });
      return;
    }
    const rec = await credStore.insertCredential({
      userId: user.id,
      credentialId: verified.credentialId,
      publicKeyCose: verified.publicKeyCose,
      signCount: verified.signCount,
      transports: verified.transports,
      ...(verified.aaguid !== undefined ? { aaguid: verified.aaguid } : {}),
      ...(typeof body.deviceLabel === 'string' ? { deviceLabel: body.deviceLabel.slice(0, 64) } : {}),
    });
    respondJson(ctx.res, 200, { ok: true, credentialId: rec.id });
  });
}

/** Browser script for the account page's "Add a passkey" button. */
const ACCOUNT_PASSKEY_JS = `'use strict';
(function () {
  var btn = document.getElementById('add-passkey');
  if (!btn) return;
  var statusEl = document.getElementById('add-passkey-status');
  var csrf = btn.getAttribute('data-csrf');
  function say(msg) { if (statusEl) statusEl.textContent = msg; }
  function b64uToBuf(s) {
    var b64 = s.split('-').join('+').split('_').join('/');
    while (b64.length % 4) b64 += '=';
    var bin = atob(b64), out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.buffer;
  }
  function bufToB64u(buf) {
    var bytes = new Uint8Array(buf), s = '';
    for (var i = 0; i < bytes.byteLength; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s).split('+').join('-').split('/').join('_').replace(/=+$/, '');
  }
  function post(path, body) {
    return fetch(path, {
      method: 'POST', credentials: 'same-origin',
      headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
    });
  }
  btn.addEventListener('click', async function () {
    if (!window.PublicKeyCredential) { say('This browser does not support passkeys.'); return; }
    btn.disabled = true;
    try {
      say('Asking your device to create a passkey for this account...');
      var optsRes = await post('/account/passkey/options', { csrf: csrf });
      var options = await optsRes.json();
      if (!optsRes.ok) { say('Could not start: ' + (options.reason || optsRes.status)); btn.disabled = false; return; }
      var publicKey = Object.assign({}, options, {
        challenge: b64uToBuf(options.challenge),
        user: Object.assign({}, options.user, { id: b64uToBuf(options.user.id) }),
        excludeCredentials: (options.excludeCredentials || []).map(function (c) { return Object.assign({}, c, { id: b64uToBuf(c.id) }); }),
      });
      var c = await navigator.credentials.create({ publicKey: publicKey });
      if (!c) { say('No passkey was created.'); btn.disabled = false; return; }
      var response = {
        id: c.id, rawId: bufToB64u(c.rawId), type: c.type,
        response: {
          clientDataJSON: bufToB64u(c.response.clientDataJSON),
          attestationObject: bufToB64u(c.response.attestationObject),
          transports: typeof c.response.getTransports === 'function' ? c.response.getTransports() : [],
        },
        clientExtensionResults: c.getClientExtensionResults ? c.getClientExtensionResults() : {},
      };
      var v = await post('/account/passkey/verify', { csrf: csrf, response: response });
      var r = await v.json();
      if (!v.ok) { say('Could not add the passkey: ' + (r.reason || v.status)); btn.disabled = false; return; }
      say('Passkey added. Next time, choose "Continue with passkey" to sign in to this account.');
    } catch (err) {
      if (err && err.name === 'InvalidStateError') say('This device already has a passkey for this account.');
      else if (err && err.name === 'NotAllowedError') say('No passkey was created.');
      else say('Error: ' + (err && err.message ? err.message : String(err)));
      btn.disabled = false;
    }
  });
})();
`;
