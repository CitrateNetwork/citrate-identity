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
 *   POST /auth/webauthn/signup-options
 *     → start a first-time passkey enrollment: mint a server-side pending
 *       user UUID, generate registration options bound to it, store
 *       challenge + pending uid under `signup:<interactionUid>`. Does NOT
 *       require an existing accountId — this is how a fresh user gets one.
 *
 *   POST /auth/webauthn/signup-verify   { response, deviceLabel? }
 *     → finish first-time enrollment: replay the stored challenge, verify
 *       the registration, create the user + credential atomically, then
 *       drive provider.interactionResult so the new user lands signed-in.
 *       Returns 201 { userId, credentialId, redirectTo }.
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
 * Challenge storage is in-memory (process-local). For the WP-A acceptance
 * surface this is sufficient: panva sticks a browser to a single instance
 * during an interaction via its session cookie, and authority deploys are
 * Redis-backed when REDIS_URL is wired (PBA-L3a-013); was a follow-up
 * mirror of {@link RedisNonceStore}.
 */

import { randomUUID } from 'node:crypto';
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

type Ctx = Parameters<Parameters<Provider['use']>[0]>[0];
type Next = Parameters<Parameters<Provider['use']>[0]>[1];

/** Challenge TTL: the WebAuthn `navigator.credentials.*` UI is fast; 5 min is plenty. */
const CHALLENGE_TTL_MS = 5 * 60 * 1000;

interface PendingChallenge {
  challenge: string;
  userId?: string;
  expiresAt: number;
}

/**
 * Challenge store. Keyed by `<flow>:<interactionUid>` so an authentication and a
 * registration challenge for the same interaction don't collide. Single-use +
 * TTL. PBA-L3a-013: Redis-backed when REDIS_URL is wired (a challenge issued by
 * one instance must be consumable on another behind the load balancer), in
 * memory otherwise.
 */
export interface ChallengeStore {
  put(key: string, challenge: string, userId?: string): Promise<void>;
  take(key: string): Promise<PendingChallenge | undefined>;
}

export class InMemoryChallengeStore implements ChallengeStore {
  private readonly entries = new Map<string, PendingChallenge>();

  async put(key: string, challenge: string, userId?: string): Promise<void> {
    this.entries.set(key, {
      challenge,
      ...(userId !== undefined ? { userId } : {}),
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

  async put(key: string, challenge: string, userId?: string): Promise<void> {
    await this.redis.set(
      CHALLENGE_PREFIX + key,
      JSON.stringify({ challenge, ...(userId !== undefined ? { userId } : {}) }),
      'PX',
      CHALLENGE_TTL_MS,
    );
  }

  async take(key: string): Promise<PendingChallenge | undefined> {
    const raw = await this.redis.getdel(CHALLENGE_PREFIX + key); // single-use across instances
    if (raw === null) return undefined;
    try {
      const v = JSON.parse(raw) as { challenge?: unknown; userId?: unknown };
      if (typeof v.challenge !== 'string') return undefined;
      return {
        challenge: v.challenge,
        ...(typeof v.userId === 'string' ? { userId: v.userId } : {}),
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
  const { rp } = options;

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

    // ── Signup (first-time enrollment, no prior accountId) ──────────────
    // signup-options + signup-verify are how a brand-new user gets an
    // account by attesting a passkey. We mint a pending user UUID at
    // signup-options time so the authenticator's stored userHandle matches
    // the row we will eventually create.
    if (ctx.path === '/auth/webauthn/signup-options') {
      const pendingUserId = randomUUID();
      const opts = await buildRegistrationOptions({
        rp,
        userId: pendingUserId,
        userName: 'New Citrate user',
        userDisplayName: 'New Citrate user',
      });
      await challenges.put(`signup:${interactionUid}`, opts.challenge, pendingUserId);
      respondJson(ctx.res, 200, opts);
      return;
    }

    if (ctx.path === '/auth/webauthn/signup-verify') {
      const pending = await challenges.take(`signup:${interactionUid}`);
      if (!pending || !pending.userId) {
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
      const user = await userStore.createWithPasskey();
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
