/**
 * Generic OAuth2 federation routes (FWA #87.3) — GitHub, Discord, X.
 *
 * Mirrors `google-routes.ts` but for plain OAuth2 (access-token + userinfo API,
 * no OIDC id_token): one `mountOAuth2Provider` drives
 *   GET /auth/<name>/start     → PKCE-protected authorize redirect
 *   GET /auth/<name>/callback   → code→token→userinfo→resolve→session
 * reusing the same single-use, TTL-bound, CSRF-interaction-bound state store.
 *
 * NON-NEGOTIABLE (same as Google, FWA-C6-01): an email binds to / links onto an
 * account ONLY when the provider PROVES ownership:
 *   - GitHub:  the account's primary email with `verified: true` (/user/emails).
 *   - Discord: the profile `email` only when `verified === true`.
 *   - X:       returns no email → handle-only; the account is created email-less
 *              and the user must complete the #87.1 email-verify step before any
 *              email binds. We NEVER assume ownership.
 *
 * Each provider mounts ONLY when its CLIENT_ID + CLIENT_SECRET are set, exactly
 * like Google. The provider `sub` is stored in `federated_identities`.
 */

import type { IncomingMessage, ServerResponse } from 'node:http';
import { createHash, randomBytes } from 'node:crypto';
import type Provider from 'oidc-provider';

import { getUserStore, type UserStore } from './stores.js';
import type { UserRecord } from './users-pg.js';
import {
  InMemoryStateStore,
  RedisStateStore,
  type StateStore,
} from './google-routes.js';
import type { RedisLike } from '../redis.js';

type Ctx = Parameters<Parameters<Provider['use']>[0]>[0];
type Next = Parameters<Parameters<Provider['use']>[0]>[1];

/** The identity a provider proves about the signed-in user. */
export interface ProviderIdentity {
  /** The provider's stable account id (goes in federated_identities). */
  providerSub: string;
  /** The proven-owned email, or undefined when the provider didn't prove one. */
  email?: string;
}

export interface OAuth2ProviderConfig {
  /** Route + federated-identity key, e.g. 'github'. */
  name: string;
  authUrl: string;
  tokenUrl: string;
  scope: string;
  clientId: string;
  clientSecret: string;
  /** Exact registered callback (e.g. https://auth.citrate.ai/auth/github/callback). */
  redirectUri: string;
  /** PKCE S256 — required by X, harmless (and used) for GitHub/Discord. */
  usePkce: boolean;
  /** Token endpoint auth: 'basic' (X confidential client) or 'body' (GitHub/Discord). */
  tokenAuth: 'basic' | 'body';
  /** Fetch userinfo with the access token and return the proven identity. */
  extractIdentity: (accessToken: string) => Promise<ProviderIdentity | null>;
  redis?: RedisLike;
}

/**
 * Resolve (or create) the local user for a proven provider identity. The email
 * is trusted ONLY when the caller passes it (it already applied the provider's
 * verified-ownership rule). Look-up order mirrors resolveGoogleUser:
 *   1. by (provider, providerSub) — a returning user, always trusted.
 *   2. else, if a VERIFIED email is present AND the existing email account is
 *      itself verified, link onto it (PBA-L3a-010);
 *   3. else create, binding the email only when verified.
 */
export async function resolveFederatedUser(
  provider: string,
  identity: ProviderIdentity,
  store: UserStore,
): Promise<UserRecord | undefined> {
  const { providerSub, email } = identity;
  if (!providerSub) return undefined;

  let user = await store.findByFederated(provider, providerSub);
  // PBA-L3a-010: both sides verified, or no link (see resolveGoogleUser).
  let emailTakenUnverified = false;
  if (!user && email) {
    user = await store.findByEmail(email);
    if (user && !user.emailVerified) {
      emailTakenUnverified = true;
      user = undefined;
    }
    if (user) {
      try {
        await store.linkFederated(user.id, provider, providerSub);
      } catch {
        // Race: another callback linked first; pick up the linked record.
        user = await store.findByFederated(provider, providerSub);
      }
    }
  }
  if (!user) {
    user = await store.createWithFederated({
      provider,
      providerSub,
      ...(email !== undefined && !emailTakenUnverified ? { email } : {}),
    });
  }
  return user;
}

function b64url(buf: Buffer): string {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function pkceChallengeS256(verifier: string): string {
  return b64url(createHash('sha256').update(verifier).digest());
}
function redirect303(res: ServerResponse, location: string): void {
  res.writeHead(303, { location, 'cache-control': 'no-store' });
  res.end();
}
function sendJson(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
  });
  res.end(JSON.stringify(body));
}

/** Mount GET /auth/<name>/{start,callback}. Mount once at boot. */
export function mountOAuth2Provider(
  provider: Provider,
  cfg: OAuth2ProviderConfig,
): void {
  const states: StateStore = cfg.redis
    ? new RedisStateStore(cfg.redis, `oauth_state:${cfg.name}:`)
    : new InMemoryStateStore();
  const startPath = `/auth/${cfg.name}/start`;
  const callbackPath = `/auth/${cfg.name}/callback`;

  provider.use(async (ctx: Ctx, next: Next) => {
    if (ctx.method !== 'GET') return next();
    if (ctx.path !== startPath && ctx.path !== callbackPath) return next();

    if (ctx.path === startPath) {
      let interaction: Awaited<
        ReturnType<typeof provider.interactionDetails>
      > | null = null;
      try {
        interaction = await provider.interactionDetails(ctx.req, ctx.res);
      } catch {
        interaction = null;
      }
      if (!interaction) {
        sendJson(ctx.res, 400, { error: 'invalid_request', reason: 'no active interaction' });
        return;
      }
      const state = b64url(randomBytes(32));
      const codeVerifier = b64url(randomBytes(64));
      try {
        await states.put(state, { interactionUid: interaction.uid, codeVerifier, nonce: '' });
      } catch {
        sendJson(ctx.res, 503, { error: 'temporarily_unavailable', reason: 'state store unavailable' });
        return;
      }
      const auth = new URL(cfg.authUrl);
      auth.searchParams.set('client_id', cfg.clientId);
      auth.searchParams.set('redirect_uri', cfg.redirectUri);
      auth.searchParams.set('response_type', 'code');
      auth.searchParams.set('scope', cfg.scope);
      auth.searchParams.set('state', state);
      if (cfg.usePkce) {
        auth.searchParams.set('code_challenge', pkceChallengeS256(codeVerifier));
        auth.searchParams.set('code_challenge_method', 'S256');
      }
      redirect303(ctx.res, auth.toString());
      return;
    }

    // callback ──────────────────────────────────────────────────────────
    const query = ctx.query ?? {};
    const code = typeof query.code === 'string' ? query.code : '';
    const state = typeof query.state === 'string' ? query.state : '';
    const errParam = typeof query.error === 'string' ? query.error : '';
    if (errParam) {
      sendJson(ctx.res, 400, { error: `${cfg.name}_oauth_failed`, reason: errParam });
      return;
    }
    if (!code || !state) {
      sendJson(ctx.res, 400, { error: 'invalid_request', reason: 'missing code or state' });
      return;
    }
    let pending;
    try {
      pending = await states.take(state);
    } catch {
      sendJson(ctx.res, 503, { error: 'temporarily_unavailable', reason: 'state store unavailable' });
      return;
    }
    if (!pending) {
      sendJson(ctx.res, 400, { error: 'invalid_request', reason: 'unknown or expired state' });
      return;
    }

    // ID-B-002 (login-CSRF): the callback's interaction cookie must be the SAME
    // interaction that began the flow, or someone is completing THEIR provider
    // login into a VICTIM's in-flight interaction.
    let cbInteraction: Awaited<
      ReturnType<typeof provider.interactionDetails>
    > | null = null;
    try {
      cbInteraction = await provider.interactionDetails(ctx.req, ctx.res);
    } catch {
      cbInteraction = null;
    }
    if (!cbInteraction || cbInteraction.uid !== pending.interactionUid) {
      sendJson(ctx.res, 400, { error: 'invalid_request', reason: 'interaction mismatch' });
      return;
    }

    // Exchange code → access token.
    const form = new URLSearchParams({
      code,
      redirect_uri: cfg.redirectUri,
      grant_type: 'authorization_code',
      client_id: cfg.clientId,
    });
    if (cfg.usePkce) form.set('code_verifier', pending.codeVerifier);
    const headers: Record<string, string> = {
      'content-type': 'application/x-www-form-urlencoded',
      accept: 'application/json',
    };
    if (cfg.tokenAuth === 'basic') {
      headers.authorization =
        'Basic ' + Buffer.from(`${cfg.clientId}:${cfg.clientSecret}`).toString('base64');
    } else {
      form.set('client_secret', cfg.clientSecret);
    }
    let tokenRes: Response;
    try {
      tokenRes = await fetch(cfg.tokenUrl, { method: 'POST', headers, body: form });
    } catch (err) {
      sendJson(ctx.res, 502, { error: `${cfg.name}_token_exchange_failed`, reason: (err as Error).message });
      return;
    }
    if (!tokenRes.ok) {
      const text = await tokenRes.text();
      sendJson(ctx.res, 502, { error: `${cfg.name}_token_exchange_failed`, reason: text.slice(0, 200) });
      return;
    }
    const tokens = (await tokenRes.json()) as { access_token?: string };
    if (!tokens.access_token) {
      sendJson(ctx.res, 502, { error: `${cfg.name}_token_exchange_failed`, reason: 'no access_token' });
      return;
    }

    // Fetch userinfo + apply the provider's proven-ownership rule.
    let identity: ProviderIdentity | null;
    try {
      identity = await cfg.extractIdentity(tokens.access_token);
    } catch (err) {
      sendJson(ctx.res, 502, { error: `${cfg.name}_userinfo_failed`, reason: (err as Error).message });
      return;
    }
    if (!identity || !identity.providerSub) {
      sendJson(ctx.res, 502, { error: `${cfg.name}_userinfo_failed`, reason: 'no account id' });
      return;
    }

    const store = getUserStore();
    const user = await resolveFederatedUser(cfg.name, identity, store);
    if (!user) {
      sendJson(ctx.res, 401, { error: 'invalid_grant', reason: 'could not resolve user' });
      return;
    }
    await store.setLastSigningMethod(user.id, cfg.name);
    const redirectTo = await provider.interactionResult(
      ctx.req,
      ctx.res,
      { login: { accountId: user.id, amr: [cfg.name], acr: `urn:citrate:${cfg.name}` } },
      { mergeWithLastSubmission: false },
    );
    redirect303(ctx.res, redirectTo);
  });
}

// ── Provider identity extractors ────────────────────────────────────────

/** GitHub: bind the primary email only when GitHub says it's verified. */
export async function githubIdentity(accessToken: string): Promise<ProviderIdentity | null> {
  const h = {
    authorization: `Bearer ${accessToken}`,
    accept: 'application/vnd.github+json',
    'user-agent': 'citrate-identity',
  };
  const userRes = await fetch('https://api.github.com/user', { headers: h });
  if (!userRes.ok) return null;
  const u = (await userRes.json()) as { id?: number | string };
  if (u.id === undefined) return null;
  const providerSub = String(u.id);
  let email: string | undefined;
  const emailsRes = await fetch('https://api.github.com/user/emails', { headers: h });
  if (emailsRes.ok) {
    const emails = (await emailsRes.json()) as Array<{
      email: string;
      primary?: boolean;
      verified?: boolean;
    }>;
    const primary = emails.find((e) => e.primary && e.verified);
    if (primary) email = primary.email;
  }
  return { providerSub, ...(email !== undefined ? { email } : {}) };
}

/** Discord: bind the email only when the profile `verified` flag is true. */
export async function discordIdentity(accessToken: string): Promise<ProviderIdentity | null> {
  const res = await fetch('https://discord.com/api/users/@me', {
    headers: { authorization: `Bearer ${accessToken}` },
  });
  if (!res.ok) return null;
  const u = (await res.json()) as { id?: string; email?: string; verified?: boolean };
  if (!u.id) return null;
  const email = u.verified === true && typeof u.email === 'string' ? u.email : undefined;
  return { providerSub: u.id, ...(email !== undefined ? { email } : {}) };
}

/** X: handle-only — no email is ever asserted (require the #87.1 verify step). */
export async function xIdentity(accessToken: string): Promise<ProviderIdentity | null> {
  const res = await fetch('https://api.twitter.com/2/users/me', {
    headers: { authorization: `Bearer ${accessToken}` },
  });
  if (!res.ok) return null;
  const body = (await res.json()) as { data?: { id?: string } };
  const id = body.data?.id;
  return id ? { providerSub: id } : null;
}

/**
 * Build + mount whichever of GitHub/Discord/X have both CLIENT_ID and
 * CLIENT_SECRET set. `issuerUrl` derives the exact registered callback
 * (<issuer>/auth/<name>/callback), matching how Google is wired.
 */
export function mountConfiguredOAuth2Providers(
  provider: Provider,
  env: Record<string, string | undefined>,
  issuerUrl: string,
  redis?: RedisLike,
): string[] {
  const mounted: string[] = [];
  const base = issuerUrl.replace(/\/+$/, '');
  const specs: Array<Omit<OAuth2ProviderConfig, 'clientId' | 'clientSecret' | 'redirectUri' | 'redis'> & {
    idEnv: string;
    secretEnv: string;
  }> = [
    {
      name: 'github',
      authUrl: 'https://github.com/login/oauth/authorize',
      tokenUrl: 'https://github.com/login/oauth/access_token',
      scope: 'read:user user:email',
      usePkce: false,
      tokenAuth: 'body',
      extractIdentity: githubIdentity,
      idEnv: 'CITRATE_AA_GITHUB_CLIENT_ID',
      secretEnv: 'CITRATE_AA_GITHUB_CLIENT_SECRET',
    },
    {
      name: 'discord',
      authUrl: 'https://discord.com/oauth2/authorize',
      tokenUrl: 'https://discord.com/api/oauth2/token',
      scope: 'identify email',
      usePkce: true,
      tokenAuth: 'body',
      extractIdentity: discordIdentity,
      idEnv: 'CITRATE_AA_DISCORD_CLIENT_ID',
      secretEnv: 'CITRATE_AA_DISCORD_CLIENT_SECRET',
    },
    {
      name: 'x',
      authUrl: 'https://twitter.com/i/oauth2/authorize',
      tokenUrl: 'https://api.twitter.com/2/oauth2/token',
      scope: 'users.read tweet.read offline.access',
      usePkce: true,
      tokenAuth: 'basic',
      extractIdentity: xIdentity,
      idEnv: 'CITRATE_AA_X_CLIENT_ID',
      secretEnv: 'CITRATE_AA_X_CLIENT_SECRET',
    },
  ];
  for (const s of specs) {
    const clientId = env[s.idEnv]?.trim();
    const clientSecret = env[s.secretEnv]?.trim();
    if (!clientId || !clientSecret) continue;
    mountOAuth2Provider(provider, {
      name: s.name,
      authUrl: s.authUrl,
      tokenUrl: s.tokenUrl,
      scope: s.scope,
      clientId,
      clientSecret,
      redirectUri: `${base}/auth/${s.name}/callback`,
      usePkce: s.usePkce,
      tokenAuth: s.tokenAuth,
      extractIdentity: s.extractIdentity,
      ...(redis ? { redis } : {}),
    });
    mounted.push(s.name);
  }
  return mounted;
}
