import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { exportJWK, generateKeyPair, type JWK } from 'jose';
import { getAddress, isAddress } from 'viem';
import type { Account, Configuration, FindAccount } from 'oidc-provider';
import { getKycStore, effectiveVerified, type KycStatus } from './kyc.js';

/**
 * Public issuer URL. In production: https://auth.citrate.ai
 * For local dev / tests, defaults to http://localhost:3000.
 */
export const ISSUER_URL = process.env.ISSUER_URL ?? 'http://localhost:3000';

/** Listen port. */
export const PORT = Number(process.env.PORT ?? 3000);

/**
 * The citrate-explorer relying party's web origin. The explorer completes login
 * by redirecting the browser to `${EXPLORER_ORIGIN}/auth/callback`, so that path
 * — NOT a bare `/callback` and NOT the authority's own origin — is what must be
 * registered as the redirect_uri. Configurable so a self-hosted / preview
 * explorer can point the authority at its own origin. Defaults to the local dev
 * explorer on :3001.
 */
export const EXPLORER_ORIGIN =
  process.env.EXPLORER_ORIGIN ?? 'http://localhost:3001';

/**
 * The citrate-dashboard relying party's web origin. Mirrors {@link EXPLORER_ORIGIN}:
 * the dashboard completes login by redirecting the browser to
 * `${DASHBOARD_ORIGIN}/auth/callback`, so that path is what must be registered as
 * a redirect_uri. Defaults to the local dev dashboard on :3002.
 */
export const DASHBOARD_ORIGIN =
  process.env.DASHBOARD_ORIGIN ?? 'http://localhost:3002';

/** The shared OAuth callback path (where panva sends `code` + `state`). */
const CALLBACK_PATH = '/auth/callback';

/**
 * Loopback redirect placeholder for native/CLI clients (RFC 8252). The actual
 * loopback port is chosen by the native app at runtime; oidc-provider treats any
 * port on a registered 127.0.0.1 loopback redirect as valid, so this concrete
 * placeholder both documents intent and satisfies registration. It mirrors the
 * `/auth/callback` path so native flows and the web flow agree.
 */
const LOOPBACK_REDIRECT = `http://127.0.0.1:${PORT}${CALLBACK_PATH}`;

/**
 * TD-8 — trusted first-party relying parties. Consent for any client in this set
 * is auto-granted (a real persisted Grant with the requested scopes/claims; see
 * siwe-routes.ts), because Citrate owns these RPs end-to-end. Any client_id NOT
 * in this set falls through to the normal interactive consent prompt. This is the
 * single source of truth — there is no per-client hardcode anywhere else.
 */
export const TRUSTED_FIRST_PARTY_CLIENT_IDS: ReadonlySet<string> = new Set([
  'citrate-explorer',
  'citrate-dashboard',
]);

/** True iff `clientId` is a Citrate-owned trusted first-party RP (TD-8). */
export function isTrustedFirstPartyClient(clientId: string): boolean {
  return TRUSTED_FIRST_PARTY_CLIENT_IDS.has(clientId);
}

/** The dev-default cookie key shipped in source — must never run in production. */
export const DEV_DEFAULT_COOKIE_KEY = 'citrate-identity-dev-cookie-key';

/** Minimum length (chars) for a production cookie signing key. */
export const MIN_COOKIE_KEY_LENGTH = 32;

/**
 * Where to persist the signing keys so they survive restarts in dev. If absent,
 * a fresh RS256 key is generated and written. Tests use ephemeral keys (the file
 * is created under a temp-ish project path and ignored by git).
 */
const JWKS_PATH = resolve(process.cwd(), '.keys/jwks.json');

interface PersistedJwks {
  keys: JWK[];
}

/**
 * Load an RS256 JWKS from disk, or generate one and persist it. Returns the
 * private JWKS in the shape oidc-provider expects (`jwks.keys`).
 */
export async function loadOrCreateJwks(): Promise<PersistedJwks> {
  if (existsSync(JWKS_PATH)) {
    const raw = readFileSync(JWKS_PATH, 'utf8');
    const parsed = JSON.parse(raw) as PersistedJwks;
    if (Array.isArray(parsed.keys) && parsed.keys.length > 0) {
      return parsed;
    }
  }

  const { privateKey } = await generateKeyPair('RS256', { extractable: true });
  const jwk = await exportJWK(privateKey);
  jwk.use = 'sig';
  jwk.alg = 'RS256';
  jwk.kid = `citrate-${Date.now()}`;

  const jwks: PersistedJwks = { keys: [jwk] };

  mkdirSync(dirname(JWKS_PATH), { recursive: true });
  writeFileSync(JWKS_PATH, JSON.stringify(jwks, null, 2), 'utf8');
  return jwks;
}

/**
 * The host (authority) a SIWE message must be bound to (EIP-4361 `domain`),
 * derived from an issuer URL. For `https://auth.citrate.ai` this is
 * `auth.citrate.ai`; for `http://127.0.0.1:42817` it is `127.0.0.1:42817`.
 * Domain binding is the anti-phishing control: a message signed for some other
 * site cannot be replayed against this authority.
 */
export function siweDomainFromIssuer(issuer: string): string {
  return new URL(issuer).host;
}

/**
 * The environment surface {@link assertProductionConfig} inspects. Passed in
 * (rather than read from `process.env` inside) so the check is pure and
 * unit-testable: a test constructs each bad case explicitly.
 */
export interface ConfigEnv {
  NODE_ENV?: string;
  CITRATE_ENV?: string;
  COOKIE_KEYS?: string;
  ISSUER_URL?: string;
  EXPLORER_ORIGIN?: string;
  DASHBOARD_ORIGIN?: string;
}

/** A host is "local" if it is localhost / a loopback / `.local` / unspecified. */
function isLocalHost(host: string): boolean {
  const h = host.toLowerCase();
  // Strip any :port for the bare-host comparisons.
  const bare = h.includes(':') ? h.slice(0, h.indexOf(':')) : h;
  return (
    bare === 'localhost' ||
    bare === '127.0.0.1' ||
    bare === '::1' ||
    bare === '0.0.0.0' ||
    bare.endsWith('.local') ||
    bare.endsWith('.localhost')
  );
}

/** True iff `url` is parseable and points at a local/loopback host. */
function isLocalUrl(url: string | undefined): boolean {
  if (!url) return false;
  try {
    return isLocalHost(new URL(url).host);
  } catch {
    // Unparseable → treat as local so production refuses to start on garbage.
    return true;
  }
}

/**
 * TD-1 — fail-closed production config gate.
 *
 * In production (`NODE_ENV==='production'` OR `CITRATE_ENV==='production'`) this
 * THROWS when any deploy-unsafe default is still in place, so the authority
 * refuses to boot rather than silently signing cookies / discovery with a known
 * dev secret. Production rejects when ANY of:
 *   - COOKIE_KEYS is unset, equals the dev default, or has any key < 32 chars;
 *   - ISSUER_URL is unset or points at a localhost / loopback host;
 *   - EXPLORER_ORIGIN or DASHBOARD_ORIGIN points at a localhost / loopback host.
 *
 * Outside production it never throws; it collects the same problems and (if the
 * caller wants) returns them as warnings — the dev defaults stay usable.
 *
 * Pure: it reads only the passed-in `env`, so a unit test can drive every branch.
 */
export function assertProductionConfig(env: ConfigEnv): { warnings: string[] } {
  const isProd =
    env.NODE_ENV === 'production' || env.CITRATE_ENV === 'production';

  const problems: string[] = [];

  // --- COOKIE_KEYS ---
  const rawCookieKeys = env.COOKIE_KEYS;
  if (rawCookieKeys === undefined || rawCookieKeys.trim() === '') {
    problems.push('COOKIE_KEYS is unset (cookie forgery if deployed unset)');
  } else {
    const keys = rawCookieKeys
      .split(',')
      .map((k) => k.trim())
      .filter(Boolean);
    if (keys.length === 0) {
      problems.push('COOKIE_KEYS contains no usable keys');
    } else {
      if (keys.includes(DEV_DEFAULT_COOKIE_KEY)) {
        problems.push(
          `COOKIE_KEYS still contains the dev-default key "${DEV_DEFAULT_COOKIE_KEY}"`,
        );
      }
      const tooShort = keys.filter((k) => k.length < MIN_COOKIE_KEY_LENGTH);
      if (tooShort.length > 0) {
        problems.push(
          `COOKIE_KEYS has ${tooShort.length} key(s) shorter than ${MIN_COOKIE_KEY_LENGTH} chars`,
        );
      }
    }
  }

  // --- ISSUER_URL ---
  if (!env.ISSUER_URL || env.ISSUER_URL.trim() === '') {
    problems.push('ISSUER_URL is unset');
  } else if (isLocalUrl(env.ISSUER_URL)) {
    problems.push(`ISSUER_URL points at a local host: ${env.ISSUER_URL}`);
  }

  // --- RP origins ---
  if (isLocalUrl(env.EXPLORER_ORIGIN)) {
    problems.push(
      `EXPLORER_ORIGIN points at a local host: ${env.EXPLORER_ORIGIN}`,
    );
  }
  if (isLocalUrl(env.DASHBOARD_ORIGIN)) {
    problems.push(
      `DASHBOARD_ORIGIN points at a local host: ${env.DASHBOARD_ORIGIN}`,
    );
  }

  if (isProd && problems.length > 0) {
    throw new Error(
      'Refusing to start in production with unsafe config (TD-1):\n  - ' +
        problems.join('\n  - '),
    );
  }

  return { warnings: problems };
}

/**
 * SIWE account resolver (IDP-S1.5).
 *
 * With SIWE, the wallet IS the identity: the account id is the EIP-55
 * checksummed wallet address, and the `wallet_address` claim is that same
 * address. There is no off-chain user record to look up — possession of the
 * address (proven by the verified EIP-4361 signature) is the account. Linked
 * (secondary) wallets and the canonical-first-wallet rule arrive in IDP-S3;
 * until then `wallets` is the single-element list of the address itself.
 *
 * Both the OIDC interaction-resume path and the direct-token path call this, so
 * claims are identical regardless of how the login was driven.
 */
export const findAccount: FindAccount = (_ctx, sub): Account => {
  // `sub` is the accountId we set during login = the verified wallet address.
  const address = isAddress(sub) ? getAddress(sub) : sub;
  return {
    accountId: address,
    async claims() {
      // Read the CURRENT KYC record at claims() time. panva invokes claims()
      // afresh for every /userinfo call (it is not cached against a token), so a
      // revoke or an expiry that lands AFTER a token was minted is reflected the
      // next time an RP calls /userinfo. This is the whole point of IDP-KYC: the
      // store — not the immutable token — is authoritative for gated actions.
      const claim = getKycStore().get(address);
      // Effective status: an expired or non-`verified` record reports as not
      // verified; a revoked record reports `revoked`. We never assert verified
      // for an expired claim (ADR: expiry → re-KYC).
      const verified = effectiveVerified(claim);
      // The effective status surfaced to RPs. 'none' = never did KYC; 'expired'
      // = stored verified but past expires_at (distinct from a vendor 'revoked').
      // Anything other than the literal 'verified' must NOT pass a gated action.
      const kyc_status: KycStatus | 'none' | 'expired' = claim
        ? verified
          ? 'verified'
          : claim.status === 'verified'
            ? 'expired'
            : claim.status
        : 'none';
      return {
        sub: address,
        // Populate the `wallet` scope claims the authority advertises. Before
        // S1.5 these were declared but never filled; SIWE makes them real.
        wallet_address: address,
        wallets: [address],
        // KYC scope claims — LIVE, read from the store above. `kyc_status` is the
        // effective state ('none' when the wallet never did KYC); the dates are
        // the raw vendor record (no PII).
        kyc_status,
        kyc_verified_at: claim?.verified_at,
        kyc_expires_at: claim?.expires_at,
      };
    },
  };
};

/**
 * Build the oidc-provider configuration for the Citrate authority.
 *
 * Reference relying party is `citrate-explorer` (IDP-S1). It is a PUBLIC client
 * (no secret) that uses Authorization Code + PKCE (S256). Refresh-token rotation
 * and token revocation are enabled per the security must-haves.
 */
export async function buildConfiguration(): Promise<Configuration> {
  const jwks = await loadOrCreateJwks();

  return {
    jwks,
    // SIWE login resolves the authenticated wallet address → OIDC account, and
    // populates the `wallet_address` / `wallets` claims (IDP-S1.5).
    findAccount,
    clients: [
      {
        client_id: 'citrate-explorer',
        // Public client → no secret; PKCE carries the proof-of-possession.
        token_endpoint_auth_method: 'none',
        application_type: 'web',
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
        redirect_uris: [
          // Web callback for the configured (local/dev) explorer origin. The
          // explorer redirects to `${EXPLORER_ORIGIN}/auth/callback` — this must
          // match byte-for-byte or panva rejects the /auth request.
          `${EXPLORER_ORIGIN}${CALLBACK_PATH}`,
          // Hosted production explorer.
          `https://explorer.citrate.ai${CALLBACK_PATH}`,
          // Loopback for native/CLI flows (RFC 8252).
          LOOPBACK_REDIRECT,
        ],
        // `offline_access` lets the explorer request a refresh token; combined
        // with the `refresh_token` grant + rotateRefreshToken below that gives
        // rotating refresh tokens (a security must-have).
        scope: 'openid profile wallet kyc offline_access',
      },
      {
        // citrate-dashboard — second first-party relying party (IDP-S5b). Same
        // posture as the explorer: PUBLIC client (no secret), Authorization Code
        // + PKCE (S256, enforced globally below), rotating refresh tokens.
        client_id: 'citrate-dashboard',
        token_endpoint_auth_method: 'none',
        application_type: 'web',
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
        redirect_uris: [
          // Web callback for the configured (local/dev) dashboard origin.
          `${DASHBOARD_ORIGIN}${CALLBACK_PATH}`,
          // Hosted production dashboard.
          `https://dashboard.citrate.ai${CALLBACK_PATH}`,
          // Loopback for native/CLI flows (RFC 8252).
          LOOPBACK_REDIRECT,
        ],
        // `kyc` is available (advertised below) but NOT required for the
        // dashboard's baseline `openid profile wallet`; offline_access enables
        // the refresh_token grant the same way it does for the explorer.
        scope: 'openid profile wallet kyc offline_access',
      },
    ],
    // `offline_access` is what turns on the `refresh_token` grant_type in panva
    // (lib/helpers/configuration.js): without a refresh-capable scope the
    // provider rejects a client that declares grant_types: ['…','refresh_token'].
    scopes: ['openid', 'profile', 'wallet', 'kyc', 'offline_access'],
    claims: {
      openid: ['sub'],
      profile: ['name', 'email'],
      // Citrate extension: canonical wallet + linked wallets surfaced under the
      // `wallet` scope. Populated by the identity registry in later stages (S3).
      wallet: ['wallet_address', 'wallets'],
      // IDP-KYC: live, revocable KYC status under its own `kyc` scope. These are
      // read from the KYC store at claims() time so /userinfo reflects the
      // CURRENT record (revocation/expiry), not a stale token snapshot. Record
      // holds NO PII — only status + dates (vendor holds PII; ADR-2026-06-03).
      kyc: ['kyc_status', 'kyc_verified_at', 'kyc_expires_at'],
    },
    cookies: {
      // Keys for signing/verifying interaction + session cookies so tampered
      // cookies are detected and ignored. In production set COOKIE_KEYS to a
      // comma-separated list of high-entropy secrets (supports rotation).
      keys: (process.env.COOKIE_KEYS ?? 'citrate-identity-dev-cookie-key')
        .split(',')
        .map((k) => k.trim())
        .filter(Boolean),
    },
    pkce: {
      // PKCE is MANDATORY for every client (red-team security must-have).
      required: () => true,
    },
    interactions: {
      // Replace panva's generic dev login page (which cannot speak SIWE) with
      // our own SIWE interaction view, mounted at /interaction/:uid by
      // mountSiweRoutes. panva 303s the browser here when an /auth request needs
      // authentication; the page drives /siwe/challenge + /siwe/verify (Path A),
      // which resolves the interaction via provider.interactionResult.
      url(_ctx, interaction) {
        return `/interaction/${interaction.uid}`;
      },
    },
    features: {
      // Spec-compliant discovery is on by default; refresh + revocation explicit.
      revocation: { enabled: true },
      // devInteractions OFF: panva's built-in dev login page cannot perform a
      // SIWE signature. We serve our own interaction view (see interactions.url).
      devInteractions: { enabled: false },
    },
    // Put scope-requested claims (notably `wallet_address` / `wallets`) directly
    // in the ID token even when an access token is co-issued. With the default
    // (true), the Authorization-Code flow would push those non-`sub` claims to
    // the userinfo endpoint only; relying parties like the explorer expect the
    // wallet identity inside the verifiable ID token, so we conform to that.
    conformIdTokenClaims: false,
    // Rotating refresh tokens: issue a fresh refresh token on every use.
    rotateRefreshToken: true,
    ttl: {
      AccessToken: 60 * 60,
      AuthorizationCode: 10 * 60,
      IdToken: 60 * 60,
      RefreshToken: 14 * 24 * 60 * 60,
    },
  };
}
