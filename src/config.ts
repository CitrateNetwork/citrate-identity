import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { exportJWK, generateKeyPair, type JWK } from 'jose';
import { getAddress, isAddress } from 'viem';
import type { Account, Configuration, FindAccount } from 'oidc-provider';

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

/** The explorer's OAuth callback path (where panva sends `code` + `state`). */
const EXPLORER_CALLBACK_PATH = '/auth/callback';

/**
 * Loopback redirect placeholder for native/CLI clients (RFC 8252). The actual
 * loopback port is chosen by the native app at runtime; oidc-provider treats any
 * port on a registered 127.0.0.1 loopback redirect as valid, so this concrete
 * placeholder both documents intent and satisfies registration. It mirrors the
 * explorer's `/auth/callback` path so native flows and the web flow agree.
 */
const LOOPBACK_REDIRECT = `http://127.0.0.1:${PORT}${EXPLORER_CALLBACK_PATH}`;

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
      return {
        sub: address,
        // Populate the `wallet` scope claims the authority advertises. Before
        // S1.5 these were declared but never filled; SIWE makes them real.
        wallet_address: address,
        wallets: [address],
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
          `${EXPLORER_ORIGIN}${EXPLORER_CALLBACK_PATH}`,
          // Hosted production explorer.
          `https://explorer.citrate.ai${EXPLORER_CALLBACK_PATH}`,
          // Loopback for native/CLI flows (RFC 8252).
          LOOPBACK_REDIRECT,
        ],
        // `offline_access` lets the explorer request a refresh token; combined
        // with the `refresh_token` grant + rotateRefreshToken below that gives
        // rotating refresh tokens (a security must-have).
        scope: 'openid profile wallet offline_access',
      },
    ],
    // `offline_access` is what turns on the `refresh_token` grant_type in panva
    // (lib/helpers/configuration.js): without a refresh-capable scope the
    // provider rejects a client that declares grant_types: ['…','refresh_token'].
    scopes: ['openid', 'profile', 'wallet', 'offline_access'],
    claims: {
      openid: ['sub'],
      profile: ['name', 'email'],
      // Citrate extension: canonical wallet + linked wallets surfaced under the
      // `wallet` scope. Populated by the identity registry in later stages (S3).
      wallet: ['wallet_address', 'wallets'],
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
