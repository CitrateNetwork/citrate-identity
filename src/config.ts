import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { exportJWK, generateKeyPair, type JWK } from 'jose';
import type { Configuration } from 'oidc-provider';

/**
 * Public issuer URL. In production: https://auth.citrate.ai
 * For local dev / tests, defaults to http://localhost:3000.
 */
export const ISSUER_URL = process.env.ISSUER_URL ?? 'http://localhost:3000';

/** Listen port. */
export const PORT = Number(process.env.PORT ?? 3000);

/**
 * Loopback redirect placeholder for native/CLI clients (RFC 8252). The actual
 * loopback port is chosen by the native app at runtime; oidc-provider treats any
 * port on a registered 127.0.0.1 loopback redirect as valid, so this concrete
 * placeholder both documents intent and satisfies registration.
 */
const LOOPBACK_REDIRECT = `http://127.0.0.1:${PORT}/callback`;

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
    clients: [
      {
        client_id: 'citrate-explorer',
        // Public client → no secret; PKCE carries the proof-of-possession.
        token_endpoint_auth_method: 'none',
        application_type: 'web',
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
        redirect_uris: [
          // Web callback for the hosted explorer.
          `${ISSUER_URL}/callback`,
          'https://explorer.citrate.ai/callback',
          // Loopback for native/CLI flows (RFC 8252).
          LOOPBACK_REDIRECT,
        ],
        scope: 'openid profile wallet',
      },
    ],
    scopes: ['openid', 'profile', 'wallet'],
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
    features: {
      // Spec-compliant discovery is on by default; refresh + revocation explicit.
      revocation: { enabled: true },
      devInteractions: { enabled: true },
    },
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
