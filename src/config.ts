import {
  readFileSync,
  writeFileSync,
  existsSync,
  mkdirSync,
  statSync,
  chmodSync,
} from 'node:fs';
import { randomUUID } from 'node:crypto';
import { dirname, resolve } from 'node:path';
import { exportJWK, generateKeyPair, type JWK } from 'jose';
import { getAddress, isAddress } from 'viem';
import type { Account, Configuration, FindAccount } from 'oidc-provider';
import { getKycStore, effectiveVerified, type KycStatus } from './kyc.js';
import { getUserStore } from './auth/stores.js';
import { resolveEntitlementClaim, ENTITLEMENT_CLAIM } from './entitlements.js';
import { predictedWalletForAccount } from './aa/wallet-claims.js';
import { getWalletRegistry } from './identity-registry.js';
import { createRedisAdapterFactory } from './redis-adapter.js';
import type { RedisLike } from './redis.js';

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

/**
 * The memrizz relying party's web origin (the federated agent-memory webapp,
 * formerly "Mnemosyne"). Mirrors {@link EXPLORER_ORIGIN}: memrizz completes login
 * by redirecting the browser to `${MEMRIZZ_ORIGIN}/auth/callback`, so that path is
 * what must be registered as a redirect_uri (and echoed for CORS). Defaults to the
 * local dev memrizz on :3003; production sets MEMRIZZ_ORIGIN=https://memrizz.citrate.ai.
 */
export const MEMRIZZ_ORIGIN =
  process.env.MEMRIZZ_ORIGIN ?? 'http://localhost:3003';

/**
 * The citrate-buyer-webapp relying party's web origin (AUTHSPINE S3-WP1). Mirrors
 * {@link EXPLORER_ORIGIN}: the buyer app completes login by redirecting the browser
 * to `${BUYER_WEBAPP_ORIGIN}/auth/callback`, so that path must be a registered
 * redirect_uri. Dev default :3004 (explorer 3001 / dashboard 3002 / memrizz 3003);
 * production sets BUYER_WEBAPP_ORIGIN to the hosted origin.
 */
export const BUYER_WEBAPP_ORIGIN =
  process.env.BUYER_WEBAPP_ORIGIN ?? 'http://localhost:3004';

/**
 * The Citrate Atlas docs app's web origin (citrate-docs, deployed at
 * `docs.citrate.ai` / `citrate-atlas.vercel.app`). Atlas completes login by
 * redirecting the browser to `${ATLAS_ORIGIN}/api/auth/callback` — a Next.js API
 * route, so the path is `/api/auth/callback`, NOT the `/auth/callback` the other
 * web RPs use. Defaults to local dev on :3000; production sets
 * ATLAS_ORIGIN=https://docs.citrate.ai.
 */
export const ATLAS_ORIGIN =
  process.env.ATLAS_ORIGIN ?? 'http://localhost:3000';

/**
 * The investor data room's web origin (citrate-dataroom, deployed at
 * `dataroom.citrate.ai` / `citrate-dataroom.vercel.app`). The data room drives
 * the access flow on a custom path and completes login by redirecting the
 * browser to `${DATAROOM_ORIGIN}/access/callback` — NOT the `/auth/callback`
 * the other web RPs use, and NOT Atlas's `/api/auth/callback`. Defaults to local
 * dev on :3000; production sets DATAROOM_ORIGIN=https://dataroom.citrate.ai.
 */
export const DATAROOM_ORIGIN =
  process.env.DATAROOM_ORIGIN ?? 'http://localhost:3000';

/**
 * Web origin of the citrate-studio relying party, when it runs as a hosted web
 * surface (the native shell uses loopback PKCE and needs no CORS). Optional —
 * only added to the CORS allow-list when set. No dev default: studio is native
 * first, so an unset value simply means "no studio web origin to allow".
 */
export const STUDIO_ORIGIN = process.env.STUDIO_ORIGIN;

/**
 * WalletConnect Cloud project id, surfaced to the SIWE interaction page so it can
 * initialise `@walletconnect/ethereum-provider` (the QR / mobile-wallet connector)
 * for chain {@link CITRATE_CHAIN_ID}. OPTIONAL and NOT fail-closed: when unset the
 * interaction page hides the WalletConnect button and only the injected
 * (`window.ethereum`) connector is offered — injected login keeps working. Get one
 * free at https://cloud.reown.com (formerly WalletConnect Cloud).
 */
export const WALLETCONNECT_PROJECT_ID = process.env.WALLETCONNECT_PROJECT_ID;

/**
 * The citrate-wallet-extension's Chrome-identity redirect URI (EW-S1
 * WP-9). `chrome.identity.launchWebAuthFlow` redirects to
 * `https://<extension-id>.chromiumapp.org/auth/callback`; the id is
 * install-specific, so the deployment registers the exact value here.
 * OPTIONAL and not fail-closed: unset simply means the extension RP
 * client is not registered on this authority instance.
 */
export const WALLET_EXTENSION_REDIRECT_URI =
  process.env.WALLET_EXTENSION_REDIRECT_URI;

/**
 * The RP web origins the authority echoes for CORS on its cross-origin routes
 * (`/siwe/*` Path B, `/sessions/events`, `/token`, `/userinfo`, `/jwks`,
 * `/me`, introspection/revocation). Only these exact origins are echoed back in
 * `Access-Control-Allow-Origin`; everything else gets no CORS headers (we never
 * open `*`). The authority's OWN origin is implicitly same-origin and does not
 * need to be listed. `STUDIO_ORIGIN` is included only when configured.
 *
 * Built once at module load from the resolved origin env vars.
 */
export const ALLOWED_CORS_ORIGINS: ReadonlySet<string> = new Set(
  [
    EXPLORER_ORIGIN,
    DASHBOARD_ORIGIN,
    STUDIO_ORIGIN,
    MEMRIZZ_ORIGIN,
    ATLAS_ORIGIN,
    DATAROOM_ORIGIN,
    BUYER_WEBAPP_ORIGIN,
  ].filter(
    (o): o is string => typeof o === 'string' && o.trim() !== '',
  ),
);

/** True iff `origin` is an allow-listed RP origin permitted to make CORS calls. */
export function isAllowedCorsOrigin(origin: string | undefined): boolean {
  return origin !== undefined && ALLOWED_CORS_ORIGINS.has(origin);
}

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
  // citrate-studio — the native agent-harness shell (Rust + Slint). PUBLIC
  // native client using the loopback PKCE flow (RFC 8252). First-party,
  // Citrate-owned end-to-end, so consent is auto-granted like the web RPs.
  'citrate-studio',
  // memrizz — the federated agent-memory webapp (formerly "Mnemosyne"). PUBLIC
  // web client (Authorization Code + PKCE). First-party, Citrate-owned, so
  // consent is auto-granted like the other web RPs.
  'memrizz',
  // citrate-atlas — the Citrate Atlas documentation app (citrate-docs). PUBLIC web
  // client (Authorization Code + PKCE). First-party, Citrate-owned end-to-end.
  'citrate-atlas',
  // citrate-dataroom — the investor data room (dataroom.citrate.ai). PUBLIC web
  // client (Authorization Code + PKCE). First-party, Citrate-owned end-to-end, so
  // the investor is not shown a consent screen for our own room.
  'citrate-dataroom',
  // citrate-buyer-webapp — the marketplace buyer app (AUTHSPINE S3-WP1). PUBLIC web
  // client (Authorization Code + PKCE); identity on the spine, Privy kept only as the
  // wallet/signer. First-party, Citrate-owned end-to-end → consent auto-granted.
  'citrate-buyer-webapp',
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
 * a fresh RS256 key is generated and written. Tests use ephemeral keys (either
 * via the explicit `path` argument or the `JWKS_PATH` env override). Read at
 * call time (not module load) so tests/ops can repoint it.
 */
function defaultJwksPath(): string {
  return process.env.JWKS_PATH
    ? resolve(process.env.JWKS_PATH)
    : resolve(process.cwd(), '.keys/jwks.json');
}

/** Private-key material on disk must be owner-read/write only. */
const JWKS_FILE_MODE = 0o600;

/**
 * How many JWKs stay published at once. Exactly two: the active signer
 * (`keys[0]`) plus one published-but-retiring verify-only key, giving every
 * rotation an overlap window in which tokens signed by the previous key still
 * verify against `/jwks` (FUA-IDENTITY-06).
 */
const MAX_PUBLISHED_JWKS = 2;

interface PersistedJwks {
  keys: JWK[];
}

/**
 * Assert the on-disk JWKS is mode 0600, repairing it when it is not.
 * FAIL CLOSED: if the mode cannot be restricted (chmod throws, or the
 * repaired mode still is not 0600) the authority must not boot with a
 * world/group-readable private key, so we throw. POSIX-only — Windows has
 * no comparable mode bits (ACLs govern access there).
 */
function assertJwksFileMode(path: string): void {
  if (process.platform === 'win32') return;
  const mode = statSync(path).mode & 0o777;
  if (mode === JWKS_FILE_MODE) return;
  chmodSync(path, JWKS_FILE_MODE); // throws → fail closed
  const repaired = statSync(path).mode & 0o777;
  if (repaired !== JWKS_FILE_MODE) {
    throw new Error(
      `JWKS file ${path} has mode 0${repaired.toString(8)} and could not be ` +
        `restricted to 0600 — refusing to use a readable signing key`,
    );
  }
}

/** Persist the private JWKS with 0600 enforced (create and rewrite paths). */
function persistJwks(jwks: PersistedJwks, path: string): void {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  // `mode` only applies when the file is created; assert/repair covers the
  // rewrite-of-existing-file path.
  writeFileSync(path, JSON.stringify(jwks, null, 2), {
    encoding: 'utf8',
    mode: JWKS_FILE_MODE,
  });
  assertJwksFileMode(path);
}

/** Generate a fresh RS256 signing JWK with a unique `kid`. */
async function generateSigningJwk(): Promise<JWK> {
  const { privateKey } = await generateKeyPair('RS256', { extractable: true });
  const jwk = await exportJWK(privateKey);
  jwk.use = 'sig';
  jwk.alg = 'RS256';
  // Date.now() alone can collide when a rotation happens in the same
  // millisecond as the original generation; suffix with randomness.
  jwk.kid = `citrate-${Date.now()}-${randomUUID().slice(0, 8)}`;
  return jwk;
}

/**
 * Load an RS256 JWKS from disk, or generate one and persist it. Returns the
 * private JWKS in the shape oidc-provider expects (`jwks.keys`).
 *
 * Invariants (FUA-IDENTITY-06):
 *  - `keys[0]` is the ACTIVE signing key (panva signs with the first suitable
 *    key; the SIWE direct path is handed `keys[0]` explicitly).
 *  - Any further keys are published-but-retiring: served by `/jwks` so
 *    outstanding tokens keep verifying, never used to sign.
 *  - The file is asserted/repaired to mode 0600 on every load, failing closed
 *    when it cannot be restricted.
 */
export async function loadOrCreateJwks(
  path: string = defaultJwksPath(),
): Promise<PersistedJwks> {
  if (existsSync(path)) {
    assertJwksFileMode(path);
    const raw = readFileSync(path, 'utf8');
    const parsed = JSON.parse(raw) as PersistedJwks;
    if (Array.isArray(parsed.keys) && parsed.keys.length > 0) {
      return parsed;
    }
  }

  const jwks: PersistedJwks = { keys: [await generateSigningJwk()] };
  persistJwks(jwks, path);
  return jwks;
}

/**
 * Rotate the signing key with an overlap window (FUA-IDENTITY-06): a fresh
 * JWK becomes the active signer (`keys[0]`) while the previous signer stays
 * published as a verify-only retiring key. A subsequent rotation drops it —
 * the publish window is {@link MAX_PUBLISHED_JWKS} keys deep, so run two
 * rotations at least one ID-token TTL apart to fully retire a key. Ops
 * entrypoint: `npm run rotate-key` (see `docs/KEY_MANAGEMENT.md`).
 */
export async function rotateJwks(
  path: string = defaultJwksPath(),
): Promise<PersistedJwks> {
  const current = await loadOrCreateJwks(path);
  const next: PersistedJwks = {
    keys: [await generateSigningJwk(), ...current.keys].slice(
      0,
      MAX_PUBLISHED_JWKS,
    ),
  };
  persistJwks(next, path);
  return next;
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
  /** Hosted memrizz web origin (formerly Mnemosyne). Widens CORS and is the
   * memrizz RP redirect origin; validated for a local host like the others. */
  MEMRIZZ_ORIGIN?: string;
  /** Hosted Citrate Atlas web origin (docs.citrate.ai). Widens CORS + is the Atlas
   * RP redirect origin; validated for a local host like the others. */
  ATLAS_ORIGIN?: string;
  /** Hosted investor data-room web origin (dataroom.citrate.ai). Widens CORS + is
   * the data-room RP redirect origin; validated for a local host like the others. */
  DATAROOM_ORIGIN?: string;
  /**
   * Optional hosted citrate-studio web origin. Only used to widen the CORS
   * allow-list; never required (studio is native-first). Validated for a local
   * host the same way the other RP origins are when present.
   */
  STUDIO_ORIGIN?: string;
  /**
   * Optional WalletConnect Cloud project id for the QR / mobile connector on the
   * SIWE interaction page. NOT fail-closed: unset simply hides the WalletConnect
   * button (injected login still works), so the prod gate never requires it.
   */
  WALLETCONNECT_PROJECT_ID?: string;
  /**
   * Postgres connection string backing the KYC claim store (TD-2). Unset is fine
   * in dev (in-memory store + a warning); in production it MUST be set or the
   * authority refuses to boot — see {@link assertProductionConfig}.
   */
  DATABASE_URL?: string;
  /**
   * Redis connection string backing the HA / restart-safe authority state: the
   * panva persistent adapter (sessions/grants/tokens/interactions), the
   * single-use SIWE nonce store, and the cross-instance logout session bus.
   * Unset is fine in dev (in-memory nonce/bus + panva's in-memory adapter + a
   * warning); in production it MUST be set or the authority refuses to boot
   * (same posture as DATABASE_URL / COOKIE_KEYS) — see
   * {@link assertProductionConfig}.
   */
  REDIS_URL?: string;
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
 *   - EXPLORER_ORIGIN or DASHBOARD_ORIGIN points at a localhost / loopback host;
 *   - DATABASE_URL is unset (TD-2: KYC claims would land in a volatile in-memory
 *     Map — data loss on restart, no multi-instance — instead of a database).
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
  if (isLocalUrl(env.MEMRIZZ_ORIGIN)) {
    problems.push(
      `MEMRIZZ_ORIGIN points at a local host: ${env.MEMRIZZ_ORIGIN}`,
    );
  }
  if (isLocalUrl(env.ATLAS_ORIGIN)) {
    problems.push(
      `ATLAS_ORIGIN points at a local host: ${env.ATLAS_ORIGIN}`,
    );
  }
  if (isLocalUrl(env.DATAROOM_ORIGIN)) {
    problems.push(
      `DATAROOM_ORIGIN points at a local host: ${env.DATAROOM_ORIGIN}`,
    );
  }
  // STUDIO_ORIGIN is optional (studio is native-first). Only validate it when
  // present — an unset value is never a problem, but a local one in prod is.
  if (env.STUDIO_ORIGIN && isLocalUrl(env.STUDIO_ORIGIN)) {
    problems.push(
      `STUDIO_ORIGIN points at a local host: ${env.STUDIO_ORIGIN}`,
    );
  }

  // --- DATABASE_URL (TD-2) ---
  // Fail closed in production when the KYC store has no database to back it: an
  // unset DATABASE_URL would silently fall back to the in-memory Map (data loss
  // on restart, no multi-instance). Same posture as COOKIE_KEYS.
  if (!env.DATABASE_URL || env.DATABASE_URL.trim() === '') {
    problems.push(
      'DATABASE_URL is unset (KYC claims would use the in-memory store — data ' +
        'loss on restart, no multi-instance; TD-2)',
    );
  }

  // --- REDIS_URL (HA / restart-safe) ---
  // Fail closed in production when there is no Redis to back the persistent panva
  // adapter + single-use nonce + cross-instance logout bus: an unset REDIS_URL
  // would silently fall back to in-memory state (sessions/grants/tokens lost on
  // restart, nonces only single-instance, logout not cascading across instances).
  // Same posture as DATABASE_URL / COOKIE_KEYS.
  if (!env.REDIS_URL || env.REDIS_URL.trim() === '') {
    problems.push(
      'REDIS_URL is unset (sessions/grants/tokens would use panva\'s in-memory ' +
        'adapter and nonces/logout-bus would be in-process — state lost on ' +
        'restart, not multi-instance / HA)',
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

/** Matches a canonical lowercase UUID (the shape `users.id` takes). */
const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/**
 * Live KYC claim fields for an OIDC accountId, read fresh at claims() time.
 *
 * The KYC store is keyed on the OIDC accountId — which `/kyc/start` (WP-C)
 * hands the vendor as `externalUserId`, and which the `/kyc/_set` webhook
 * writes back under. For SIWE subs the accountId IS the EIP-55 address; for
 * UUID-keyed subs (passkey / email-pw / Google) it is the user UUID. Either
 * way one human → one key → one KYC record, so both account shapes resolve
 * verification identically (COMP-S1 seam, unblocked once EW-S1 gave every
 * account shape a wallet). panva calls claims() afresh per /userinfo, so a
 * revoke or an expiry that lands after a token was minted is reflected on the
 * next call.
 */
async function kycClaimFields(accountId: string): Promise<{
  kyc_status: KycStatus | 'none' | 'expired';
  kyc_verified_at?: string;
  kyc_expires_at?: string;
}> {
  const claim = await getKycStore().get(accountId);
  const kyc_status: KycStatus | 'none' | 'expired' = claim
    ? effectiveVerified(claim)
      ? 'verified'
      : claim.status === 'verified'
        ? 'expired'
        : claim.status
    : 'none';
  return {
    kyc_status,
    kyc_verified_at: claim?.verified_at,
    kyc_expires_at: claim?.expires_at,
  };
}

/**
 * The `wallets` claim (IDP-S3): the identity's primary wallet first,
 * then every registry-linked wallet (proof-verified, in link order,
 * deduped). Read at claims() time so links/unlinks reflect on the next
 * /userinfo call without re-login.
 */
async function linkedWalletsFor(
  sub: string,
  primary: string | undefined,
): Promise<string[]> {
  const out: string[] = [];
  const seen = new Set<string>();
  if (primary) {
    out.push(primary);
    seen.add(primary.toLowerCase());
  }
  for (const w of await getWalletRegistry().list(sub)) {
    if (!seen.has(w.address)) {
      out.push(getAddress(w.address));
      seen.add(w.address);
    }
  }
  return out;
}

/**
 * Account resolver — both SIWE (wallet-bound) and password / WebAuthn
 * (user-UUID-bound).
 *
 * Two `sub` shapes flow through here:
 *
 *   - EIP-55 wallet address (SIWE, IDP-S1.5). The wallet IS the identity:
 *     `wallet_address` + `wallets` are populated from `sub`. KYC is keyed
 *     on the address.
 *   - User UUID (WP-6 email/password + WebAuthn). Identity is the user
 *     record; no wallet binding yet (the user enrolls a Citrate smart
 *     wallet later from the dashboard, after which `primary_wallet` will
 *     populate the wallet claims). `wallet_address` / `wallets` are
 *     omitted; KYC is not yet looked up for UUID subs (they have no
 *     wallet to key on).
 *
 * Both the OIDC interaction-resume path and the direct-token path call
 * this, so claims are identical regardless of how the login was driven.
 */
export const findAccount: FindAccount = (_ctx, sub): Account => {
  const isUuid = UUID_RE.test(sub);
  const accountId = isUuid ? sub : isAddress(sub) ? getAddress(sub) : sub;
  return {
    accountId,
    async claims() {
      if (isUuid) {
        // UUID-keyed user (passkey / email-pw / Google sign-in). Per
        // EW-S1 the smart wallet exists counterfactually from signup:
        // `wallet_address` is the CREATE2 prediction for this userId
        // (deployed lazily on the first UserOp), unless the user has
        // explicitly bound a wallet (`primary_wallet`), which wins.
        // When the AA env is not configured (dev), the claim is
        // omitted and RPs treat absence as "no wallet bound".
        // `signing_method` is the most recent successful sign-in
        // method persisted by the auth routes; per-session method
        // remains the standard `amr` claim. KYC is not yet keyed on
        // UUIDs (the vendor attaches verification to a wallet).
        const rec = await getUserStore().findById(accountId);
        const wallet = rec?.primaryWallet
          ? getAddress(rec.primaryWallet)
          : predictedWalletForAccount(accountId);
        const linked = await linkedWalletsFor(accountId, wallet);
        // KYC is keyed on the OIDC accountId (the UUID here), which is exactly
        // the `externalUserId` /kyc/start handed the vendor. Surface it live —
        // the smart wallet exists counterfactually from signup, so a UUID-keyed
        // user is as KYC-able as a SIWE one (COMP-S1 seam, post-EW-S1).
        const kyc = await kycClaimFields(accountId);
        // Centralized access tier (DGX_AUTHSPINE §3): mint the entitlement claim
        // from the entitlements roster (KYC-gated). Absent → RP resolves Public.
        const ent = await resolveEntitlementClaim(
          accountId,
          wallet ?? null,
          rec?.email ?? null,
          kyc.kyc_status,
        );
        return {
          sub: accountId,
          // `email`/`email_verified` (OIDC standard, under the `profile` map) —
          // emitted for UUID accounts that have an email (email-pw / Google).
          // RPs (e.g. the data room) read these; absent for passkey-only or SIWE.
          ...(rec?.email
            ? { email: rec.email, email_verified: rec.emailVerified }
            : {}),
          ...(wallet ? { wallet_address: wallet } : {}),
          ...(linked.length > 0 ? { wallets: linked } : {}),
          ...(rec?.lastSigningMethod
            ? { signing_method: rec.lastSigningMethod }
            : {}),
          ...kyc,
          ...(ent ? { [ENTITLEMENT_CLAIM]: ent } : {}),
        };
      }
      // Wallet-bound path (SIWE). Same live KYC read as the UUID path, keyed
      // on the accountId (here the EIP-55 address).
      const kyc = await kycClaimFields(accountId);
      const ent = await resolveEntitlementClaim(
        accountId,
        accountId,
        null,
        kyc.kyc_status,
      );
      return {
        sub: accountId,
        wallet_address: accountId,
        wallets: await linkedWalletsFor(accountId, accountId),
        signing_method: 'siwe',
        ...kyc,
        ...(ent ? { [ENTITLEMENT_CLAIM]: ent } : {}),
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
 *
 * @param redis when provided (REDIS_URL set), the persistent {@link RedisAdapter}
 *   is installed so sessions/grants/tokens/interactions survive restart and work
 *   multi-instance. When omitted (dev) panva's default in-memory adapter is used,
 *   leaving the existing single-instance behaviour unchanged.
 */
export async function buildConfiguration(
  redis?: RedisLike,
): Promise<Configuration> {
  const jwks = await loadOrCreateJwks();

  return {
    jwks,
    // HA / restart-safe: persist all authority state in Redis when configured.
    // Omitting `adapter` (dev, no REDIS_URL) keeps panva's in-memory adapter.
    ...(redis ? { adapter: createRedisAdapterFactory(redis) } : {}),
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
      {
        // citrate-buyer-webapp — the marketplace buyer app (AUTHSPINE S3-WP1).
        // Same posture as explorer/dashboard: PUBLIC client (no secret),
        // Authorization Code + PKCE (S256, enforced globally below), rotating
        // refresh tokens via offline_access. Identity is on the spine; Privy is
        // retained only as the in-app wallet/signer (it never talks to /token).
        client_id: 'citrate-buyer-webapp',
        token_endpoint_auth_method: 'none',
        application_type: 'web',
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
        redirect_uris: [
          // Web callback for the configured (local/dev) buyer-webapp origin.
          `${BUYER_WEBAPP_ORIGIN}${CALLBACK_PATH}`,
          // Hosted buyer-webapp (Vercel) — replace/extend when a custom
          // *.citrate.ai domain lands (set BUYER_WEBAPP_ORIGIN to it).
          `https://citrate-buyer-webapp.vercel.app${CALLBACK_PATH}`,
          // Loopback for native/CLI flows (RFC 8252).
          LOOPBACK_REDIRECT,
        ],
        post_logout_redirect_uris: [
          BUYER_WEBAPP_ORIGIN,
          `${BUYER_WEBAPP_ORIGIN}/`,
          'https://citrate-buyer-webapp.vercel.app',
          'https://citrate-buyer-webapp.vercel.app/',
        ],
        scope: 'openid profile wallet kyc offline_access',
      },
      {
        // memrizz — the federated agent-memory webapp (formerly "Mnemosyne").
        // Hosted web RP, same posture as explorer/dashboard: PUBLIC client (no
        // secret), Authorization Code + PKCE (S256, enforced globally below),
        // rotating refresh tokens via offline_access. The Vercel BFF forwards the
        // user's id_token (aud = client_id `memrizz`) to mem-gateway, which
        // independently re-verifies it (iss + aud + exp, RS256) — so this
        // client_id and the gateway's OIDC_AUDIENCE must stay in lockstep.
        client_id: 'memrizz',
        token_endpoint_auth_method: 'none',
        application_type: 'web',
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
        redirect_uris: [
          // Web callback for the configured (local/dev) memrizz origin.
          `${MEMRIZZ_ORIGIN}${CALLBACK_PATH}`,
          // Hosted production memrizz.
          `https://memrizz.citrate.ai${CALLBACK_PATH}`,
          // Loopback for native/CLI flows (RFC 8252).
          LOOPBACK_REDIRECT,
        ],
        // RP-initiated logout (GET /session/end, or the /logout alias) lands the
        // browser back on memrizz once the session ends. panva matches these
        // exactly, so register the bare origins (with + without trailing slash).
        post_logout_redirect_uris: [
          MEMRIZZ_ORIGIN,
          `${MEMRIZZ_ORIGIN}/`,
          'https://memrizz.citrate.ai',
          'https://memrizz.citrate.ai/',
        ],
        scope: 'openid profile wallet kyc offline_access',
      },
      {
        // citrate-atlas — the Citrate Atlas documentation app (citrate-docs),
        // hosted at docs.citrate.ai (+ citrate-atlas.vercel.app). Hosted web RP,
        // PUBLIC client (no secret), Authorization Code + PKCE (S256), rotating
        // refresh tokens via offline_access. NOTE the callback is the Next.js API
        // route `/api/auth/callback`, NOT the `/auth/callback` the other web RPs
        // use. Its `aud` is the client_id `citrate-atlas` (Atlas enforces aud).
        client_id: 'citrate-atlas',
        token_endpoint_auth_method: 'none',
        application_type: 'web',
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
        redirect_uris: [
          // Configured (local/dev) Atlas origin.
          `${ATLAS_ORIGIN}/api/auth/callback`,
          // Hosted production Atlas — custom domain + the Vercel alias.
          'https://docs.citrate.ai/api/auth/callback',
          'https://citrate-atlas.vercel.app/api/auth/callback',
        ],
        post_logout_redirect_uris: [
          ATLAS_ORIGIN,
          `${ATLAS_ORIGIN}/`,
          'https://docs.citrate.ai',
          'https://docs.citrate.ai/',
          'https://citrate-atlas.vercel.app',
          'https://citrate-atlas.vercel.app/',
        ],
        scope: 'openid profile wallet kyc offline_access',
      },
      {
        // citrate-dataroom — the investor data room, hosted at dataroom.citrate.ai
        // (+ the citrate-dataroom.vercel.app alias, kept for pre-DNS / preview
        // testing). Hosted web RP, PUBLIC client (no secret), Authorization Code +
        // PKCE (S256), rotating refresh tokens via offline_access. NOTE the callback
        // is the data room's custom path `/access/callback` — NOT `/auth/callback`
        // (the other web RPs) and NOT `/api/auth/callback` (atlas). Its `aud` is the
        // client_id `citrate-dataroom`, which the room re-verifies server-side.
        client_id: 'citrate-dataroom',
        token_endpoint_auth_method: 'none',
        application_type: 'web',
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
        redirect_uris: [
          // Configured (local/dev) data-room origin.
          `${DATAROOM_ORIGIN}/access/callback`,
          // Hosted production data room — custom domain + the Vercel alias.
          'https://dataroom.citrate.ai/access/callback',
          'https://citrate-dataroom.vercel.app/access/callback',
        ],
        post_logout_redirect_uris: [
          DATAROOM_ORIGIN,
          `${DATAROOM_ORIGIN}/`,
          'https://dataroom.citrate.ai',
          'https://dataroom.citrate.ai/',
          'https://citrate-dataroom.vercel.app',
          'https://citrate-dataroom.vercel.app/',
        ],
        scope: 'openid profile wallet kyc offline_access',
      },
      {
        // citrate-studio — the native agent-harness shell (Rust + Slint).
        // application_type: 'native' tells panva to apply RFC 8252 loopback
        // rules: a 127.0.0.1 / localhost redirect matches regardless of the
        // ephemeral port the app binds at runtime, which is exactly the native
        // loopback PKCE flow (see ADR-2026-06-04-auth-oidc-siwe in
        // citrate-studio). PUBLIC client (no secret), PKCE S256 enforced
        // globally below, rotating refresh tokens via offline_access.
        client_id: 'citrate-studio',
        token_endpoint_auth_method: 'none',
        application_type: 'native',
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
        redirect_uris: [
          // RFC 8252 loopback — panva matches any ephemeral port for these
          // 127.0.0.1 / localhost hosts when application_type is 'native'.
          `http://127.0.0.1${CALLBACK_PATH}`,
          `http://localhost${CALLBACK_PATH}`,
          // The fixed-port loopback (shared with the web RPs) as a fallback.
          LOOPBACK_REDIRECT,
        ],
        scope: 'openid profile wallet kyc offline_access',
      },
      {
        // citrate-gui-native — the Tauri/Slint desktop wallet (EW-S1
        // WP-8 "Link this device"). Same RFC 8252 native posture as
        // citrate-studio: PUBLIC client, loopback redirects on any
        // ephemeral port, PKCE S256 enforced globally, rotating
        // refresh tokens via offline_access.
        client_id: 'citrate-gui-native',
        token_endpoint_auth_method: 'none',
        application_type: 'native',
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
        redirect_uris: [
          `http://127.0.0.1${CALLBACK_PATH}`,
          `http://localhost${CALLBACK_PATH}`,
          LOOPBACK_REDIRECT,
        ],
        scope: 'openid profile wallet kyc offline_access',
      },
      // citrate-wallet-extension — Chrome MV3 popup (EW-S1 WP-9 "Link
      // this wallet"). chrome.identity.launchWebAuthFlow redirects to
      // the install-specific https://<ext-id>.chromiumapp.org URI, so
      // the client only registers when the deployment pins that URI
      // via WALLET_EXTENSION_REDIRECT_URI. PUBLIC client + PKCE S256.
      ...(WALLET_EXTENSION_REDIRECT_URI
        ? [
            {
              client_id: 'citrate-wallet-extension',
              token_endpoint_auth_method: 'none' as const,
              application_type: 'web' as const,
              grant_types: ['authorization_code', 'refresh_token'],
              response_types: ['code' as const],
              redirect_uris: [WALLET_EXTENSION_REDIRECT_URI],
              scope: 'openid profile wallet kyc offline_access',
            },
          ]
        : []),
    ],
    // `offline_access` is what turns on the `refresh_token` grant_type in panva
    // (lib/helpers/configuration.js): without a refresh-capable scope the
    // provider rejects a client that declares grant_types: ['…','refresh_token'].
    scopes: ['openid', 'profile', 'wallet', 'kyc', 'offline_access'],
    claims: {
      // `https://citrate.ai/entitlement` rides under `openid` (always granted) so
      // every RP gets the centralized access tier in the id_token without having
      // to request an extra scope. Minted only when the principal is on the
      // entitlements roster; absent otherwise (RP falls back to Public).
      openid: ['sub', ENTITLEMENT_CLAIM],
      profile: ['name', 'email', 'email_verified'],
      // Citrate extension: canonical wallet + linked wallets + the most
      // recent signing method, surfaced under the `wallet` scope (EW-S1
      // WP-6 seam — explorer/dashboard RPs + Lane B's PIN-S4 consume this
      // shape; keep it stable). Linked-wallets list grows in IDP-S3.
      wallet: ['wallet_address', 'wallets', 'signing_method'],
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
      // panva defaults `_interaction` to `path=/interaction/<uid>` and
      // `_interaction_resume` to `path=/auth/<uid>`. That breaks every
      // sign-in flow whose form-submit hits a NON-`/interaction/<uid>/...`
      // route: a browser respects cookie path, so a `POST /siwe/verify` or
      // `POST /auth/password/register` from the interaction page arrives
      // *without* the cookie — `provider.interactionDetails` returns
      // `undefined`, the route bails with "no active interaction", sign-in
      // fails. Widening the path to `/` lets the cookie ride every same-
      // origin request to `auth.citrate.ai`. CSRF defense stays the
      // standard `HttpOnly` + `Secure` + `SameSite=lax` — `lax` already
      // blocks cross-origin POST abuse.
      long: { path: '/' },
      short: { path: '/' },
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
      // IDP-S2 / TD-5: token introspection is how a relying party (and our logout
      // test) asks the authority whether a token is still active. After /logout
      // revokes a token, introspection reports { active: false } — that is the
      // "invalidates a token immediately" guarantee the cascade depends on.
      //
      // FUA-IDENTITY-08 (SECREM-02): every RP is a PUBLIC client
      // (token_endpoint_auth_method 'none'), so we cannot rely on client-secret
      // auth to scope introspection. Pin an explicit allowedPolicy: a client may
      // introspect ONLY tokens issued to itself — a caller asserting another
      // client's id gets { active: false }, closing the cross-client
      // token-activity probe. An RP checking its own token (the logout cascade)
      // is unaffected, since there token.clientId === client.clientId.
      introspection: {
        enabled: true,
        allowedPolicy: async (
          _ctx: unknown,
          client: { clientId: string },
          token: { clientId?: string },
        ): Promise<boolean> => token.clientId === client.clientId,
      },
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
