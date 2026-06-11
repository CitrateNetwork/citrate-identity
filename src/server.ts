import Provider from 'oidc-provider';
import {
  assertProductionConfig,
  buildConfiguration,
  loadOrCreateJwks,
  siweDomainFromIssuer,
  ISSUER_URL,
  PORT,
  WALLETCONNECT_PROJECT_ID,
} from './config.js';
import { mountSiweRoutes } from './siwe-routes.js';
import { mountKycRoutes } from './kyc-routes.js';
import { mountLogoutRoutes } from './logout-routes.js';
import { mountHttpExtras } from './http-extras.js';
import { mountAaRoutes } from './aa/aa-routes.js';
import { loadAaConfig } from './aa/config.js';
import { mountStaticAssets } from './static-assets.js';
import { mountPasswordRoutes } from './auth/password-routes.js';
import { mountWebauthnRoutes } from './auth/webauthn-routes.js';
import { mountGoogleRoutes } from './auth/google-routes.js';
import { initAuthStoresFromEnv } from './auth/stores.js';
import { rpIdFromIssuer } from './auth/webauthn.js';
import { initKycStoreFromEnv, getKycStore } from './kyc.js';
import { PgKycStore } from './kyc-pg.js';
import { resolve } from 'node:path';
import { readFileSync } from 'node:fs';

/** Resolve the package version once at boot for the interaction-page footer. */
function readPackageVersion(): string {
  try {
    const raw = readFileSync(
      resolve(process.cwd(), 'package.json'),
      'utf8',
    );
    const parsed = JSON.parse(raw) as { version?: unknown };
    return typeof parsed.version === 'string' ? parsed.version : 'dev';
  } catch {
    return 'dev';
  }
}
import { createCitratePublicClient, type NonceStore } from './siwe.js';
import { RedisNonceStore } from './nonce-redis.js';
import { RedisSessionBus, getSessionBus, setSessionBus } from './session-bus.js';
import { createRedis, type RedisLike } from './redis.js';
import type { PublicClient } from 'viem';

export interface CreateProviderOptions {
  /**
   * RPC URL for EIP-1271 (smart-contract / Safe wallet) signature verification.
   * When set, SIWE verification can check `isValidSignature` on-chain. Reads
   * `CITRATE_RPC_URL` from the environment by default; when absent, only EOA
   * (ECDSA) signatures are accepted and 1271 logins are declined (fail closed).
   */
  rpcUrl?: string;
  /** Inject a viem public client directly (tests). Overrides `rpcUrl`. */
  publicClient?: PublicClient;
  /**
   * Shared secret guarding the KYC vendor-webhook endpoints (POST /kyc/_set,
   * /kyc/_revoke). Overrides `KYC_WEBHOOK_SECRET` from the environment; tests
   * pass it explicitly. When neither is set the endpoints fail closed.
   */
  kycWebhookSecret?: string;
  /**
   * Shared Redis client (HA / restart-safe). When provided, the persistent panva
   * adapter is installed and the SIWE nonce store is Redis-backed. The
   * cross-instance session bus is installed separately at boot (see
   * {@link initRedisFromEnv}). When omitted (dev) the in-memory adapter + nonce
   * store are used, leaving the single-instance behaviour unchanged.
   */
  redis?: RedisLike;
  /**
   * Nonce store override. Defaults to a {@link RedisNonceStore} when `redis` is
   * provided, else mountSiweRoutes falls back to its in-memory store. Tests pass
   * one explicitly.
   */
  nonceStore?: NonceStore;
  /**
   * Override the `/health` Redis probe. Defaults to a round-trip against the
   * `redis` client when one is provided (and omitted entirely otherwise, so the
   * `redis` field is absent from the health body in dev). Tests inject one.
   */
  pingRedis?: () => Promise<boolean>;
  /**
   * Override the `/health` Postgres probe. Defaults to {@link PgKycStore.ping}
   * when the live KYC store is Postgres-backed (omitted otherwise). Tests inject
   * one.
   */
  pingDb?: () => Promise<boolean>;
  /**
   * WalletConnect Cloud project id surfaced to the SIWE interaction page so it
   * offers the QR / mobile connector. Defaults to `WALLETCONNECT_PROJECT_ID` from
   * the environment; when unset the page shows only the injected connector (NOT
   * fail-closed). Tests pass it explicitly to assert both-connectors rendering.
   */
  walletConnectProjectId?: string;
  /**
   * FUA-IDENTITY-01: enable the out-of-band direct ID-token mint on
   * `/siwe/verify` (no PKCE/consent). Off by default (fail closed). When set,
   * `audience` must name a registered first-party client. Browser RPs use the
   * authorization-code flow and never need this; tests of the direct path opt in.
   */
  allowDirectTokenGrant?: boolean;
  /**
   * Override the Google federation tab state on the interaction page. Defaults
   * to `Boolean(CITRATE_AA_GOOGLE_CLIENT_ID)` from the environment. Tests pass
   * `false` explicitly to keep the assertion deterministic regardless of the
   * shell environment, and `true` to assert the active-button rendering.
   */
  googleEnabled?: boolean;
}

/**
 * Select + install the Redis-backed authority state from the environment (HA /
 * restart-safe). Mirrors {@link initKycStoreFromEnv}:
 *
 *   - `REDIS_URL` set  → connect one shared `ioredis` client, install the
 *     cross-instance {@link RedisSessionBus} as the live session bus, and return
 *     the client so the caller can build the {@link RedisNonceStore} + pass the
 *     persistent panva adapter. State survives restarts + is multi-instance.
 *   - `REDIS_URL` unset → return undefined; the in-memory nonce/bus + panva's
 *     in-memory adapter are used (dev), with a one-line warning. In PRODUCTION an
 *     unset REDIS_URL never reaches here: {@link assertProductionConfig} throws
 *     first (fail-closed, same posture as DATABASE_URL).
 *
 * `ioredis` is imported lazily inside {@link createRedis}, so dev/test that use
 * the in-memory path never pull the driver in.
 */
export async function initRedisFromEnv(
  env: { REDIS_URL?: string } = process.env,
): Promise<RedisLike | undefined> {
  const url = env.REDIS_URL;
  if (url && url.trim() !== '') {
    const redis = await createRedis(url);
    const bus = new RedisSessionBus(redis);
    await bus.start();
    setSessionBus(bus);
    return redis;
  }
  // eslint-disable-next-line no-console
  console.warn(
    '[citrate-identity] REDIS_URL unset — using the in-memory OIDC adapter, ' +
      'nonce store, and session bus (authority state is lost on restart and not ' +
      'shared across instances). Set REDIS_URL to back sessions/grants/tokens + ' +
      'nonces + the logout bus with Redis (required in production).',
  );
  return undefined;
}

/**
 * Construct the Citrate OIDC authority Provider. Exposed as a factory so tests
 * can mount it on an ephemeral port without binding a fixed socket. Also mounts
 * the SIWE (EIP-4361) login routes (`/siwe/challenge`, `/siwe/verify`) that log
 * a wallet in as an OIDC account (IDP-S1.5).
 */
export async function createProvider(
  issuer: string = ISSUER_URL,
  options: CreateProviderOptions = {},
): Promise<Provider> {
  // HA / restart-safe: when a Redis client is provided, panva persists all
  // authority state via the RedisAdapter; otherwise its in-memory default (dev).
  const configuration = await buildConfiguration(options.redis);
  const provider = new Provider(issuer, configuration);
  // Behind a TLS-terminating proxy (auth.citrate.ai) we trust X-Forwarded-* so
  // discovery advertises https URLs and secure cookies behave.
  provider.proxy = true;

  // Branded static assets (brand marks + self-hosted fonts) are served from
  // /brand/* and /fonts/*. Mounted FIRST so a request for a font/logo never
  // touches panva's OIDC routing.
  mountStaticAssets(provider, {
    publicRoot: resolve(process.cwd(), 'public'),
  });

  // CORS + /health first, so the cross-origin RP routes carry CORS headers and
  // the liveness probe answers without ever touching panva's OIDC routing.
  //   - Redis probe: a cheap round-trip (EXISTS on a throwaway key) against the
  //     shared client when REDIS_URL wired one; omitted in dev so `redis` is
  //     absent from the body. Swallows errors → false (never throws).
  //   - DB probe: PgKycStore.ping() when the live KYC store is Postgres-backed;
  //     omitted in dev (in-memory store) so `db` is absent.
  const kycStore = getKycStore();
  const defaultPingRedis = options.redis
    ? async (): Promise<boolean> => {
        try {
          await options.redis!.exists('citrate-identity:health-probe');
          return true;
        } catch {
          return false;
        }
      }
    : undefined;
  const defaultPingDb =
    kycStore instanceof PgKycStore
      ? (): Promise<boolean> => kycStore.ping()
      : undefined;
  const pingRedis = options.pingRedis ?? defaultPingRedis;
  const pingDb = options.pingDb ?? defaultPingDb;
  mountHttpExtras(provider, {
    ...(pingRedis ? { pingRedis } : {}),
    ...(pingDb ? { pingDb } : {}),
  });

  // SIWE login. The signing JWK is the same RS256 key the authority publishes
  // via JWKS, so direct-path ID tokens verify against `/jwks`. `keys[0]` is
  // the ACTIVE signer by invariant (loadOrCreateJwks/rotateJwks); any further
  // keys are published-but-retiring verify-only keys kept for the rotation
  // overlap window (FUA-IDENTITY-06).
  const jwks = await loadOrCreateJwks();
  const rpcUrl = options.rpcUrl ?? process.env.CITRATE_RPC_URL;
  const publicClient =
    options.publicClient ??
    (rpcUrl ? createCitratePublicClient(rpcUrl) : undefined);

  // Single-use nonce store: Redis-backed (one-time across instances) when a
  // Redis client is provided, else mountSiweRoutes falls back to in-memory.
  const nonceStore =
    options.nonceStore ??
    (options.redis ? new RedisNonceStore(options.redis) : undefined);

  // WalletConnect: explicit option wins, else the env var. Undefined → the page
  // hides the WalletConnect button (injected still works; not fail-closed).
  const walletConnectProjectId =
    options.walletConnectProjectId ?? WALLETCONNECT_PROJECT_ID;

  // Google federation: ungated UI shows the tab unconditionally with a
  // clear "not enabled" message; the active "Continue with Google" button
  // (and the matching /auth/google/* routes — follow-up WP) only render
  // when CITRATE_AA_GOOGLE_CLIENT_ID is set. No env wired yet anywhere; the
  // flag is plumbed through so the prod deploy can turn it on later.
  // Google federation requires BOTH the public client id (UI gate) AND the
  // server-side secret (route gate). If either is missing the UI renders
  // the "not enabled" copy and `mountGoogleRoutes` is skipped below — both
  // must agree or a user clicks "Continue with Google" and hits a 404.
  const googleEnabled =
    options.googleEnabled ??
    Boolean(
      process.env.CITRATE_AA_GOOGLE_CLIENT_ID &&
        process.env.CITRATE_AA_GOOGLE_CLIENT_SECRET,
    );
  // Footer build version: read once from package.json. Best-effort so dev/test
  // never crash if the file's missing — we just label the build "dev".
  const version = readPackageVersion();

  mountSiweRoutes(provider, {
    expectedDomain: siweDomainFromIssuer(issuer),
    issuer,
    signingJwk: jwks.keys[0],
    publicClient,
    googleEnabled,
    version,
    ...(nonceStore ? { nonceStore } : {}),
    ...(walletConnectProjectId ? { walletConnectProjectId } : {}),
    ...(options.allowDirectTokenGrant ? { allowDirectTokenGrant: true } : {}),
  });

  // EW-S1 WP-6 slice B — email/password + WebAuthn login routes that the
  // branded /interaction/:uid page calls. Read/write the user + credential
  // stores wired by initAuthStoresFromEnv (Postgres in prod, in-memory in
  // dev — same posture as the KYC store).
  mountPasswordRoutes(provider);
  const rpId = rpIdFromIssuer(issuer);
  mountWebauthnRoutes(provider, {
    rp: {
      rpId,
      rpName: 'Citrate',
      // WebAuthn requires the origin match the issuer host; in dev that's
      // http://localhost:PORT, in prod https://auth.citrate.ai.
      expectedOrigin: issuer,
    },
  });

  // EW-S1 WP-6 slice C — Google federation. Mount the OAuth start +
  // callback routes ONLY when both the public client id (also the UI
  // gate) AND the server-side secret are set. Without both, the
  // interaction page falls back to the "not enabled" copy and these
  // routes never register (a hit on /auth/google/start gets a 404
  // from panva's catch-all).
  const googleClientSecret = process.env.CITRATE_AA_GOOGLE_CLIENT_SECRET;
  const googleClientId = process.env.CITRATE_AA_GOOGLE_CLIENT_ID;
  if (googleEnabled && googleClientId && googleClientSecret) {
    mountGoogleRoutes(provider, {
      clientId: googleClientId,
      clientSecret: googleClientSecret,
      // The redirect URI Google compares byte-for-byte against the OAuth
      // client's "Authorized redirect URIs" list. ISSUER_URL is
      // https://auth.citrate.ai in prod and http://localhost:PORT in dev,
      // so the operator just registers `<ISSUER_URL>/auth/google/callback`
      // with Google and we mirror that here.
      redirectUri: `${issuer}/auth/google/callback`,
    });
  } else if (googleEnabled && !googleClientSecret) {
    // eslint-disable-next-line no-console
    console.warn(
      '[citrate-identity] CITRATE_AA_GOOGLE_CLIENT_ID is set but ' +
        'CITRATE_AA_GOOGLE_CLIENT_SECRET is not — Google tab will render as ' +
        '"not enabled" since the routes were not mounted.',
    );
  }

  // IDP-KYC: the vendor-webhook stand-in that writes the LIVE KYC claim record
  // into the store /userinfo reads from. Guarded by KYC_WEBHOOK_SECRET; fails
  // closed when unset. Stores ONLY the claim record — no PII (ADR-2026-06-03).
  mountKycRoutes(provider, options.kycWebhookSecret !== undefined
    ? { webhookSecret: options.kycWebhookSecret }
    : {});

  // IDP-S2 / TD-5 (authority side): POST /logout revokes the presented token,
  // ends its session, and publishes a `logout` on the session bus; GET
  // /sessions/events streams those events to subscribed relying parties (SSE).
  mountLogoutRoutes(provider);

  // EW-S1 WP-5: /aa/* — smart-wallet address prediction + deploy-permit
  // signing for the Citrate ERC-4337 stack. Only enabled when the AA env
  // is set (CITRATE_AA_FACTORY etc.); production refuses to boot via
  // loadAaConfig if the env is partial.
  if (process.env.CITRATE_AA_FACTORY) {
    const aaCfg = loadAaConfig(process.env);
    const rpc = process.env.CITRATE_AA_RPC_URL ?? process.env.CITRATE_RPC_URL ?? 'https://rpc.citrate.ai';
    mountAaRoutes(provider, { config: aaCfg, rpcUrl: rpc });
  }

  return provider;
}

/** Boot the authority and listen. Entry point for `npm run dev`. */
async function main(): Promise<void> {
  // TD-1: fail-closed config gate. In production this THROWS on any deploy-unsafe
  // default (dev cookie key, localhost issuer/origins) so we never boot with a
  // forgeable cookie secret. In dev it returns the same problems as warnings.
  const { warnings } = assertProductionConfig(process.env);
  for (const w of warnings) {
    // eslint-disable-next-line no-console
    console.warn(`[citrate-identity] config warning: ${w}`);
  }

  // TD-2: install the KYC store for this environment. With DATABASE_URL set this
  // connects Postgres and ensures the schema; without it (dev) it warns and uses
  // the in-memory store. assertProductionConfig above already refused to start in
  // production if DATABASE_URL was unset, so this only falls back to memory in dev.
  await initKycStoreFromEnv(process.env);

  // WP-6 WP-B: install the user + WebAuthn credential stores. Same DATABASE_URL
  // gate as KYC — Postgres in prod, in-memory in dev — so /auth/password/* and
  // /auth/webauthn/* persist user records as soon as DATABASE_URL is set.
  await initAuthStoresFromEnv(process.env);

  // HA / restart-safe: install the Redis-backed authority state for this env.
  // With REDIS_URL set this connects one shared client, installs the
  // cross-instance logout bus, and returns the client for the persistent panva
  // adapter + Redis nonce store; without it (dev) it warns and uses the in-memory
  // adapter/nonce/bus. assertProductionConfig already refused to start in
  // production if REDIS_URL was unset, so this only falls back to memory in dev.
  const redis = await initRedisFromEnv(process.env);

  const provider = await createProvider(ISSUER_URL, redis ? { redis } : {});
  const server = provider.listen(PORT, () => {
    // eslint-disable-next-line no-console
    console.log(
      `citrate-identity listening on ${ISSUER_URL} — discovery at ${ISSUER_URL}/.well-known/openid-configuration`,
    );
  });

  // Clean shutdown: stop accepting connections, then close the shared Redis
  // client (and, via the live bus's own close, its dedicated subscriber). On a
  // rolling deploy this lets in-flight requests drain and releases the Redis
  // sockets instead of leaking them until the TCP timeout.
  const shutdown = (signal: string): void => {
    // eslint-disable-next-line no-console
    console.log(`[citrate-identity] ${signal} received — shutting down`);
    server.close(() => {
      void (async () => {
        try {
          const bus = getSessionBus();
          if (bus instanceof RedisSessionBus) await bus.close();
          if (redis) await redis.quit();
        } finally {
          process.exit(0);
        }
      })();
    });
  };
  process.once('SIGTERM', () => shutdown('SIGTERM'));
  process.once('SIGINT', () => shutdown('SIGINT'));
}

// Only auto-listen when run directly (tsx src/server.ts), not when imported by tests.
const invokedDirectly =
  process.argv[1] !== undefined && import.meta.url === `file://${process.argv[1]}`;
if (invokedDirectly) {
  main().catch((err) => {
    // eslint-disable-next-line no-console
    console.error('failed to start citrate-identity', err);
    process.exit(1);
  });
}
