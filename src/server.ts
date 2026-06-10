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
import { initKycStoreFromEnv, getKycStore } from './kyc.js';
import { PgKycStore } from './kyc-pg.js';
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
  // via JWKS, so direct-path ID tokens verify against `/jwks`.
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

  mountSiweRoutes(provider, {
    expectedDomain: siweDomainFromIssuer(issuer),
    issuer,
    signingJwk: jwks.keys[0],
    publicClient,
    ...(nonceStore ? { nonceStore } : {}),
    ...(walletConnectProjectId ? { walletConnectProjectId } : {}),
    ...(options.allowDirectTokenGrant ? { allowDirectTokenGrant: true } : {}),
  });

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
