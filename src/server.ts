import Provider from 'oidc-provider';
import {
  buildConfiguration,
  loadOrCreateJwks,
  siweDomainFromIssuer,
  ISSUER_URL,
  PORT,
} from './config.js';
import { mountSiweRoutes } from './siwe-routes.js';
import { mountKycRoutes } from './kyc-routes.js';
import { createCitratePublicClient } from './siwe.js';
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
  const configuration = await buildConfiguration();
  const provider = new Provider(issuer, configuration);
  // Behind a TLS-terminating proxy (auth.citrate.ai) we trust X-Forwarded-* so
  // discovery advertises https URLs and secure cookies behave.
  provider.proxy = true;

  // SIWE login. The signing JWK is the same RS256 key the authority publishes
  // via JWKS, so direct-path ID tokens verify against `/jwks`.
  const jwks = await loadOrCreateJwks();
  const rpcUrl = options.rpcUrl ?? process.env.CITRATE_RPC_URL;
  const publicClient =
    options.publicClient ??
    (rpcUrl ? createCitratePublicClient(rpcUrl) : undefined);

  mountSiweRoutes(provider, {
    expectedDomain: siweDomainFromIssuer(issuer),
    issuer,
    signingJwk: jwks.keys[0],
    publicClient,
  });

  // IDP-KYC: the vendor-webhook stand-in that writes the LIVE KYC claim record
  // into the store /userinfo reads from. Guarded by KYC_WEBHOOK_SECRET; fails
  // closed when unset. Stores ONLY the claim record — no PII (ADR-2026-06-03).
  mountKycRoutes(provider, options.kycWebhookSecret !== undefined
    ? { webhookSecret: options.kycWebhookSecret }
    : {});

  return provider;
}

/** Boot the authority and listen. Entry point for `npm run dev`. */
async function main(): Promise<void> {
  const provider = await createProvider();
  provider.listen(PORT, () => {
    // eslint-disable-next-line no-console
    console.log(
      `citrate-identity listening on ${ISSUER_URL} — discovery at ${ISSUER_URL}/.well-known/openid-configuration`,
    );
  });
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
