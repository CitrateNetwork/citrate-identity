import Provider from 'oidc-provider';
import { buildConfiguration, ISSUER_URL, PORT } from './config.js';

/**
 * Construct the Citrate OIDC authority Provider. Exposed as a factory so tests
 * can mount it on an ephemeral port without binding a fixed socket.
 */
export async function createProvider(issuer: string = ISSUER_URL): Promise<Provider> {
  const configuration = await buildConfiguration();
  const provider = new Provider(issuer, configuration);
  // Behind a TLS-terminating proxy (auth.citrate.ai) we trust X-Forwarded-* so
  // discovery advertises https URLs and secure cookies behave.
  provider.proxy = true;
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
