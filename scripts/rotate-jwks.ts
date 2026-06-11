/**
 * Ops entrypoint for signing-key rotation (FUA-IDENTITY-06 / KEYSAFE K2).
 *
 *   npm run rotate-key
 *
 * Generates a fresh RS256 signing key, makes it the active signer, and keeps
 * the previous signer published as a verify-only retiring key so outstanding
 * tokens keep verifying for the overlap window. Run it again (at least one
 * ID-token TTL later) to fully retire the old key. See docs/KEY_MANAGEMENT.md.
 *
 * Prints ONLY key ids — never key material.
 */
import { rotateJwks } from '../src/config.js';

const jwks = await rotateJwks();
console.log('[rotate-jwks] rotation complete. published kids (keys[0] signs):');
for (const [i, k] of jwks.keys.entries()) {
  console.log(`  [${i}] ${k.kid}${i === 0 ? '  <- active signer' : '  <- retiring (verify-only)'}`);
}
console.log('[rotate-jwks] restart the authority to pick up the new signer.');
