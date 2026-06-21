/**
 * FWA-C6-01 permanent tripwire (Class-A: trust-what-is-signed).
 *
 * A signed id_token proves the IdP ISSUED it, not that the subject owns the
 * `email` it carries. Any federation route that verifies a third-party token
 * (`jwtVerify`) and then reads `email` off the payload to link/create a local
 * account MUST also consult `email_verified` (see trustedEmailFromIdToken).
 *
 * This test statically scans `src/` and FAILS if any file that calls
 * `jwtVerify` reads a `.email` claim but never references `email_verified`.
 * It is dependency-free (runs in the existing `vitest run` gate) and mirrors
 * the semgrep rule in `.semgrep/email-verified-trust.yml` for CI where semgrep
 * is available. A future Google-shaped federation route that forgets the gate
 * trips this red.
 */
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const SRC_ROOT = fileURLToPath(new URL('../../src', import.meta.url));

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) {
      out.push(...walk(full));
    } else if (entry.endsWith('.ts') && !entry.endsWith('.test.ts')) {
      out.push(full);
    }
  }
  return out;
}

describe('FWA-C6-01 tripwire: federation routes must check email_verified', () => {
  it('no jwtVerify consumer reads .email without referencing email_verified', () => {
    const offenders: string[] = [];
    for (const file of walk(SRC_ROOT)) {
      const src = readFileSync(file, 'utf8');
      const verifiesAToken = /\bjwtVerify\s*\(/.test(src);
      if (!verifiesAToken) continue;
      // Reads an email claim off some payload object: `.email` (not part of a
      // longer identifier like `.emailVerified` / `.email_verified`).
      const readsEmailClaim =
        /\.email\b(?!_?[Vv]erified)/.test(src) || /\[['"]email['"]\]/.test(src);
      const checksVerified = /email_verified|emailVerified/.test(src);
      if (readsEmailClaim && !checksVerified) {
        offenders.push(file.replace(SRC_ROOT, 'src'));
      }
    }
    expect(
      offenders,
      `Class-A trust-what-is-signed (FWA-C6-01): these files verify a token and ` +
        `read an email claim but never check email_verified:\n${offenders.join('\n')}`,
    ).toEqual([]);
  });
});
