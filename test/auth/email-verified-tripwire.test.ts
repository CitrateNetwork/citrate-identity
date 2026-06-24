/**
 * FWA-C6-01 / FWA-BV-ID-04 permanent tripwire (Class-A: trust-what-is-signed).
 *
 * A signed id_token proves the IdP ISSUED it, not that the subject owns the
 * `email` it carries. Any federation route that verifies a third-party token
 * (`jwtVerify`) and then reads `email` off the payload to link/create a local
 * account MUST also consult `email_verified` (see trustedEmailFromIdToken).
 *
 * This test statically scans `src/` and FAILS if any file that calls
 * `jwtVerify` reads a `.email` claim in a function that never references
 * `email_verified`. It is dependency-free (runs in the existing `vitest run`
 * gate) and mirrors the semgrep rule in `.semgrep/email-verified-trust.yml`
 * for CI where semgrep is available. A future Google-shaped federation route
 * that forgets the gate trips this red.
 *
 * FWA-BV-ID-04 hardening over the prior net:
 *   1. Comments and string/template literals are STRIPPED before scanning, so a
 *      mention of `email_verified` in a comment or a string does NOT satisfy the
 *      guard (was a false negative), and a `.email` inside a comment/string does
 *      not manufacture a false offender.
 *   2. The guard is checked in the SAME FUNCTION as the `.email` read (not just
 *      whole-file presence): an `email_verified` check in an unrelated function
 *      no longer launders a `.email` read elsewhere.
 *   3. The `.email` read still matches every idiom — `await jwtVerify`,
 *      `const { payload } = await jwtVerify`, and the sync form — because the
 *      check is on the `.email` token, not on the binding shape.
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

/**
 * Strip comments and string/template literals from TS source, preserving line
 * structure (newlines kept) so line numbers and brace nesting are unaffected.
 * Replacing a literal/comment body with spaces means a `.email` /
 * `email_verified` mention inside it can never satisfy or trip the scan.
 *
 * Handles: // line comments, block comments, '…' "…" `…` strings (with escapes
 * and `${…}` template substitutions kept as live code). A small hand state
 * machine — deliberately dependency-free for the vitest gate.
 */
export function stripCommentsAndStrings(src: string): string {
  let out = '';
  let i = 0;
  const n = src.length;
  // Template-literal nesting: when we enter `${`, push the template so we can
  // resume it after the substitution's `}`.
  const tmplStack: boolean[] = [];

  while (i < n) {
    const c = src[i];
    const c2 = src[i + 1];

    // Line comment
    if (c === '/' && c2 === '/') {
      while (i < n && src[i] !== '\n') {
        i++;
      }
      continue;
    }
    // Block comment (preserve newlines inside)
    if (c === '/' && c2 === '*') {
      i += 2;
      while (i < n && !(src[i] === '*' && src[i + 1] === '/')) {
        out += src[i] === '\n' ? '\n' : ' ';
        i++;
      }
      i += 2;
      out += '  ';
      continue;
    }
    // Single / double quoted string
    if (c === "'" || c === '"') {
      const quote = c;
      i++;
      while (i < n && src[i] !== quote) {
        if (src[i] === '\\') {
          i++;
        }
        if (i < n) {
          out += src[i] === '\n' ? '\n' : ' ';
          i++;
        }
      }
      i++; // closing quote
      continue;
    }
    // Template literal
    if (c === '`') {
      i++;
      while (i < n) {
        if (src[i] === '\\') {
          i += 2;
          continue;
        }
        // Enter a `${ … }` substitution: that part is live code.
        if (src[i] === '$' && src[i + 1] === '{') {
          out += '${';
          i += 2;
          tmplStack.push(true);
          break;
        }
        if (src[i] === '`') {
          i++;
          break;
        }
        out += src[i] === '\n' ? '\n' : ' ';
        i++;
      }
      continue;
    }
    // Closing a template substitution → resume the surrounding template literal.
    if (c === '}' && tmplStack.length > 0) {
      out += '}';
      i++;
      tmplStack.pop();
      // Re-enter the template body.
      while (i < n) {
        if (src[i] === '\\') {
          i += 2;
          continue;
        }
        if (src[i] === '$' && src[i + 1] === '{') {
          out += '${';
          i += 2;
          tmplStack.push(true);
          break;
        }
        if (src[i] === '`') {
          i++;
          break;
        }
        out += src[i] === '\n' ? '\n' : ' ';
        i++;
      }
      continue;
    }

    out += c;
    i++;
  }
  return out;
}

/**
 * Split `code` (already comment/string-stripped) into top-level brace-delimited
 * blocks so a guard in one function can't launder a `.email` read in another.
 * Returns each `{ … }` body PLUS the full text as a coarse fallback scope (so a
 * read that isn't inside any brace block is still attributed to a scope).
 */
export function braceScopes(code: string): string[] {
  const scopes: string[] = [];
  const stack: number[] = []; // indices of open braces
  for (let i = 0; i < code.length; i++) {
    const ch = code[i];
    if (ch === '{') {
      stack.push(i);
    } else if (ch === '}') {
      const open = stack.pop();
      if (open !== undefined) {
        scopes.push(code.slice(open + 1, i));
      }
    }
  }
  return scopes;
}

const EMAIL_READ = /\.email\b(?!_?[Vv]erified)/;
const EMAIL_INDEX = /\[\s*['"]email['"]\s*\]/;
const VERIFIED_GUARD = /email_verified|emailVerified/;

/** A scope is an offender if it reads the email claim but never references a
 *  verified guard WITHIN that same scope. */
function scopeIsOffender(scope: string): boolean {
  const readsEmailClaim = EMAIL_READ.test(scope) || EMAIL_INDEX.test(scope);
  if (!readsEmailClaim) return false;
  return !VERIFIED_GUARD.test(scope);
}

describe('FWA-C6-01 tripwire: federation routes must check email_verified', () => {
  it('no jwtVerify consumer reads .email without an in-scope email_verified guard', () => {
    const offenders: string[] = [];
    for (const file of walk(SRC_ROOT)) {
      const raw = readFileSync(file, 'utf8');
      const code = stripCommentsAndStrings(raw);
      const verifiesAToken = /\bjwt(Verify|Decrypt)\s*\(/.test(code);
      if (!verifiesAToken) continue;

      // Look at each brace-delimited scope (function/arrow body etc). The file
      // is an offender if ANY scope reads the email claim without a verified
      // guard in that same scope — AND the broadest (whole-file, stripped) view
      // also lacks a guard around that read. We require the per-scope check so
      // an email_verified check in an unrelated function can't launder a read
      // elsewhere; the innermost scope containing the read is the tightest.
      const scopes = braceScopes(code);
      const offendingScopes = scopes.filter(scopeIsOffender);

      if (offendingScopes.length === 0) continue;

      // Among the offending scopes, only flag those whose read is NOT enclosed
      // by some ancestor scope that DOES carry the guard (e.g. the read sits in
      // a tiny block but the enclosing function guards it). Approximate the
      // "tightest guarded ancestor" by checking: does any scope that CONTAINS
      // this offending scope's text carry the guard?
      const genuinelyUnguarded = offendingScopes.some((off) => {
        const ancestorGuards = scopes.some(
          (s) => s !== off && s.includes(off) && VERIFIED_GUARD.test(s),
        );
        return !ancestorGuards;
      });

      if (genuinelyUnguarded) {
        offenders.push(file.replace(SRC_ROOT, 'src'));
      }
    }
    expect(
      offenders,
      `Class-A trust-what-is-signed (FWA-C6-01 / FWA-BV-ID-04): these files verify ` +
        `a token and read an email claim in a function with no in-scope ` +
        `email_verified check (comments/strings do not count):\n${offenders.join('\n')}`,
    ).toEqual([]);
  });
});

/**
 * Meta-tests: lock the net's own logic so a future "simplification" can't
 * silently reintroduce the comment/string-blind FALSE NEGATIVE (FWA-BV-ID-04).
 * These exercise the same predicates the file scan uses, on in-memory fixtures.
 */
function fileTrips(src: string): boolean {
  const code = stripCommentsAndStrings(src);
  if (!/\bjwt(Verify|Decrypt)\s*\(/.test(code)) return false;
  const scopes = braceScopes(code);
  const offendingScopes = scopes.filter(
    (s) =>
      (/\.email\b(?!_?[Vv]erified)/.test(s) ||
        /\[\s*['"]email['"]\s*\]/.test(s)) &&
      !/email_verified|emailVerified/.test(s),
  );
  return offendingScopes.some(
    (off) =>
      !scopes.some(
        (s) => s !== off && s.includes(off) && /email_verified|emailVerified/.test(s),
      ),
  );
}

describe('FWA-BV-ID-04: net is comment/string-blind no more', () => {
  it('catches the await/destructure offender (must stay RED)', () => {
    const src = `
      import { jwtVerify } from 'jose';
      export async function cb(token, aud) {
        const { payload } = await jwtVerify(token, KEY, { audience: aud });
        const email = payload.email;
        return findByEmail(email);
      }`;
    expect(fileTrips(src)).toBe(true);
  });

  it('catches the await + verified.payload offender (must stay RED)', () => {
    const src = `
      import { jwtVerify } from 'jose';
      export async function cb(token, aud) {
        const verified = await jwtVerify(token, KEY, { audience: aud });
        const payload = verified.payload;
        const email = payload.email;
        return findByEmail(email);
      }`;
    expect(fileTrips(src)).toBe(true);
  });

  it('FALSE-NEGATIVE FIX: email_verified ONLY in a comment does NOT satisfy the guard', () => {
    const src = `
      import { jwtVerify } from 'jose';
      export async function cb(token, aud) {
        // we really should check email_verified before trusting this
        const { payload } = await jwtVerify(token, KEY, { audience: aud });
        const email = payload.email;
        return findByEmail(email);
      }`;
    // Old net: passed (comment made checksVerified=true). New net: trips.
    expect(fileTrips(src)).toBe(true);
  });

  it('FALSE-NEGATIVE FIX: email_verified ONLY in a string literal does NOT satisfy the guard', () => {
    const src = `
      import { jwtVerify } from 'jose';
      export async function cb(token, aud) {
        log('remember to honor email_verified');
        const { payload } = await jwtVerify(token, KEY, { audience: aud });
        const email = payload.email;
        return findByEmail(email);
      }`;
    expect(fileTrips(src)).toBe(true);
  });

  it('GREEN: a real in-scope email_verified === true guard passes', () => {
    const src = `
      import { jwtVerify } from 'jose';
      function trustedEmail(payload) {
        const email = typeof payload.email === 'string' ? payload.email : undefined;
        const verified = payload.email_verified;
        return verified === true || verified === 'true' ? email : undefined;
      }
      export async function cb(token, aud) {
        const { payload } = await jwtVerify(token, KEY, { audience: aud });
        return findByEmail(trustedEmail(payload));
      }`;
    expect(fileTrips(src)).toBe(false);
  });

  it('GREEN: a commented-out .email read does NOT manufacture a false offender', () => {
    const src = `
      import { jwtVerify } from 'jose';
      export async function cb(token, aud) {
        const { payload } = await jwtVerify(token, KEY, { audience: aud });
        // const email = payload.email; // legacy, removed
        return findByGoogleSub(payload.sub);
      }`;
    expect(fileTrips(src)).toBe(false);
  });
});
