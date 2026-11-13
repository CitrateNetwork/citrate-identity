/**
 * AES-GCM decryption pins the auth-tag length. `createDecipheriv` for a GCM
 * mode must be called with `{ authTagLength: 16 }`, so the cipher itself
 * refuses a tag of any other length rather than relying only on the envelope
 * slicing exactly 16 bytes. The envelope layout makes a short tag unreachable
 * through the public API today, so this is a source scan over `src/`
 * (comments stripped), with a negative control on the unpinned shape.
 */
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { newDek, openField, sealField } from '../src/kyc-crypto.js';

const SRC_ROOT = fileURLToPath(new URL('../src', import.meta.url));

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) out.push(...walk(full));
    else if (entry.endsWith('.ts') && !entry.endsWith('.test.ts')) out.push(full);
  }
  return out;
}

function stripComments(src: string): string {
  return src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1');
}

/** Each `createDecipheriv(...)` call's argument text. */
function decipherCalls(code: string): string[] {
  const calls: string[] = [];
  const re = /createDecipheriv\s*\(/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(code)) !== null) {
    let depth = 1;
    let i = m.index + m[0].length;
    const start = i;
    while (i < code.length && depth > 0) {
      if (code[i] === '(') depth++;
      else if (code[i] === ')') depth--;
      i++;
    }
    calls.push(code.slice(start, i - 1));
  }
  return calls;
}

function unpinnedGcmDeciphers(src: string): string[] {
  const code = stripComments(src);
  // A file that names a GCM mode: every decipher in it must pin the tag length.
  if (!/aes-\d{3}-gcm/i.test(code)) return [];
  return decipherCalls(code).filter((args) => !/authTagLength\s*:\s*(16|TAG_LEN)\b/.test(args));
}

describe('AES-GCM decipher pins the auth-tag length', () => {
  it('every GCM createDecipheriv in src/ passes authTagLength: 16', () => {
    const offenders: string[] = [];
    let calls = 0;
    for (const file of walk(SRC_ROOT)) {
      const src = readFileSync(file, 'utf8');
      calls += decipherCalls(stripComments(src)).length;
      for (const c of unpinnedGcmDeciphers(src)) offenders.push(`${file.replace(SRC_ROOT, 'src')}: createDecipheriv(${c})`);
    }
    expect(calls).toBeGreaterThanOrEqual(2);
    expect(offenders).toEqual([]);
  });

  it('negative control: the unpinned call shape is flagged, the pinned one is not', () => {
    const src = [
      "const ALG = 'aes-256-gcm';",
      'const a = createDecipheriv(ALG, key, iv);',
      'const b = createDecipheriv(ALG, key, iv, { authTagLength: TAG_LEN });',
      '// const c = createDecipheriv(ALG, key, iv);',
    ].join('\n');
    expect(unpinnedGcmDeciphers(src)).toEqual(['ALG, key, iv']);
  });

  it('sealed fields still round-trip and a tampered tag is refused', () => {
    const dek = newDek();
    const sealed = sealField('hello', dek);
    expect(openField(sealed, dek)).toBe('hello');
    const buf = Buffer.from(sealed, 'base64');
    buf[1 + 12] ^= 0x01; // first tag byte (version, 12-byte IV, then the tag)
    expect(() => openField(buf.toString('base64'), dek)).toThrow();
  });
});
