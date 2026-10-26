/**
 * Tripwire: every package the server source imports at runtime is declared in
 * package.json `dependencies`.
 *
 * A package that is only present transitively (or only in devDependencies)
 * still resolves in a dev checkout, so tests pass, but a production install
 * (`npm ci --omit=dev`, or a lockfile change upstream) can drop it and the
 * server fails at boot. Type-only imports are erased at compile time and are
 * exempt.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { builtinModules } from 'node:module';
import { join, relative } from 'node:path';

const ROOT = join(__dirname, '..');
const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')) as {
  dependencies?: Record<string, string>;
};
const declared = new Set(Object.keys(pkg.dependencies ?? {}));
const builtins = new Set(builtinModules);

/** Package name for a bare specifier (`@scope/name/sub` → `@scope/name`, `name/sub` → `name`). */
function packageName(spec: string): string | null {
  if (spec.startsWith('.') || spec.startsWith('/') || spec.startsWith('node:')) return null;
  const parts = spec.split('/');
  const name = spec.startsWith('@') ? parts.slice(0, 2).join('/') : parts[0]!;
  return builtins.has(name) ? null : name;
}

/** Runtime (non type-only) import/export/dynamic-import specifiers in a TS source. */
function runtimeImports(source: string): string[] {
  const out: string[] = [];
  const stmt = /^\s*(import|export)\s+(type\s+)?[^;]*?\sfrom\s+['"]([^'"]+)['"]/gm;
  for (const m of source.matchAll(stmt)) if (!m[2]) out.push(m[3]!);
  for (const m of source.matchAll(/^\s*import\s+['"]([^'"]+)['"]/gm)) out.push(m[1]!);
  for (const m of source.matchAll(/\bimport\(\s*['"]([^'"]+)['"]\s*\)/g)) out.push(m[1]!);
  return out;
}

function tsFiles(dir: string): string[] {
  const files: string[] = [];
  for (const entry of readdirSync(dir)) {
    const p = join(dir, entry);
    if (statSync(p).isDirectory()) files.push(...tsFiles(p));
    else if (p.endsWith('.ts') && !p.endsWith('.d.ts')) files.push(p);
  }
  return files;
}

describe('runtime imports are declared dependencies', () => {
  it('every bare runtime import under src/ is in package.json dependencies', () => {
    const missing: string[] = [];
    for (const file of tsFiles(join(ROOT, 'src'))) {
      for (const spec of runtimeImports(readFileSync(file, 'utf8'))) {
        const name = packageName(spec);
        if (name && !declared.has(name)) missing.push(`${relative(ROOT, file)} → ${name}`);
      }
    }
    expect(missing).toEqual([]);
  });

  it('negative control: the scanner sees static, side-effect and dynamic imports, and skips type-only ones', () => {
    const src = [
      "import { a } from 'undeclared-pkg';",
      "import '@scope/side-effect/sub';",
      "const m = await import('dyn-pkg');",
      "import type { T } from 'types-only-pkg';",
      "import { x } from './local.js';",
      "import { readFileSync } from 'node:fs';",
      "import { join } from 'path';",
    ].join('\n');
    const names = runtimeImports(src).map(packageName).filter(Boolean);
    expect(names).toEqual(['undeclared-pkg', '@scope/side-effect', 'dyn-pkg']);
  });
});
