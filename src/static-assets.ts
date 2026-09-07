/**
 * Static asset middleware for the authority's branded interaction page
 * (WP-6 slice B of EW-S1).
 *
 * Serves two fixed prefixes from the repo's `public/` directory:
 *
 *   GET /brand/<file>   → public/brand/<file>     (svg wordmarks + mark)
 *   GET /fonts/<file>   → public/fonts/<file>     (Space Grotesk, Geist,
 *                                                  Geist Mono, Cormorant)
 *
 * The branded login page references these paths directly from `<img>`,
 * `<link>`, and `@font-face` URLs. Self-hosting the brand assets is the
 * point — the previous attempt pulled fonts from `fonts.googleapis.com`,
 * which both leaked to a third party and made the page look wrong when
 * the CDN was slow.
 *
 * Design choices:
 *   - The middleware is mounted BEFORE panva so a request for
 *     `/brand/citrate-mark.svg` never touches the OIDC routing.
 *   - Path traversal is rejected by string check: any `..` or absolute
 *     fragment in the request URL fails with 400 (no filesystem walk).
 *   - Content-types cover the file extensions we actually ship; an
 *     unknown extension falls through to `application/octet-stream`
 *     rather than guessing.
 *   - Cache-Control is `public, max-age=31536000, immutable` because
 *     the files are content-addressable by virtue of being committed —
 *     a change ships as a code deploy with a fresh URL. CSP-friendly.
 */
import { readFile } from 'node:fs/promises';
import { join, resolve, sep } from 'node:path';
import type Provider from 'oidc-provider';

type Ctx = Parameters<Parameters<Provider['use']>[0]>[0];
type Next = Parameters<Parameters<Provider['use']>[0]>[1];

interface StaticAssetOptions {
  /**
   * Filesystem directory the URL prefix is rooted at. The middleware
   * concatenates `<root>/<urlPrefix>/<file>` and reads the result. The
   * caller's `public/` directory is the canonical root.
   */
  publicRoot: string;
}

const CONTENT_TYPES: Record<string, string> = {
  svg: 'image/svg+xml',
  woff2: 'font/woff2',
  woff: 'font/woff',
  ttf: 'font/ttf',
  otf: 'font/otf',
  png: 'image/png',
  ico: 'image/x-icon',
  json: 'application/json; charset=utf-8',
  css: 'text/css; charset=utf-8',
  // Self-hosted browser JS the interaction page loads SAME-ORIGIN instead of
  // from a third-party CDN (ID-B-004): /vendor/*.mjs.
  mjs: 'text/javascript; charset=utf-8',
  js: 'text/javascript; charset=utf-8',
};

const ALLOWED_PREFIXES = ['/brand/', '/fonts/', '/vendor/'];

function safeJoin(root: string, urlPath: string): string | null {
  // Strip leading slash so join doesn't absolutize against root.
  const trimmed = urlPath.replace(/^\/+/, '');
  // Reject any segment containing `..` or null bytes BEFORE touching the FS.
  if (trimmed.includes('..') || trimmed.includes('\0')) return null;
  const joined = resolve(root, trimmed);
  const rootResolved = resolve(root) + sep;
  if (!joined.startsWith(rootResolved)) return null;
  return joined;
}

function contentTypeFor(path: string): string {
  const m = /\.([a-z0-9]+)$/i.exec(path);
  const ext = m ? m[1].toLowerCase() : '';
  return CONTENT_TYPES[ext] ?? 'application/octet-stream';
}

/**
 * Mount the static asset middleware on the provider's Koa app. Idempotent
 * shape (the middleware itself uses `next()` to fall through); calling
 * twice would register twice and is the caller's responsibility to avoid.
 */
export function mountStaticAssets(
  provider: Provider,
  options: StaticAssetOptions,
): void {
  const root = resolve(options.publicRoot);

  provider.use(async (ctx: Ctx, next: Next) => {
    if (ctx.method !== 'GET' && ctx.method !== 'HEAD') return next();
    const path = ctx.path;
    if (!ALLOWED_PREFIXES.some((p) => path.startsWith(p))) return next();

    const fsPath = safeJoin(root, path);
    if (fsPath === null) {
      ctx.status = 400;
      ctx.type = 'text/plain';
      ctx.body = 'bad path';
      return;
    }

    let buf: Buffer;
    try {
      buf = await readFile(fsPath);
    } catch {
      // Missing or unreadable — surface 404 so callers can fall back instead
      // of letting panva 4xx the request as an unknown route.
      ctx.status = 404;
      ctx.type = 'text/plain';
      ctx.body = 'not found';
      return;
    }

    ctx.status = 200;
    ctx.set('content-type', contentTypeFor(fsPath));
    ctx.set('cache-control', 'public, max-age=31536000, immutable');
    ctx.set('x-content-type-options', 'nosniff');
    ctx.body = ctx.method === 'HEAD' ? undefined : buf;
  });
}
