/**
 * `POST /aa/bundler-keys` — admin-gated minting of `bk_` bundler API keys
 * (EW-S1 WP-4 slice B, sprint item 12).
 *
 * Auth posture (a `bk_` key authorizes paymaster-sponsored UserOps, so this
 * is gas-spending access — NOT open self-serve):
 *   - 503 when unconfigured (no bundler Redis or empty admin allowlist)
 *   - 401 when there is no live authenticated subject (interaction/session)
 *   - 403 when the subject is authenticated but not in BUNDLER_KEY_ADMIN_SUBS
 *   - 201 + `{ apiKey }` (plaintext, shown ONCE) for an allowlisted operator
 *
 * The minted hash lands in the bundler gate's Redis set (BUNDLER_REDIS_URL),
 * so the gate honours the key immediately. See {@link bundler-keys}.
 */
import type Provider from 'oidc-provider';

import {
  authorizeBundlerKeyMint,
  mintBundlerApiKey,
  type BundlerKeyRedis,
} from './bundler-keys.js';

type Ctx = Parameters<Parameters<Provider['use']>[0]>[0];
type Next = Parameters<Parameters<Provider['use']>[0]>[1];

export interface BundlerKeyRouteOptions {
  /** The BUNDLER's Redis (BUNDLER_REDIS_URL) — the set the gate reads. */
  redis?: BundlerKeyRedis;
  /** Operator subjects permitted to mint (BUNDLER_KEY_ADMIN_SUBS). */
  adminSubs?: string[];
}

export function mountBundlerKeyRoutes(
  provider: Provider,
  options: BundlerKeyRouteOptions = {},
): void {
  const adminSubs = options.adminSubs ?? [];
  const redis = options.redis;
  const configured = Boolean(redis) && adminSubs.length > 0;

  provider.use(async (ctx: Ctx, next: Next) => {
    if (ctx.method === 'POST' && ctx.path === '/aa/bundler-keys') {
      // Same auth posture as the password/webauthn/guardian routes: the live
      // OIDC interaction cookie (or an active session) names the subject.
      let accountId: string | null = null;
      try {
        const interaction = await provider.interactionDetails(ctx.req, ctx.res);
        const result = interaction?.result as { login?: { accountId?: string } } | undefined;
        accountId = result?.login?.accountId ?? interaction?.session?.accountId ?? null;
      } catch {
        accountId = null;
      }

      const authz = authorizeBundlerKeyMint({ configured, accountId, adminSubs });
      if (!authz.ok) {
        respond(ctx, authz.status, { error: authz.error });
        return;
      }

      const body = await readJson(ctx);
      const label =
        typeof body?.label === 'string' ? body.label.slice(0, 128) : null;
      const apiKey = await mintBundlerApiKey(redis!);
      respond(ctx, 201, {
        apiKey,
        prefix: 'bk_',
        label,
        note: 'stored as SHA-256 only — this is the only time the plaintext is shown',
      });
      return;
    }
    await next();
  });
}

function respond(ctx: Ctx, status: number, body: unknown): void {
  ctx.status = status;
  ctx.type = 'application/json';
  ctx.body = body;
}

async function readJson(ctx: Ctx): Promise<Record<string, unknown> | null> {
  const existing = (ctx.request as { body?: unknown }).body;
  if (existing && typeof existing === 'object' && !Array.isArray(existing)) {
    return existing as Record<string, unknown>;
  }
  const chunks: Buffer[] = [];
  await new Promise<void>((resolve, reject) => {
    const req = ctx.req as NodeJS.ReadableStream;
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => resolve());
    req.on('error', reject);
  });
  if (chunks.length === 0) return null;
  try {
    const parsed = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}
