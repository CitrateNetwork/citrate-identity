/**
 * Guardian-nomination HTTP surface (EW-S1 WP-10, sprint item 31).
 *
 *   POST /auth/guardians   — nominate guardians from the post-signin
 *                            page. Gated by the LIVE OIDC interaction
 *                            cookie (same posture as the password +
 *                            webauthn routes): the nomination binds to
 *                            the interaction's authenticated account.
 *   GET  /aa/guardians     — Bearer-gated (own sub). Returns the stored
 *                            nomination plus, when the recovery-module
 *                            address is configured, the ready-to-append
 *                            Kernel `initConfig` entry the SDK includes
 *                            in the wallet's first deploy.
 *
 * Wire shape proven in citrate-chain test/aa/GuardianRecoveryE2E.t.sol.
 */

import type Provider from 'oidc-provider';
import type { Address } from 'viem';

import {
  getGuardianStore,
  normalizeNomination,
  GuardianNominationError,
} from './guardians.js';
import { guardianInstallModuleCall } from './install-data.js';

type Ctx = Parameters<Parameters<Provider['use']>[0]>[0];
type Next = Parameters<Parameters<Provider['use']>[0]>[1];

export interface GuardianRouteOptions {
  /** GuardianRecoveryModule address (canonical 40204.json aaStack). When
   * unset the GET response omits the initConfig entry. */
  recoveryModule?: Address;
  /** Addresses refused as guardians (the authority's identity signer). */
  forbidden?: string[];
}

export function mountGuardianRoutes(
  provider: Provider,
  options: GuardianRouteOptions = {},
): void {
  provider.use(async (ctx: Ctx, next: Next) => {
    // ── POST /auth/guardians (interaction-cookie-gated page surface) ──
    if (ctx.method === 'POST' && ctx.path === '/auth/guardians') {
      let interaction: Awaited<ReturnType<typeof provider.interactionDetails>> | null = null;
      try {
        interaction = await provider.interactionDetails(ctx.req, ctx.res);
      } catch {
        interaction = null;
      }
      const result = interaction?.result as { login?: { accountId?: string } } | undefined;
      const accountId = result?.login?.accountId ?? interaction?.session?.accountId;
      if (!accountId) {
        respond(ctx, 401, {
          error: 'unauthorized',
          reason: 'sign in first, then nominate guardians',
        });
        return;
      }

      const body = await readJson(ctx);
      try {
        const nomination = normalizeNomination({
          sub: accountId,
          guardians: body?.guardians,
          threshold: body?.threshold,
          ...(options.forbidden ? { forbidden: options.forbidden } : {}),
        });
        await getGuardianStore().set(nomination);
        respond(ctx, 200, {
          sub: accountId,
          guardians: nomination.guardians,
          threshold: nomination.threshold,
        });
      } catch (err) {
        if (err instanceof GuardianNominationError) {
          respond(ctx, 400, { error: 'invalid_request', reason: err.message });
          return;
        }
        throw err;
      }
      return;
    }

    // ── GET /aa/guardians (Bearer, own sub — the SDK reads this) ─────
    if (ctx.method === 'GET' && ctx.path === '/aa/guardians') {
      const sub = await resolveSub(provider, ctx);
      if (!sub) {
        respond(ctx, 401, { error: 'unauthorized', reason: 'access token required' });
        return;
      }
      const nomination = await getGuardianStore().get(sub);
      if (!nomination) {
        respond(ctx, 200, { sub, nominated: false });
        return;
      }
      respond(ctx, 200, {
        sub,
        nominated: true,
        guardians: nomination.guardians,
        threshold: nomination.threshold,
        // The Kernel initConfig entry the SDK appends to initialize() so
        // the guardians are installed at the wallet's first deploy.
        ...(options.recoveryModule
          ? {
              initConfig: guardianInstallModuleCall({
                recoveryModule: options.recoveryModule,
                threshold: nomination.threshold,
                guardians: nomination.guardians as Address[],
              }),
            }
          : {}),
      });
      return;
    }

    return next();
  });
}

// ── helpers (same shapes as the sibling aa routes) ───────────────────

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

async function resolveSub(provider: Provider, ctx: Ctx): Promise<string | null> {
  const auth = ctx.headers.authorization;
  if (typeof auth !== 'string') return null;
  const m = /^Bearer\s+(.+)$/i.exec(auth.trim());
  if (!m || !m[1]) return null;
  try {
    const token = await provider.AccessToken.find(m[1].trim());
    if (!token || token.isExpired) return null;
    return typeof token.accountId === 'string' ? token.accountId : null;
  } catch {
    return null;
  }
}
