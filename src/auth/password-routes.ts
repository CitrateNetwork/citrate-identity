/**
 * Email + password HTTP routes (WP-6 slice B of EW-S1).
 *
 * Two POST endpoints mounted on the provider's Koa app:
 *
 *   POST /auth/password/register  { email, password }
 *     → create a new user with Argon2id hash, then drive
 *       provider.interactionResult so the OIDC /auth flow resumes
 *       (auto-sign-in after register). Returns { redirectTo }.
 *
 *   POST /auth/password/login     { email, password }
 *     → look up user by email, verify Argon2id hash, drive
 *       provider.interactionResult. Returns { redirectTo }.
 *
 * Both endpoints REQUIRE an active OIDC interaction cookie — they are
 * the "login form" for the interaction view at /interaction/:uid. A
 * headless API caller without an interaction cookie gets 400.
 *
 * The user record (created via password) is stored in the {@link UserStore}
 * singleton (Postgres in prod, in-memory in dev); the OIDC accountId is
 * the user's UUID, which {@link findAccount} treats as a UUID-keyed
 * (not wallet-bound) account.
 */

import type { IncomingMessage, ServerResponse } from 'node:http';
import type Provider from 'oidc-provider';

import { hashPassword, verifyPassword, PasswordError } from './password.js';
import { getUserStore } from './stores.js';
import { predictedWalletForAccount } from '../aa/wallet-claims.js';

type Ctx = Parameters<Parameters<Provider['use']>[0]>[0];
type Next = Parameters<Parameters<Provider['use']>[0]>[1];

/** Minimum email shape: a string containing one `@` with text on each side. */
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

async function readJson(
  req: IncomingMessage,
  maxBytes = 64 * 1024,
): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    const buf = chunk as Buffer;
    size += buf.length;
    if (size > maxBytes) throw new Error('payload too large');
    chunks.push(buf);
  }
  if (chunks.length === 0) return {};
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

function respondJson(
  res: ServerResponse,
  status: number,
  body: unknown,
): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
  });
  res.end(payload);
}

/**
 * Drive panva to complete the OIDC interaction with this accountId. Returns
 * the `redirectTo` URL the page should navigate to (panva's resume URL).
 * Caller must already have asserted there IS a live interaction cookie.
 */
async function finishLogin(
  provider: Provider,
  req: IncomingMessage,
  res: ServerResponse,
  accountId: string,
  amr: string[],
  acr: string,
): Promise<string> {
  return provider.interactionResult(
    req,
    res,
    { login: { accountId, amr, acr } },
    { mergeWithLastSubmission: false },
  );
}

/**
 * Mount POST /auth/password/{register,login} on the provider's Koa app.
 * Idempotent shape (each handler short-circuits via `return`); mount once
 * at boot.
 */
export function mountPasswordRoutes(provider: Provider): void {
  provider.use(async (ctx: Ctx, next: Next) => {
    if (ctx.method !== 'POST') return next();
    if (ctx.path !== '/auth/password/register' && ctx.path !== '/auth/password/login') {
      return next();
    }

    // Both register and login REQUIRE a live OIDC interaction cookie — they
    // are the login form for the interaction view, not headless endpoints.
    let interaction: Awaited<
      ReturnType<typeof provider.interactionDetails>
    > | null = null;
    try {
      interaction = await provider.interactionDetails(ctx.req, ctx.res);
    } catch {
      interaction = null;
    }
    if (!interaction) {
      respondJson(ctx.res, 400, {
        error: 'invalid_request',
        reason: 'no active interaction',
      });
      return;
    }

    let body: { email?: unknown; password?: unknown };
    try {
      body = (await readJson(ctx.req)) as typeof body;
    } catch {
      respondJson(ctx.res, 400, { error: 'invalid_request', reason: 'bad_body' });
      return;
    }

    const email = typeof body.email === 'string' ? body.email.trim() : '';
    const password = typeof body.password === 'string' ? body.password : '';
    if (!EMAIL_RE.test(email)) {
      respondJson(ctx.res, 400, {
        error: 'invalid_request',
        reason: 'invalid email',
      });
      return;
    }
    if (password.length === 0) {
      respondJson(ctx.res, 400, {
        error: 'invalid_request',
        reason: 'password is required',
      });
      return;
    }

    const store = getUserStore();

    if (ctx.path === '/auth/password/register') {
      // Reject duplicate emails BEFORE hashing — Argon2 costs ~100ms, no point
      // burning that on a request we'll already 409.
      const existing = await store.findByEmail(email);
      if (existing) {
        respondJson(ctx.res, 409, {
          error: 'email_taken',
          reason: 'an account with this email already exists',
        });
        return;
      }
      let passwordHash: string;
      try {
        passwordHash = await hashPassword(password);
      } catch (err) {
        if (err instanceof PasswordError) {
          respondJson(ctx.res, 400, {
            error: 'invalid_request',
            reason: err.message,
          });
          return;
        }
        throw err;
      }
      const user = await store.createWithEmailPassword({ email, passwordHash });
      await store.setLastSigningMethod(user.id, 'email-pw');
      const redirectTo = await finishLogin(
        provider,
        ctx.req,
        ctx.res,
        user.id,
        ['pwd'],
        'urn:citrate:password',
      );
      const walletAddress = predictedWalletForAccount(user.id);
      respondJson(ctx.res, 200, {
        userId: user.id,
        redirectTo,
        ...(walletAddress ? { walletAddress } : {}),
      });
      return;
    }

    // /auth/password/login — sign-in-or-create.
    const user = await store.findByEmail(email);

    // No account yet → this is someone who meant to sign UP (the common
    // accidental-"Sign in" case). Auto-create the account with these credentials
    // and continue to the address modal, rather than dead-ending at a confusing
    // 401. (AUTHSPINE S1-WP1.) A WRONG PASSWORD on an EXISTING account still
    // fails — that is a real error, below. NOTE: this makes the unknown-email
    // response (200, `created:true`) differ from the wrong-password response
    // (401), which is a deliberate UX trade-off over strict account-enumeration
    // resistance; the enumeration-free path is passwordless/magic-link (future).
    if (!user || !user.passwordHash) {
      let passwordHash: string;
      try {
        passwordHash = await hashPassword(password);
      } catch (err) {
        if (err instanceof PasswordError) {
          respondJson(ctx.res, 400, { error: 'invalid_request', reason: err.message });
          return;
        }
        throw err;
      }
      let created;
      try {
        created = await store.createWithEmailPassword({ email, passwordHash });
      } catch {
        // Lost a create race (email registered between findByEmail and now):
        // fall back to a normal verify against the now-existing account.
        const racer = await store.findByEmail(email);
        if (racer?.passwordHash && (await verifyPassword(password, racer.passwordHash))) {
          await store.setLastSigningMethod(racer.id, 'email-pw');
          const redirectTo = await finishLogin(
            provider, ctx.req, ctx.res, racer.id, ['pwd'], 'urn:citrate:password',
          );
          const walletAddress = predictedWalletForAccount(racer.id);
          respondJson(ctx.res, 200, {
            userId: racer.id, redirectTo, ...(walletAddress ? { walletAddress } : {}),
          });
          return;
        }
        respondJson(ctx.res, 401, { error: 'invalid_grant', reason: 'invalid email or password' });
        return;
      }
      await store.setLastSigningMethod(created.id, 'email-pw');
      const redirectTo = await finishLogin(
        provider, ctx.req, ctx.res, created.id, ['pwd'], 'urn:citrate:password',
      );
      const walletAddress = predictedWalletForAccount(created.id);
      respondJson(ctx.res, 200, {
        userId: created.id,
        redirectTo,
        created: true,
        ...(walletAddress ? { walletAddress } : {}),
      });
      return;
    }

    const ok = await verifyPassword(password, user.passwordHash);
    if (!ok) {
      respondJson(ctx.res, 401, {
        error: 'invalid_grant',
        reason: 'invalid email or password',
      });
      return;
    }
    await store.setLastSigningMethod(user.id, 'email-pw');
    const redirectTo = await finishLogin(
      provider,
      ctx.req,
      ctx.res,
      user.id,
      ['pwd'],
      'urn:citrate:password',
    );
    const walletAddress = predictedWalletForAccount(user.id);
    respondJson(ctx.res, 200, {
      userId: user.id,
      redirectTo,
      ...(walletAddress ? { walletAddress } : {}),
    });
  });
}
