/**
 * Email + password HTTP routes (WP-6 slice B of EW-S1; verified-email gate FWA #87.1).
 *
 * THREE POST endpoints mounted on the provider's Koa app:
 *
 *   POST /auth/password/register  { email, password }
 *     → validate, hash the password, and STASH it against a single-use
 *       verification code emailed via Resend. Does NOT create a user or a
 *       session. Returns { status: "verification_required" }. Enumeration-safe:
 *       the same response whether or not the email already exists.
 *
 *   POST /auth/password/login     { email, password }
 *     → a VERIFIED account with the right password signs in directly. Any other
 *       case (unverified account, or unknown email) issues a verification code
 *       and returns { status: "verification_required" } — an unverified email
 *       can never mint a session, bind, provision a wallet, or match a grant.
 *
 *   POST /auth/password/verify    { email, code }
 *     → the SOLE path that turns a typed email into a bound, verified account +
 *       session. Consumes the code (single-use, TTL, attempt-capped), then
 *       creates-or-updates the user with `email_verified=true` and the stashed
 *       password, and completes the OIDC interaction.
 *
 * All three REQUIRE an active OIDC interaction cookie (the login form for
 * /interaction/:uid). This mirrors the Google guard (FWA-C6-01): an email binds
 * ONLY when ownership is proven — for Google via `email_verified` on the
 * id_token, here via a Resend one-time code.
 */

import type { IncomingMessage, ServerResponse } from 'node:http';
import type Provider from 'oidc-provider';

import { hashPassword, verifyPassword, PasswordError } from './password.js';
import { getUserStore } from './stores.js';
import { predictedWalletForAccount } from '../aa/wallet-claims.js';
import { getEmailVerificationStore, CODE_TTL_MS } from './email-verification-pg.js';
import { sendVerificationCode } from '../email-send.js';

type Ctx = Parameters<Parameters<Provider['use']>[0]>[0];
type Next = Parameters<Parameters<Provider['use']>[0]>[1];

/** Minimum email shape: a string containing one `@` with text on each side. */
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const CODE_RE = /^[0-9]{6}$/;
const TTL_MINUTES = Math.round(CODE_TTL_MS / 60_000);

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

function respondJson(res: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
  });
  res.end(payload);
}

/**
 * Drive panva to complete the OIDC interaction with this accountId. Returns
 * the `redirectTo` URL the page should navigate to. Caller must already have
 * asserted there IS a live interaction cookie.
 */
async function finishLogin(
  provider: Provider,
  req: IncomingMessage,
  res: ServerResponse,
  accountId: string,
): Promise<string> {
  return provider.interactionResult(
    req,
    res,
    { login: { accountId, amr: ['pwd'], acr: 'urn:citrate:password' } },
    { mergeWithLastSubmission: false },
  );
}

/**
 * Issue a verification code for `email` (stashing the signup passwordHash) and
 * email it via Resend. Returns a discriminated result the caller maps to an
 * HTTP status. Never reveals whether the email already exists.
 */
async function issueAndSend(
  email: string,
  passwordHash: string,
): Promise<'sent' | 'rate_limited' | 'send_failed'> {
  const { code, rateLimited } = await getEmailVerificationStore().issue(
    email,
    passwordHash,
  );
  if (rateLimited || !code) return 'rate_limited';
  const ok = await sendVerificationCode(email, code, TTL_MINUTES);
  return ok ? 'sent' : 'send_failed';
}

/** Map an issueAndSend result to the HTTP response (identical across paths). */
function respondForIssue(
  res: ServerResponse,
  result: 'sent' | 'rate_limited' | 'send_failed',
): void {
  if (result === 'rate_limited') {
    respondJson(res, 429, {
      error: 'too_many_requests',
      reason: 'too many verification emails — wait a few minutes and try again',
    });
    return;
  }
  if (result === 'send_failed') {
    // Fail closed: we could not deliver the code, so do NOT pretend success.
    respondJson(res, 503, {
      error: 'email_unavailable',
      reason: 'could not send the verification email — please try again shortly',
    });
    return;
  }
  respondJson(res, 200, {
    status: 'verification_required',
    // enumeration-safe generic copy — same for new + existing addresses.
    message: 'Enter the 6-digit code we emailed you to continue.',
  });
}

/**
 * Mount POST /auth/password/{register,login,verify} on the provider's Koa app.
 * Idempotent shape; mount once at boot.
 */
export function mountPasswordRoutes(provider: Provider): void {
  provider.use(async (ctx: Ctx, next: Next) => {
    if (ctx.method !== 'POST') return next();
    if (
      ctx.path !== '/auth/password/register' &&
      ctx.path !== '/auth/password/login' &&
      ctx.path !== '/auth/password/verify'
    ) {
      return next();
    }

    // All three REQUIRE a live OIDC interaction cookie — they are the login
    // form for the interaction view, not headless endpoints.
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

    let body: { email?: unknown; password?: unknown; code?: unknown };
    try {
      body = (await readJson(ctx.req)) as typeof body;
    } catch {
      respondJson(ctx.res, 400, { error: 'invalid_request', reason: 'bad_body' });
      return;
    }

    const email = typeof body.email === 'string' ? body.email.trim() : '';
    if (!EMAIL_RE.test(email)) {
      respondJson(ctx.res, 400, {
        error: 'invalid_request',
        reason: 'invalid email',
      });
      return;
    }

    const store = getUserStore();

    // ── /auth/password/verify — consume code → create/verify → session ──────
    if (ctx.path === '/auth/password/verify') {
      const code = typeof body.code === 'string' ? body.code.trim() : '';
      if (!CODE_RE.test(code)) {
        respondJson(ctx.res, 400, {
          error: 'invalid_request',
          reason: 'code must be 6 digits',
        });
        return;
      }
      const { ok, passwordHash } = await getEmailVerificationStore().consume(
        email,
        code,
      );
      if (!ok) {
        respondJson(ctx.res, 401, {
          error: 'invalid_grant',
          reason: 'invalid or expired code',
        });
        return;
      }
      // Ownership proven. Create-or-update, always ending verified.
      let user = await store.findByEmail(email);
      if (!user) {
        if (!passwordHash) {
          // A code with no stashed password can't create an account (shouldn't
          // happen via register/login, which always stash one).
          respondJson(ctx.res, 422, {
            error: 'invalid_request',
            reason: 'no pending signup for this email',
          });
          return;
        }
        user = await store.createWithEmailPassword({ email, passwordHash });
      } else if (passwordHash) {
        // Existing account: attach/replace the password (email-proven reset).
        await store.rotatePasswordHash(user.id, passwordHash);
      }
      await store.markEmailVerified(user.id);
      await store.setLastSigningMethod(user.id, 'email-pw');
      const redirectTo = await finishLogin(provider, ctx.req, ctx.res, user.id);
      const walletAddress = predictedWalletForAccount(user.id);
      respondJson(ctx.res, 200, {
        userId: user.id,
        redirectTo,
        emailVerified: true,
        ...(walletAddress ? { walletAddress } : {}),
      });
      return;
    }

    // register + login both need a password.
    const password = typeof body.password === 'string' ? body.password : '';
    if (password.length === 0) {
      respondJson(ctx.res, 400, {
        error: 'invalid_request',
        reason: 'password is required',
      });
      return;
    }

    // Hash once up front (both paths that proceed need it).
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

    // ── /auth/password/register — never creates/sessions; always verify-first ─
    if (ctx.path === '/auth/password/register') {
      // No duplicate 409 (that was an account-enumeration oracle). Whether the
      // email is new or already exists, we issue a code and return the same
      // generic shape; only entering the code creates/updates anything.
      respondForIssue(ctx.res, await issueAndSend(email, passwordHash));
      return;
    }

    // ── /auth/password/login ────────────────────────────────────────────────
    const user = await store.findByEmail(email);
    if (user && user.emailVerified && user.passwordHash) {
      // The only path that signs in without a fresh code: a VERIFIED account
      // proving its password. Email ownership was proven at signup.
      const okPw = await verifyPassword(password, user.passwordHash);
      if (!okPw) {
        respondJson(ctx.res, 401, {
          error: 'invalid_grant',
          reason: 'invalid email or password',
        });
        return;
      }
      await store.setLastSigningMethod(user.id, 'email-pw');
      const redirectTo = await finishLogin(provider, ctx.req, ctx.res, user.id);
      const walletAddress = predictedWalletForAccount(user.id);
      respondJson(ctx.res, 200, {
        userId: user.id,
        redirectTo,
        ...(walletAddress ? { walletAddress } : {}),
      });
      return;
    }

    // Unverified account, an account with no password, OR an unknown email:
    // all converge on the verify-first flow with an identical response, so the
    // login endpoint is not an existence oracle.
    respondForIssue(ctx.res, await issueAndSend(email, passwordHash));
  });
}
