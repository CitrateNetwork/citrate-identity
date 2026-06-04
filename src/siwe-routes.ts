/**
 * SIWE ↔ panva integration (IDP-S1.5).
 *
 * Mounts two routes on the provider's Koa app:
 *
 *   GET  /siwe/challenge → `{ nonce }`  (fresh, single-use, short TTL)
 *   POST /siwe/verify    → verify an EIP-4361 message and LOG THE USER IN
 *
 * How SIWE becomes an OIDC login (the panva integration, made real):
 *
 *   A) **Interaction-resume (the production OIDC path).** When an RP sends the
 *      user through `/auth`, panva creates an *interaction* and redirects the
 *      browser to it. The wallet UI then calls `/siwe/challenge` + `/siwe/verify`
 *      WITH that interaction's cookie present. On a valid signature we call
 *      `provider.interactionResult(req, res, { login: { accountId } })`, which
 *      is exactly how a username/password form would resume the flow — panva
 *      then mints the authorization code / ID token / access token through its
 *      normal machinery, and `findAccount` (config.ts) populates the
 *      `wallet_address` claim from the accountId.
 *
 *   B) **Direct-token (headless / API login).** When `/siwe/verify` is called
 *      WITHOUT an active interaction (no OIDC `/auth` in front of it — e.g. a
 *      CLI or a test asserting "a token is issued"), we mint a real RS256 OIDC
 *      ID token signed by the SAME JWKS the authority publishes, so it verifies
 *      against `/jwks`. Claims come from the same `findAccount`, so
 *      `wallet_address` is populated identically. This is not a fake token: it
 *      is signed by the authority key and carries the standard OIDC claims.
 *
 * Both paths share one verification core (`verifySiweLogin`) and one account
 * model (`findAccount`), so security checks and claims can never diverge.
 */
import type { IncomingMessage, ServerResponse } from 'node:http';
import { SignJWT, importJWK, type JWK } from 'jose';
import type Provider from 'oidc-provider';
import type { Account } from 'oidc-provider';
import {
  InMemoryNonceStore,
  SiweVerificationError,
  verifySiweLogin,
  type NonceStore,
  type VerifySiweResult,
} from './siwe.js';
import type { PublicClient } from 'viem';

export interface SiweRouteOptions {
  /**
   * The authority host SIWE messages must be bound to (domain binding). Derived
   * from the issuer URL (e.g. `auth.citrate.ai`, or `127.0.0.1:PORT` in tests).
   */
  expectedDomain: string;
  /** Issuer URL — the `iss` of direct-path tokens and the SIWE message `uri`. */
  issuer: string;
  /** The RS256 signing JWK (private) the authority publishes via JWKS. */
  signingJwk: JWK;
  /** Nonce store (defaults to in-memory; Redis in multi-instance prod). */
  nonceStore?: NonceStore;
  /** Optional viem public client enabling EIP-1271 (smart-contract wallets). */
  publicClient?: PublicClient;
  /** Audience for direct-path tokens. Defaults to the explorer client. */
  audience?: string;
  /** ID-token lifetime for the direct path, seconds. */
  idTokenTtlSeconds?: number;
}

/** Read a JSON request body with a hard size cap (anti-DoS). */
async function readJson(req: IncomingMessage, maxBytes = 64 * 1024): Promise<unknown> {
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

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
  });
  res.end(payload);
}

/**
 * Resolve the OIDC account for a wallet address via the provider's configured
 * `findAccount`. Returns the populated claims so the direct path mirrors the
 * interaction path exactly.
 */
async function accountClaimsFor(
  provider: Provider,
  ctx: unknown,
  address: string,
): Promise<Record<string, unknown>> {
  const findAccount = provider.Account.findAccount;
  const account = (await findAccount(
    ctx as never,
    address,
    undefined,
  )) as Account | undefined;
  if (!account) {
    // findAccount is configured in config.ts to always resolve an address →
    // account, so this is a real invariant violation, not an expected branch.
    throw new Error('findAccount did not resolve the authenticated address');
  }
  // Mirror the OIDC `wallet` + `openid` scopes for the direct token.
  return account.claims('id_token', 'openid wallet', {}, []) as Promise<
    Record<string, unknown>
  > as unknown as Record<string, unknown>;
}

/**
 * Mint a real OIDC ID token signed by the authority's JWKS key (direct path).
 */
async function mintIdToken(
  opts: Required<Pick<SiweRouteOptions, 'issuer' | 'signingJwk'>> &
    Pick<SiweRouteOptions, 'audience' | 'idTokenTtlSeconds'>,
  claims: Record<string, unknown>,
): Promise<string> {
  const key = await importJWK(opts.signingJwk, 'RS256');
  const now = Math.floor(Date.now() / 1000);
  const ttl = opts.idTokenTtlSeconds ?? 60 * 60;
  return new SignJWT(claims)
    .setProtectedHeader({ alg: 'RS256', kid: opts.signingJwk.kid, typ: 'JWT' })
    .setIssuer(opts.issuer)
    .setAudience(opts.audience ?? 'citrate-explorer')
    .setSubject(String(claims.sub))
    .setIssuedAt(now)
    .setExpirationTime(now + ttl)
    .setJti(`${claims.sub}-${now}-${Math.random().toString(36).slice(2)}`)
    .sign(key);
}

/**
 * Mount `/siwe/challenge` and `/siwe/verify` on the provider's Koa app.
 * Returns the nonce store so a caller/test can inspect or swap it.
 */
export function mountSiweRoutes(
  provider: Provider,
  options: SiweRouteOptions,
): NonceStore {
  const nonceStore = options.nonceStore ?? new InMemoryNonceStore();

  provider.use(async (ctx, next) => {
    const { method, path } = ctx;

    if (method === 'GET' && path === '/siwe/challenge') {
      const nonce = nonceStore.issue();
      sendJson(ctx.res, 200, { nonce });
      return; // handled; do not fall through to panva
    }

    if (method === 'POST' && path === '/siwe/verify') {
      let body: { message?: unknown; signature?: unknown };
      try {
        body = (await readJson(ctx.req)) as typeof body;
      } catch {
        sendJson(ctx.res, 400, { error: 'invalid_request', reason: 'bad_body' });
        return;
      }

      if (typeof body.message !== 'string' || typeof body.signature !== 'string') {
        sendJson(ctx.res, 400, {
          error: 'invalid_request',
          reason: 'message and signature are required strings',
        });
        return;
      }

      let result: VerifySiweResult;
      try {
        result = await verifySiweLogin({
          message: body.message,
          signature: body.signature,
          expectedDomain: options.expectedDomain,
          nonceStore,
          publicClient: options.publicClient,
        });
      } catch (err) {
        if (err instanceof SiweVerificationError) {
          // All policy failures (replay / domain / expiry / chain / malleable /
          // bad sig) fail closed as 401 — no token is ever issued.
          sendJson(ctx.res, 401, {
            error: 'invalid_grant',
            reason: err.reason,
          });
          return;
        }
        sendJson(ctx.res, 400, { error: 'invalid_request' });
        return;
      }

      const accountId = result.address;

      // PATH A — resume an in-flight OIDC interaction if one exists.
      try {
        const interaction = await provider.interactionDetails(ctx.req, ctx.res);
        if (interaction) {
          const redirectTo = await provider.interactionResult(
            ctx.req,
            ctx.res,
            { login: { accountId, amr: ['siwe'], acr: 'urn:citrate:siwe' } },
            { mergeWithLastSubmission: false },
          );
          sendJson(ctx.res, 200, {
            address: accountId,
            method: result.method,
            redirectTo,
          });
          return;
        }
      } catch {
        // No active interaction (or its cookie isn't present) → fall through to
        // the direct-token path. This is expected for headless/API logins.
      }

      // PATH B — direct OIDC token, signed by the authority JWKS.
      const claims = await accountClaimsFor(provider, ctx, accountId);
      const idToken = await mintIdToken(
        {
          issuer: options.issuer,
          signingJwk: options.signingJwk,
          audience: options.audience,
          idTokenTtlSeconds: options.idTokenTtlSeconds,
        },
        claims,
      );

      sendJson(ctx.res, 200, {
        address: accountId,
        method: result.method,
        token_type: 'Bearer',
        id_token: idToken,
        wallet_address: claims.wallet_address,
      });
      return;
    }

    await next();
  });

  return nonceStore;
}
