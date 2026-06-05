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
  CITRATE_CHAIN_ID,
  InMemoryNonceStore,
  SiweVerificationError,
  verifySiweLogin,
  type NonceStore,
  type VerifySiweResult,
} from './siwe.js';
import type { PublicClient } from 'viem';
import { isTrustedFirstPartyClient } from './config.js';

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
  /**
   * Chain the interaction page tells the wallet to bind the SIWE message to.
   * Defaults to {@link CITRATE_CHAIN_ID}; overridable for tests / other chains.
   */
  chainId?: number;
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

function sendHtml(res: ServerResponse, status: number, html: string): void {
  res.writeHead(status, {
    'content-type': 'text/html; charset=utf-8',
    'cache-control': 'no-store',
  });
  res.end(html);
}

/** Minimal HTML-attribute/text escaping for the values we interpolate. */
function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * The SIWE interaction page (Path A). panva 303s the browser here for an
 * in-flight `/auth` interaction. The page:
 *   1. fetches /siwe/challenge for a fresh nonce,
 *   2. asks the injected wallet (window.ethereum) to sign an EIP-4361 message
 *      bound to this authority's domain + the Citrate chainId (40204),
 *   3. POSTs /siwe/verify (the interaction cookie rides along → Path A →
 *      provider.interactionResult), and
 *   4. navigates to the returned `redirectTo`, resuming the OIDC flow so panva
 *      mints the authorization code and redirects to the explorer callback.
 *
 * The page is intentionally dependency-free (plain HTML+JS). The automated E2E
 * test does not load this page in a browser; it performs steps 1–4 directly over
 * HTTP with a viem EOA. The page is the real human path for the same flow.
 */
function renderInteractionPage(opts: {
  uid: string;
  domain: string;
  uri: string;
  chainId: number;
  statement: string;
}): string {
  // Values that land inside the inline script as JSON literals.
  const cfg = JSON.stringify({
    uid: opts.uid,
    domain: opts.domain,
    uri: opts.uri,
    chainId: opts.chainId,
    statement: opts.statement,
  });
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Sign in to Citrate</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 28rem; margin: 4rem auto; padding: 0 1rem; color: #111; }
  button { font-size: 1rem; padding: 0.6rem 1.1rem; border-radius: 0.5rem; border: 1px solid #8ecc09; background: #8ecc09; color: #082; cursor: pointer; }
  button:disabled { opacity: 0.6; cursor: default; }
  #status { margin-top: 1rem; color: #555; white-space: pre-wrap; }
  code { background: #f3f3f3; padding: 0.1rem 0.3rem; border-radius: 0.25rem; }
</style>
</head>
<body>
  <h1>Sign in with your wallet</h1>
  <p>Authenticate to <code>${escapeHtml(opts.domain)}</code> by signing a message on the Citrate network (chain ${opts.chainId}). No transaction, no gas.</p>
  <button id="signin" type="button">Connect wallet &amp; sign in</button>
  <p id="status" role="status"></p>
<script>
const CFG = ${cfg};
const statusEl = document.getElementById('status');
const btn = document.getElementById('signin');
function setStatus(msg) { statusEl.textContent = msg; }

// Build a canonical EIP-4361 message string. Mirrors the fields the authority
// verifies: domain (anti-phishing), uri, chainId (Citrate), nonce, issuedAt,
// expirationTime, and the signing address.
function buildSiweMessage(address, nonce) {
  const issuedAt = new Date();
  const expirationTime = new Date(issuedAt.getTime() + 10 * 60 * 1000);
  const lines = [
    CFG.domain + ' wants you to sign in with your Ethereum account:',
    address,
    '',
    CFG.statement,
    '',
    'URI: ' + CFG.uri,
    'Version: 1',
    'Chain ID: ' + CFG.chainId,
    'Nonce: ' + nonce,
    'Issued At: ' + issuedAt.toISOString(),
    'Expiration Time: ' + expirationTime.toISOString(),
  ];
  return lines.join('\\n');
}

async function signIn() {
  btn.disabled = true;
  try {
    if (!window.ethereum) {
      setStatus('No injected wallet found. Install a wallet to continue.');
      btn.disabled = false;
      return;
    }
    setStatus('Requesting wallet…');
    const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
    const address = accounts[0];

    setStatus('Fetching challenge…');
    const challengeRes = await fetch('/siwe/challenge', { credentials: 'same-origin' });
    const { nonce } = await challengeRes.json();

    const message = buildSiweMessage(address, nonce);
    setStatus('Awaiting signature…');
    const signature = await window.ethereum.request({
      method: 'personal_sign',
      params: [message, address],
    });

    setStatus('Verifying…');
    const verifyRes = await fetch('/siwe/verify', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({ message, signature }),
    });
    const result = await verifyRes.json();
    if (!verifyRes.ok || !result.redirectTo) {
      setStatus('Sign-in failed: ' + (result.reason || result.error || verifyRes.status));
      btn.disabled = false;
      return;
    }
    setStatus('Signed in. Redirecting…');
    window.location = result.redirectTo;
  } catch (err) {
    setStatus('Error: ' + (err && err.message ? err.message : String(err)));
    btn.disabled = false;
  }
}
btn.addEventListener('click', signIn);
</script>
</body>
</html>`;
}

/** The subset of a panva consent-prompt `details` we surface to the user. */
interface ConsentPromptDetails {
  missingOIDCScope?: string[];
  missingOIDCClaims?: string[];
  missingResourceScopes?: Record<string, string[]>;
}

/**
 * Interactive consent page for a NON-trusted (third-party) client (TD-8
 * fall-through). Unlike the trusted-set auto-grant, this requires the user to
 * explicitly POST /consent/approve before any Grant is persisted. The page is
 * dependency-free plain HTML+JS, mirroring the SIWE interaction page.
 */
function renderConsentPage(opts: {
  uid: string;
  clientId: string;
  details: ConsentPromptDetails;
}): string {
  const scopes = (opts.details.missingOIDCScope ?? []).join(' ');
  const claims = (opts.details.missingOIDCClaims ?? []).join(', ');
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Authorize ${escapeHtml(opts.clientId)}</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 28rem; margin: 4rem auto; padding: 0 1rem; color: #111; }
  button { font-size: 1rem; padding: 0.6rem 1.1rem; border-radius: 0.5rem; border: 1px solid #8ecc09; background: #8ecc09; color: #082; cursor: pointer; }
  button:disabled { opacity: 0.6; cursor: default; }
  #status { margin-top: 1rem; color: #555; white-space: pre-wrap; }
  code { background: #f3f3f3; padding: 0.1rem 0.3rem; border-radius: 0.25rem; }
</style>
</head>
<body>
  <h1>Authorize <code>${escapeHtml(opts.clientId)}</code></h1>
  <p>This application is requesting access to your Citrate identity.</p>
  <p>Scopes: <code>${escapeHtml(scopes || '(none)')}</code></p>
  ${claims ? `<p>Claims: <code>${escapeHtml(claims)}</code></p>` : ''}
  <button id="approve" type="button">Approve</button>
  <p id="status" role="status"></p>
<script>
const statusEl = document.getElementById('status');
const btn = document.getElementById('approve');
btn.addEventListener('click', async () => {
  btn.disabled = true;
  statusEl.textContent = 'Authorizing…';
  try {
    const res = await fetch('/consent/approve', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      credentials: 'same-origin',
      body: '{}',
    });
    const result = await res.json();
    if (!res.ok || !result.redirectTo) {
      statusEl.textContent = 'Authorization failed: ' + (result.reason || res.status);
      btn.disabled = false;
      return;
    }
    statusEl.textContent = 'Authorized. Redirecting…';
    window.location = result.redirectTo;
  } catch (err) {
    statusEl.textContent = 'Error: ' + (err && err.message ? err.message : String(err));
    btn.disabled = false;
  }
});
</script>
</body>
</html>`;
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
 * Auto-consent for a trusted first-party client (TD-8). Builds (or extends) the
 * client's Grant for this account with exactly the OIDC scopes + claims +
 * resource scopes the consent prompt reports as still missing, persists it, and
 * resumes the interaction via `interactionResult({ consent: { grantId } })`.
 * Returns the `redirectTo` URL panva computed for resuming the /auth flow.
 *
 * The trust decision lives in {@link isTrustedFirstPartyClient} (config.ts), so
 * adding/removing an RP is a one-line change to the trusted set — there is no
 * per-client branch here.
 */
async function grantConsent(
  provider: Provider,
  ctx: { req: IncomingMessage; res: ServerResponse },
  interaction: NonNullable<Awaited<ReturnType<typeof provider.interactionDetails>>>,
): Promise<string> {
  const { session, params, prompt, grantId } = interaction;
  const accountId = session?.accountId;
  if (!accountId) {
    // The login prompt always precedes consent, so a consent prompt without a
    // session is an invariant violation rather than an expected branch.
    throw new Error('consent prompt reached without an authenticated session');
  }
  const clientId = String(params.client_id);

  // Reuse an existing grant for this client+account if one is already on the
  // interaction; otherwise mint a fresh one.
  let grant = grantId
    ? await provider.Grant.find(grantId)
    : undefined;
  if (!grant) {
    grant = new provider.Grant({ accountId, clientId });
  }

  const details = prompt.details as {
    missingOIDCScope?: string[];
    missingOIDCClaims?: string[];
    missingResourceScopes?: Record<string, string[]>;
  };
  if (details.missingOIDCScope) {
    grant.addOIDCScope(details.missingOIDCScope.join(' '));
  }
  if (details.missingOIDCClaims) {
    grant.addOIDCClaims(details.missingOIDCClaims);
  }
  if (details.missingResourceScopes) {
    for (const [resource, scopes] of Object.entries(details.missingResourceScopes)) {
      grant.addResourceScope(resource, scopes.join(' '));
    }
  }

  const persistedGrantId = await grant.save();
  const redirectTo = await provider.interactionResult(
    ctx.req,
    ctx.res,
    { consent: { grantId: persistedGrantId } },
    { mergeWithLastSubmission: true },
  );
  return redirectTo;
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

  // The chainId every SIWE message must bind to, surfaced to the page so the
  // wallet signs for Citrate and the authority's chain check passes.
  const chainId = options.chainId ?? CITRATE_CHAIN_ID;

  provider.use(async (ctx, next) => {
    const { method, path } = ctx;

    // GET /interaction/:uid — the custom interaction view. panva 303s here
    // (interactions.url in config) whenever an in-flight /auth request needs a
    // prompt. Two prompts occur for the explorer flow:
    //   - `login`   → render the SIWE sign-in page (Path A drives the rest).
    //   - `consent` → the explorer is a trusted first-party RP, so grant the
    //                 requested OIDC scopes/claims automatically and resume.
    if (method === 'GET' && /^\/interaction\/[^/]+$/.test(path)) {
      const uid = path.slice('/interaction/'.length);
      let interaction: Awaited<
        ReturnType<typeof provider.interactionDetails>
      > | null = null;
      try {
        const details = await provider.interactionDetails(ctx.req, ctx.res);
        // Confirm the cookie-bound interaction matches the requested uid so a
        // stale/forged uid in the URL can't render a usable surface.
        if (details && details.uid === uid) interaction = details;
      } catch {
        interaction = null;
      }
      if (!interaction) {
        sendHtml(
          ctx.res,
          400,
          '<!doctype html><meta charset="utf-8"><p>This sign-in session is invalid or has expired. Start over from the application.</p>',
        );
        return;
      }

      const promptName = interaction.prompt.name;

      if (promptName === 'consent') {
        const clientId = String(interaction.params.client_id);
        // TD-8: auto-consent only for clients in the trusted first-party set
        // (config.ts). Build (or extend) the Grant with exactly the scopes/claims
        // the request is still missing, then resume. This is real consent
        // persisted as a Grant — not a bypass of the authorization model.
        if (isTrustedFirstPartyClient(clientId)) {
          const redirectTo = await grantConsent(provider, ctx, interaction);
          ctx.res.writeHead(303, {
            location: redirectTo,
            'cache-control': 'no-store',
          });
          ctx.res.end();
          return;
        }
        // Untrusted / third-party client: fall through to an explicit consent
        // prompt. The user must POST /consent/approve to grant — no auto-grant.
        sendHtml(
          ctx.res,
          200,
          renderConsentPage({
            uid,
            clientId,
            details: interaction.prompt.details as ConsentPromptDetails,
          }),
        );
        return;
      }

      if (promptName === 'login') {
        sendHtml(
          ctx.res,
          200,
          renderInteractionPage({
            uid,
            domain: options.expectedDomain,
            uri: options.issuer,
            chainId,
            statement: 'Sign in to Citrate',
          }),
        );
        return;
      }

      // Any other prompt is not supported by this minimal authority.
      sendHtml(
        ctx.res,
        400,
        `<!doctype html><meta charset="utf-8"><p>Unsupported interaction prompt: ${escapeHtml(
          promptName,
        )}.</p>`,
      );
      return;
    }

    if (method === 'GET' && path === '/siwe/challenge') {
      const nonce = await nonceStore.issue();
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

    // POST /consent/approve — explicit user approval for a NON-trusted client's
    // consent prompt (TD-8 fall-through). The cookie-bound interaction must be a
    // live consent prompt; we then persist the same kind of real Grant the
    // trusted path builds and resume the /auth flow.
    if (method === 'POST' && path === '/consent/approve') {
      let interaction: Awaited<
        ReturnType<typeof provider.interactionDetails>
      > | null = null;
      try {
        interaction = await provider.interactionDetails(ctx.req, ctx.res);
      } catch {
        interaction = null;
      }
      if (!interaction || interaction.prompt.name !== 'consent') {
        sendJson(ctx.res, 400, {
          error: 'invalid_request',
          reason: 'no active consent interaction',
        });
        return;
      }
      const redirectTo = await grantConsent(provider, ctx, interaction);
      sendJson(ctx.res, 200, { redirectTo });
      return;
    }

    await next();
  });

  return nonceStore;
}
