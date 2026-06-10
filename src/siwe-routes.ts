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
  /**
   * WalletConnect Cloud project id. When set, the interaction page additionally
   * offers the WalletConnect (QR / mobile) connector — it lazy-loads
   * `@walletconnect/ethereum-provider` from a CDN and `personal_sign`s the SAME
   * EIP-4361 message. When UNSET the WalletConnect button is omitted entirely and
   * only the injected (`window.ethereum`) connector is shown — injected login is
   * never blocked by a missing project id (not fail-closed).
   */
  walletConnectProjectId?: string;
  /**
   * FUA-IDENTITY-01 (SECREM-02): enable the out-of-band "Path B" direct ID-token
   * mint on `/siwe/verify` (a token signed by the authority JWKS for a caller
   * with NO active OIDC interaction — no PKCE, no consent, no redirect_uri). This
   * sidesteps the authorization-code machinery, so it is **disabled by default**
   * (fail closed). Enable ONLY for a deliberate headless/server integration, in
   * which case {@link audience} MUST name a registered first-party client so the
   * minted token is bound to a real RP. Browser RPs use the code flow (Path A)
   * and never need this.
   */
  allowDirectTokenGrant?: boolean;
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
 * Serialize a value as JSON safe to embed inside an inline `<script>` block
 * (FUA-IDENTITY-07). `JSON.stringify` does NOT escape `<`, `>`, `&`, U+2028, or
 * U+2029, so a value containing `</script>` would break out of the script
 * context. We escape those to their `\uXXXX` forms — still valid JS string
 * content, but inert as markup — so a hostile `client_id` (or any embedded
 * value) cannot inject script. Mirrors the standard "JSON for `<script>`" guard.
 */
export function jsonForScript(value: unknown): string {
  return JSON.stringify(value)
    .replace(/</g, '\\u003c')
    .replace(/>/g, '\\u003e')
    .replace(/&/g, '\\u0026')
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029');
}

/**
 * Reject cross-site state-changing POSTs (FUA-IDENTITY-04 — login-CSRF /
 * forced-consent). The SIWE interaction (`/siwe/verify` Path A) and
 * `/consent/approve` mutate the cookie-bound interaction, so a cross-site POST
 * carrying the victim's interaction cookie must be refused. Returns `true` iff
 * the request is safe to act on:
 *   - `Sec-Fetch-Site` present (modern browsers, unforgeable by page JS): allow
 *     only `same-origin` / `none` (a top-level same-site navigation).
 *   - else fall back to `Origin`: allow only the authority's own origin.
 *   - no browser signals at all → a non-browser client (no ambient cookie / not
 *     a CSRF vector) → allow, so API clients and tests are unaffected.
 * RP origins are intentionally NOT allowed here: these are the authority's own
 * interaction pages, never driven cross-origin by an RP.
 */
function isSameOriginRequest(req: IncomingMessage, issuerOrigin: string): boolean {
  const header = (name: string): string | undefined => {
    const v = req.headers[name];
    return Array.isArray(v) ? v[0] : v;
  };
  const secFetchSite = header('sec-fetch-site');
  if (secFetchSite !== undefined) {
    return secFetchSite === 'same-origin' || secFetchSite === 'none';
  }
  const origin = header('origin');
  if (origin !== undefined) {
    return origin === issuerOrigin;
  }
  return true; // no browser signals → not a browser CSRF vector
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
  /** A friendly name for the app being signed into (the client_id). */
  clientId: string;
  /** WalletConnect Cloud project id, or undefined to hide that connector. */
  walletConnectProjectId?: string;
}): string {
  // Values that land inside the inline script as JSON literals. The
  // walletConnectProjectId is included only when configured; its presence is
  // what the page uses to decide whether to render the WalletConnect button.
  // FUA-IDENTITY-07: serialize for the inline <script> with jsonForScript (not
  // raw JSON.stringify) so a hostile clientId / value cannot break out of the
  // script context.
  const cfg = jsonForScript({
    uid: opts.uid,
    domain: opts.domain,
    uri: opts.uri,
    chainId: opts.chainId,
    statement: opts.statement,
    clientId: opts.clientId,
    walletConnectProjectId: opts.walletConnectProjectId ?? null,
  });
  const hasWalletConnect = Boolean(opts.walletConnectProjectId);
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Sign in to Citrate</title>
<link rel="preconnect" href="https://fonts.googleapis.com" />
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Geist:wght@400;500;600&family=Source+Serif+4:opsz,wght@8..60,400;8..60,600&display=swap" />
<style>
  :root {
    /* Citrate brand: green primary on a clean paper/ink palette. */
    --brand: #8ecc09;
    --brand-ink: #2f4d00;
    --brand-hover: #7eb808;
    --paper: #fbfbf8;
    --card: #ffffff;
    --ink: #14150f;
    --muted: #6b6f63;
    --line: #e7e8e0;
    --danger: #b42318;
    --serif: 'Source Serif 4', Georgia, 'Times New Roman', serif;
    --sans: 'Geist', system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
  }
  * { box-sizing: border-box; }
  body {
    font-family: var(--sans);
    margin: 0; min-height: 100vh;
    display: flex; align-items: center; justify-content: center;
    background: var(--paper); color: var(--ink);
    padding: 1.5rem;
    -webkit-font-smoothing: antialiased;
  }
  .card {
    width: 100%; max-width: 26rem;
    background: var(--card);
    border: 1px solid var(--line);
    border-radius: 1rem;
    padding: 2rem 1.75rem;
    box-shadow: 0 1px 2px rgba(20,21,15,0.04), 0 8px 24px rgba(20,21,15,0.06);
  }
  .brand { display: flex; align-items: center; gap: 0.6rem; margin-bottom: 1.5rem; }
  .brand .dot {
    width: 1.5rem; height: 1.5rem; border-radius: 0.45rem;
    background: var(--brand);
    box-shadow: 0 0 0 4px rgba(142,204,9,0.18);
    flex: none;
  }
  .brand .name { font-family: var(--serif); font-weight: 600; font-size: 1.15rem; letter-spacing: -0.01em; }
  h1 { font-family: var(--serif); font-weight: 600; font-size: 1.55rem; line-height: 1.15; margin: 0 0 0.5rem; letter-spacing: -0.02em; }
  .lede { color: var(--muted); margin: 0 0 1.5rem; font-size: 0.95rem; line-height: 1.5; }
  .app-chip {
    display: inline-flex; align-items: center; gap: 0.4rem;
    background: rgba(142,204,9,0.12); color: var(--brand-ink);
    border: 1px solid rgba(142,204,9,0.35);
    padding: 0.15rem 0.55rem; border-radius: 999px;
    font-weight: 500; font-size: 0.85rem;
  }
  .connected {
    display: none; align-items: center; gap: 0.5rem;
    margin-bottom: 1rem; padding: 0.6rem 0.75rem;
    background: var(--paper); border: 1px solid var(--line); border-radius: 0.6rem;
    font-size: 0.85rem;
  }
  .connected.show { display: flex; }
  .connected .addr { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; color: var(--ink); }
  .actions { display: grid; gap: 0.6rem; }
  button {
    font-family: var(--sans);
    font-size: 0.98rem; font-weight: 500;
    padding: 0.75rem 1rem; border-radius: 0.65rem;
    border: 1px solid transparent; cursor: pointer;
    display: flex; align-items: center; justify-content: center; gap: 0.5rem;
    transition: background 120ms ease, border-color 120ms ease, opacity 120ms ease;
  }
  button.primary { background: var(--brand); color: var(--brand-ink); border-color: var(--brand); }
  button.primary:hover:not(:disabled) { background: var(--brand-hover); border-color: var(--brand-hover); }
  button.secondary { background: var(--card); color: var(--ink); border-color: var(--line); }
  button.secondary:hover:not(:disabled) { border-color: var(--brand); }
  button:disabled { opacity: 0.55; cursor: default; }
  #status {
    margin-top: 1.1rem; min-height: 1.2rem;
    color: var(--muted); font-size: 0.88rem; line-height: 1.45; white-space: pre-wrap;
  }
  #status.error { color: var(--danger); }
  .meta { margin-top: 1.5rem; padding-top: 1rem; border-top: 1px solid var(--line); color: var(--muted); font-size: 0.78rem; line-height: 1.5; }
  .meta code { background: var(--paper); border: 1px solid var(--line); padding: 0.05rem 0.3rem; border-radius: 0.3rem; }
</style>
</head>
<body>
  <main class="card">
    <div class="brand"><span class="dot" aria-hidden="true"></span><span class="name">Citrate</span></div>
    <h1>Sign in with your wallet</h1>
    <p class="lede">Continue to <span class="app-chip" id="app-name">${escapeHtml(opts.clientId)}</span> by signing a message on the Citrate network. No transaction, no gas.</p>
    <div class="connected" id="connected" role="status">
      <span aria-hidden="true">&#128081;</span>
      <span>Connected as <span class="addr" id="connected-addr"></span></span>
    </div>
    <div class="actions">
      <button id="signin-injected" class="primary" type="button">Connect a browser wallet</button>
      ${hasWalletConnect ? '<button id="signin-walletconnect" class="secondary" type="button">Use WalletConnect (mobile / QR)</button>' : ''}
    </div>
    <p id="status" role="status"></p>
    <p class="meta">Authenticating to <code>${escapeHtml(opts.domain)}</code> on chain ${opts.chainId}. You are signing a Sign-In with Ethereum (EIP-4361) message; it proves you control your address and is never a transaction.</p>
  </main>
<script>
const CFG = ${cfg};
const statusEl = document.getElementById('status');
const injectedBtn = document.getElementById('signin-injected');
const wcBtn = document.getElementById('signin-walletconnect');
const connectedEl = document.getElementById('connected');
const connectedAddrEl = document.getElementById('connected-addr');

function setStatus(msg, isError) {
  statusEl.textContent = msg;
  statusEl.classList.toggle('error', Boolean(isError));
}
function showConnected(address) {
  connectedAddrEl.textContent = address;
  connectedEl.classList.add('show');
}
function setBusy(busy) {
  injectedBtn.disabled = busy;
  if (wcBtn) wcBtn.disabled = busy;
}

// Build a canonical EIP-4361 message string. Mirrors the fields the authority
// verifies: domain (anti-phishing), uri, chainId (Citrate), nonce, issuedAt,
// expirationTime, and the signing address. Both connectors sign THIS string.
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

// Shared tail: fetch a fresh nonce, sign the EIP-4361 message via the given
// EIP-1193 provider's personal_sign, POST /siwe/verify, follow redirectTo.
async function completeSignIn(provider, address) {
  setStatus('Fetching challenge…');
  const challengeRes = await fetch('/siwe/challenge', { credentials: 'same-origin' });
  const { nonce } = await challengeRes.json();

  const message = buildSiweMessage(address, nonce);
  setStatus('Check your wallet to sign the message…');
  const signature = await provider.request({
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
    setStatus('Sign-in failed: ' + (result.reason || result.error || verifyRes.status), true);
    return false;
  }
  setStatus('Signed in. Redirecting…');
  window.location = result.redirectTo;
  return true;
}

// EIP-1193 user-rejection codes: 4001 (rejected request) is the common one.
function describeError(err) {
  if (err && (err.code === 4001 || err.code === 'ACTION_REJECTED')) {
    return 'You declined the signature. Try again when ready.';
  }
  return (err && err.message ? err.message : String(err));
}

// --- Injected connector (window.ethereum personal_sign). ---
async function signInInjected() {
  setBusy(true);
  try {
    if (!window.ethereum) {
      setStatus('No browser wallet found. Install one (e.g. MetaMask) or use WalletConnect.', true);
      setBusy(false);
      return;
    }
    setStatus('Requesting wallet…');
    const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
    const address = accounts[0];
    showConnected(address);
    const ok = await completeSignIn(window.ethereum, address);
    if (!ok) setBusy(false);
  } catch (err) {
    setStatus('Error: ' + describeError(err), true);
    setBusy(false);
  }
}
injectedBtn.addEventListener('click', signInInjected);

// --- WalletConnect connector (QR / mobile), only when a project id is set. ---
${
  hasWalletConnect
    ? `
async function signInWalletConnect() {
  setBusy(true);
  try {
    setStatus('Starting WalletConnect…');
    // Lazy-load the provider from a CDN ESM build — no bundler/build step.
    const { EthereumProvider } = await import('https://esm.sh/@walletconnect/ethereum-provider@2');
    const wc = await EthereumProvider.init({
      projectId: CFG.walletConnectProjectId,
      chains: [CFG.chainId],
      showQrModal: true,
      metadata: {
        name: 'Citrate',
        description: 'Sign in to Citrate',
        url: CFG.uri,
        icons: [],
      },
    });
    setStatus('Scan the QR code or approve in your wallet…');
    await wc.connect();
    const accounts = wc.accounts || (await wc.request({ method: 'eth_accounts' }));
    const address = accounts[0];
    if (!address) throw new Error('WalletConnect returned no account');
    // Guard against a wallet that connected on a different chain.
    if (typeof wc.chainId === 'number' && wc.chainId !== CFG.chainId) {
      setStatus('Wrong network: please switch your wallet to Citrate (chain ' + CFG.chainId + ').', true);
      try { await wc.disconnect(); } catch (e) {}
      setBusy(false);
      return;
    }
    showConnected(address);
    const ok = await completeSignIn(wc, address);
    if (!ok) {
      try { await wc.disconnect(); } catch (e) {}
      setBusy(false);
    }
  } catch (err) {
    setStatus('Error: ' + describeError(err), true);
    setBusy(false);
  }
}
wcBtn.addEventListener('click', signInWalletConnect);
`
    : ''
}
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

  // The authority's own origin, for the cross-site (CSRF) guard on the
  // state-changing interaction POSTs (FUA-IDENTITY-04).
  let issuerOrigin: string;
  try {
    issuerOrigin = new URL(options.issuer).origin;
  } catch {
    issuerOrigin = options.issuer;
  }

  // FUA-IDENTITY-01: the out-of-band direct-token path is off unless explicitly
  // enabled. When enabled it MUST be bound to a registered first-party client
  // via `audience` — fail closed at mount rather than mint unbound tokens.
  const directTokenAudience = options.audience ?? 'citrate-explorer';
  if (options.allowDirectTokenGrant && !isTrustedFirstPartyClient(directTokenAudience)) {
    throw new Error(
      `allowDirectTokenGrant requires options.audience to be a registered first-party client (got "${directTokenAudience}")`,
    );
  }

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
        // Surface the app being signed into (the client_id) so the page can show
        // it; fall back to a generic label if the interaction has no client_id.
        const clientId = interaction.params.client_id
          ? String(interaction.params.client_id)
          : 'a Citrate app';
        sendHtml(
          ctx.res,
          200,
          renderInteractionPage({
            uid,
            domain: options.expectedDomain,
            uri: options.issuer,
            chainId,
            statement: 'Sign in to Citrate',
            clientId,
            ...(options.walletConnectProjectId
              ? { walletConnectProjectId: options.walletConnectProjectId }
              : {}),
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
          // FUA-IDENTITY-04: interactionResult resolves the cookie-bound login
          // (a state change). Refuse a cross-site POST carrying the victim's
          // interaction cookie (login-CSRF). Same-origin browser requests and
          // non-browser API clients are unaffected.
          if (!isSameOriginRequest(ctx.req, issuerOrigin)) {
            sendJson(ctx.res, 403, {
              error: 'invalid_request',
              reason: 'cross_site_forbidden',
            });
            return;
          }
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
      // FUA-IDENTITY-01: off unless explicitly enabled. This path mints an
      // authority-signed token with no PKCE/consent/redirect_uri, so a default
      // deployment fails closed and directs callers to the code flow (Path A).
      if (!options.allowDirectTokenGrant) {
        sendJson(ctx.res, 400, {
          error: 'invalid_request',
          reason:
            'no active OIDC interaction; the direct token grant is disabled — use the authorization code flow',
        });
        return;
      }
      const claims = await accountClaimsFor(provider, ctx, accountId);
      const idToken = await mintIdToken(
        {
          issuer: options.issuer,
          signingJwk: options.signingJwk,
          // Bound to a registered first-party client (validated at mount).
          audience: directTokenAudience,
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
      // FUA-IDENTITY-04: persisting a consent Grant is a state change; refuse a
      // cross-site POST riding the victim's interaction cookie (forced-consent).
      if (!isSameOriginRequest(ctx.req, issuerOrigin)) {
        sendJson(ctx.res, 403, {
          error: 'invalid_request',
          reason: 'cross_site_forbidden',
        });
        return;
      }
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
