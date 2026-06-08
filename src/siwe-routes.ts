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
   * True iff Google federation is configured (env `CITRATE_AA_GOOGLE_CLIENT_ID`
   * set). When true the interaction page renders an active "Continue with
   * Google" button on the Google tab; when false the tab still appears but
   * shows a one-line "not enabled" message. The actual /auth/google/* routes
   * are mounted in a follow-up WP — this flag only governs the UI.
   */
  googleEnabled?: boolean;
  /**
   * Build version surfaced in the interaction page footer (e.g. the package
   * version). Defaults to "dev" so tests don't need to thread it.
   */
  version?: string;
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
 * The branded `/interaction/:uid` login surface (WP-6 slice B).
 *
 * Four sign-in methods, served as one self-contained HTML document:
 *
 *   - **PASSKEY** — `/auth/webauthn/authenticate-{options,verify}`. Default
 *     tab. Discoverable credentials: `allowCredentials=[]` so the browser
 *     surfaces any resident credential the user has.
 *   - **EMAIL / PASSWORD** — `/auth/password/{login,register}`. Single form,
 *     "Sign in" + "Register" buttons.
 *   - **GOOGLE** — `/auth/google/start` (UI conditional on
 *     {@link SiweRouteOptions.googleEnabled}). When the env is unset, the
 *     tab is still rendered but shows the "not enabled" copy the §5
 *     acceptance bar names.
 *   - **SIWE** — preserves the existing EIP-4361 flow byte-for-byte: same
 *     `/siwe/challenge` → `/siwe/verify` → `interactionResult` path the
 *     prior page drove, same connector IDs (`signin-injected`,
 *     `signin-walletconnect`) the SIWE e2e test asserts on.
 *
 * The visual system is the explorer's `scan.css` tokens verbatim — warm
 * paper canvas (`#f1eee6`), Citrate accent green (`#8ecc09`), 6px buttons,
 * 9px cards, the evergreen sticky header. Fonts are self-hosted from
 * `/fonts/*` (no CDN); brand SVGs from `/brand/*` (no inline placeholders).
 *
 * The page is dependency-free plain HTML + JS. The SIWE e2e test does not
 * load this page in a browser — it performs the SIWE flow over HTTP with
 * a viem EOA — but this page is the real human surface for the same flow.
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
  /** True iff `/auth/google/start` is mounted and ready (env was set). */
  googleEnabled: boolean;
  /** Footer build-version string. */
  version: string;
}): string {
  // Inline config the page JS reads. WalletConnect project id is included
  // only when configured; its presence is what the SIWE tab uses to decide
  // whether to wire the WalletConnect button.
  const cfg = JSON.stringify({
    uid: opts.uid,
    domain: opts.domain,
    uri: opts.uri,
    chainId: opts.chainId,
    statement: opts.statement,
    clientId: opts.clientId,
    walletConnectProjectId: opts.walletConnectProjectId ?? null,
  });
  const hasWalletConnect = Boolean(opts.walletConnectProjectId);
  const googleEnabled = opts.googleEnabled;

  // The custom 1.5-stroke `currentColor` icon glyphs lifted verbatim from
  // citrate-explorer/src/scan/icons.tsx. Inlined as SVG strings to avoid
  // shipping a runtime icon dependency.
  const ICON_KEY = '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="8" cy="8" r="4"/><path d="M10.8 10.8 L20 20 M17 17 L19 15 M14.5 14.5 L16.5 12.5"/></svg>';
  const ICON_MAIL = '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="5" width="18" height="14" rx="2"/><path d="M3 7 L12 13 L21 7"/></svg>';
  const ICON_GOOGLE = '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 7 v10 M7 12 h10"/></svg>';
  const ICON_WALLET = '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="6" width="18" height="13" rx="2.5"/><path d="M3 10 H21 M16.5 14 h.01"/></svg>';
  const ICON_SHIELD = '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3 L19 6 V11 c0 5-3 8-7 10 c-4-2-7-5-7-10 V6 Z"/><path d="M9 12 L11 14 L15 9.5"/></svg>';

  return `<!doctype html>
<html lang="en" data-theme="light">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Sign in to Citrate</title>
<style>
/* Self-hosted brand fonts — no Google CDN, no leaks, CSP-tight. */
@font-face { font-family: 'Geist'; src: url('/fonts/Geist-Regular.woff2') format('woff2'); font-weight: 400; font-style: normal; font-display: swap; }
@font-face { font-family: 'Geist'; src: url('/fonts/Geist-Medium.woff2') format('woff2'); font-weight: 500; font-style: normal; font-display: swap; }
@font-face { font-family: 'Geist'; src: url('/fonts/Geist-SemiBold.woff2') format('woff2'); font-weight: 600; font-style: normal; font-display: swap; }
@font-face { font-family: 'Geist Mono'; src: url('/fonts/GeistMono-Regular.woff2') format('woff2'); font-weight: 400; font-style: normal; font-display: swap; }
@font-face { font-family: 'Geist Mono'; src: url('/fonts/GeistMono-Medium.woff2') format('woff2'); font-weight: 500; font-style: normal; font-display: swap; }
@font-face { font-family: 'Space Grotesk'; src: url('/fonts/SpaceGrotesk.ttf') format('truetype'); font-weight: 100 900; font-style: normal; font-display: swap; }
@font-face { font-family: 'Cormorant'; src: url('/fonts/Cormorant.ttf') format('truetype'); font-weight: 300 700; font-style: normal; font-display: swap; }

/* Design tokens — lifted verbatim from citrate-explorer/src/scan/scan.css
   light theme (lines 22-53). The same warm paper canvas + Citrate accent
   green visual system the explorer ships, so the two surfaces agree. */
:root {
  --font-display: 'Space Grotesk', system-ui, sans-serif;
  --font-sans: 'Geist', system-ui, -apple-system, "Segoe UI", sans-serif;
  --font-mono: 'Geist Mono', ui-monospace, "SF Mono", Menlo, monospace;
  --font-serif: 'Cormorant', Georgia, "Times New Roman", serif;
  --tr-eyebrow: 0.14em;
  --r-1: 6px; --r-2: 9px; --r-pill: 999px;
  --canvas:        #f1eee6;
  --surface:       #faf8f3;
  --surface-2:     #ffffff;
  --surface-sunk:  #ecebe4;
  --border:        #dbdcd5;
  --border-2:      #e6e5df;
  --border-strong: #c3c4be;
  --text-1:        #0e0f0c;
  --text-2:        #555851;
  --text-3:        #8a8c84;
  --accent:        #8ecc09;
  --accent-deep:   #5a8205;
  --accent-text:   #4f7304;
  --accent-tint:   #e8f3c6;
  --danger:        #a72414;
  --danger-bg:     #f6e1de;
  --header-bg:     #0f2a1a;
  --header-fg:     #f1eee6;
  --header-fg-2:   #9db8a6;
  --header-border: rgba(205,231,214,.12);
  --header-field:  rgba(255,255,255,.06);
  --shadow-lift:   0 14px 38px -18px rgba(14,15,12,.30), 0 0 0 1px var(--border);
}
* { box-sizing: border-box; }
html, body { margin: 0; padding: 0; }
body {
  background: var(--canvas); color: var(--text-1);
  font-family: var(--font-sans);
  -webkit-font-smoothing: antialiased;
  text-rendering: optimizeLegibility;
  min-height: 100vh; display: flex; flex-direction: column;
}
button { font-family: inherit; cursor: pointer; }
input { font-family: inherit; }
::selection { background: var(--accent); color: #0e0f0c; }
:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }

/* Eyebrow — Geist Mono 11px uppercase letter-spaced. */
.eyebrow {
  font-family: var(--font-mono);
  font-size: 11px; font-weight: 500;
  letter-spacing: var(--tr-eyebrow); text-transform: uppercase;
  color: var(--accent-text);
}

/* Sticky evergreen header. */
.hdr {
  position: sticky; top: 0; z-index: 60;
  background: var(--header-bg); color: var(--header-fg);
  border-bottom: 1px solid var(--header-border);
  height: 64px; display: flex; align-items: center; gap: 18px;
  padding: 0 20px;
}
.hdr-logo { display: flex; align-items: center; gap: 10px; flex-shrink: 0; }
.hdr-logo img { height: 24px; display: block; }
.hdr-right { margin-left: auto; display: flex; align-items: center; gap: 12px; }
.chainbadge {
  display: flex; align-items: center; gap: 9px;
  padding: 5px 11px; border-radius: var(--r-pill);
  border: 1px solid var(--header-border);
  font-size: 12px; font-family: var(--font-mono);
}
.chainbadge .dot {
  width: 7px; height: 7px; border-radius: 50%;
  background: var(--accent);
  box-shadow: 0 0 0 3px rgba(142,204,9,.2);
}
.chainbadge .k { color: var(--header-fg-2); }
.chainbadge .v { color: var(--header-fg); font-variant-numeric: tabular-nums; }

/* Main + card. */
.main { flex: 1; display: flex; align-items: center; justify-content: center; padding: 40px 24px; }
.card {
  width: 100%; max-width: 28rem;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--r-2);
  box-shadow: var(--shadow-lift);
  padding: 28px 28px 24px;
}
.card .app-chip {
  display: inline-flex; align-items: center; gap: 6px;
  font-family: var(--font-mono); font-size: 11px; font-weight: 500;
  letter-spacing: 0.03em; text-transform: uppercase;
  color: var(--accent-text);
  background: var(--accent-tint);
  border: 1px solid color-mix(in srgb, var(--accent) 40%, transparent);
  border-radius: var(--r-pill);
  padding: 3px 9px;
}
h1 {
  font-family: var(--font-display); font-weight: 500;
  font-size: 30px; line-height: 1.15; letter-spacing: -0.015em;
  color: var(--text-1);
  margin: 14px 0 8px;
}
.lede {
  font-family: var(--font-serif); font-weight: 400;
  font-size: 16px; line-height: 1.45;
  color: var(--text-2);
  margin: 0 0 22px;
}

/* Method tabs. */
.tabs {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 6px;
  border: 1px solid var(--border);
  background: var(--surface-sunk);
  border-radius: var(--r-1);
  padding: 4px;
  margin-bottom: 22px;
}
.tabs button {
  height: 34px; padding: 0 6px;
  border: 1px solid transparent;
  background: transparent;
  border-radius: 4px;
  font-family: var(--font-mono); font-size: 11px; font-weight: 500;
  letter-spacing: var(--tr-eyebrow); text-transform: uppercase;
  color: var(--text-2);
  display: inline-flex; align-items: center; justify-content: center; gap: 6px;
  transition: background .15s, color .15s, border-color .15s;
}
.tabs button:hover { color: var(--text-1); }
.tabs button[aria-selected="true"] {
  background: var(--surface-2);
  color: var(--accent-text);
  border-color: var(--border);
  box-shadow: 0 1px 2px rgba(14,15,12,.06);
}

.panel { display: none; }
.panel[data-active="true"] { display: block; }

/* Buttons + inputs. */
.btn {
  height: 38px; padding: 0 16px;
  border-radius: var(--r-1); border: 1px solid var(--border);
  background: var(--surface-2); color: var(--text-1);
  font-weight: 500; font-size: 13.5px;
  display: inline-flex; align-items: center; justify-content: center; gap: 8px;
  transition: border-color .15s ease-out, background .15s ease-out;
  width: 100%;
}
.btn:hover:not(:disabled) { border-color: var(--border-strong); }
.btn.primary {
  background: var(--accent); border-color: var(--accent);
  color: #112005; font-weight: 600;
}
.btn.primary:hover:not(:disabled) { filter: brightness(1.04); }
.btn.ghost { background: transparent; border-color: transparent; color: var(--text-2); }
.btn:disabled { opacity: 0.5; cursor: default; }

.field { display: grid; gap: 6px; margin-bottom: 12px; }
.field label {
  font-family: var(--font-mono);
  font-size: 11px; font-weight: 500;
  letter-spacing: var(--tr-eyebrow); text-transform: uppercase;
  color: var(--text-3);
}
.field input {
  height: 38px; padding: 0 12px;
  border-radius: var(--r-1); border: 1px solid var(--border);
  background: var(--surface-2); color: var(--text-1);
  font-size: 14px;
  transition: border-color .15s, background .15s;
}
.field input:focus { outline: none; border-color: var(--accent); }
.actions { display: grid; gap: 10px; margin-top: 4px; }
.row { display: flex; gap: 8px; align-items: center; justify-content: space-between; }

.altlink { display: block; text-align: center; margin-top: 12px; font-size: 13px; color: var(--text-2); background: none; border: none; cursor: pointer; }
.altlink:hover { color: var(--accent-text); }

.note {
  display: flex; gap: 9px; padding: 12px 13px;
  border-radius: var(--r-1);
  font-size: 13px; line-height: 1.5;
  color: var(--text-2);
  background: var(--surface-sunk);
  border: 1px solid var(--border-2);
}
.note .ic { flex-shrink: 0; color: var(--text-3); margin-top: 1px; }

#status {
  margin-top: 14px; min-height: 1.2rem;
  color: var(--text-2); font-size: 13px; line-height: 1.45;
  white-space: pre-wrap;
}
#status.error { color: var(--danger); }

/* Connected hint shown by the SIWE flow when an EOA address is in scope. */
.connected {
  display: none; align-items: center; gap: 8px;
  margin-bottom: 12px; padding: 10px 12px;
  background: var(--surface-2);
  border: 1px solid var(--border);
  border-radius: var(--r-1);
  font-size: 13px;
}
.connected.show { display: flex; }
.connected .addr { font-family: var(--font-mono); color: var(--text-1); }

/* Footer eyebrow row. */
.footer-eyebrow {
  margin: 18px auto 28px;
  font-family: var(--font-mono);
  font-size: 11px; font-weight: 500;
  letter-spacing: var(--tr-eyebrow); text-transform: uppercase;
  color: var(--text-3);
  text-align: center;
}
.footer-eyebrow .sep { margin: 0 8px; color: var(--border-strong); }

@media (prefers-reduced-motion: reduce) {
  * { transition-duration: .001ms !important; }
}

/* Narrow viewports (phones): 4-column tab row squishes the icons + labels
   under ~480px. Drop to a 2×2 grid + tighter card padding so the whole
   card still fits in the viewport without horizontal scroll. */
@media (max-width: 480px) {
  .main { padding: 16px 12px; }
  .card { padding: 20px 18px 18px; }
  h1 { font-size: 26px; }
  .lede { font-size: 15px; margin-bottom: 18px; }
  .tabs {
    grid-template-columns: repeat(2, 1fr);
    gap: 4px;
  }
  .tabs button { height: 38px; }
  .field input { font-size: 16px; } /* iOS Safari avoids autozoom at >=16px */
  .footer-eyebrow { font-size: 10px; }
}

/* Very narrow (<360px, old/small phones): single column. */
@media (max-width: 360px) {
  .tabs { grid-template-columns: 1fr; }
  .tabs button { height: 36px; }
}
</style>
</head>
<body>
<header class="hdr" role="banner">
  <div class="hdr-logo">
    <img src="/brand/citrate-wordmark-white.svg" alt="Citrate" />
  </div>
  <div class="hdr-right">
    <div class="chainbadge" aria-label="Citrate chain ${opts.chainId}">
      <span class="dot" aria-hidden="true"></span>
      <span class="k">CHAIN</span>
      <span class="v">${opts.chainId}</span>
    </div>
  </div>
</header>

<main class="main">
  <div style="width: 100%; max-width: 28rem;">
    <section class="card" aria-label="Sign in or register">
      <div class="eyebrow" aria-hidden="true">SIGN IN OR REGISTER</div>
      <h1>Welcome to Citrate</h1>
      <p class="lede">Continue to <span class="app-chip" id="app-name">${escapeHtml(opts.clientId)}</span> &mdash; a secure, embedded wallet is created for you on the Citrate network.</p>

      <div class="tabs" role="tablist" aria-label="Sign-in methods" data-default-tab="passkey">
        <button id="tab-passkey" role="tab" aria-controls="panel-passkey" aria-selected="true" data-method="passkey">${ICON_KEY}<span>Passkey</span></button>
        <button id="tab-password" role="tab" aria-controls="panel-password" aria-selected="false" data-method="password">${ICON_MAIL}<span>Email</span></button>
        <button id="tab-google" role="tab" aria-controls="panel-google" aria-selected="false" data-method="google">${ICON_GOOGLE}<span>Google</span></button>
        <button id="tab-siwe" role="tab" aria-controls="panel-siwe" aria-selected="false" data-method="siwe">${ICON_WALLET}<span>Wallet</span></button>
      </div>

      <!-- Passkey panel — default active. -->
      <div id="panel-passkey" class="panel" role="tabpanel" aria-labelledby="tab-passkey" data-active="true">
        <p class="note">${ICON_SHIELD}<span>If you've added a passkey to your device for Citrate, your browser will offer it. No password, no phishing.</span></p>
        <div class="actions">
          <button id="signin-passkey" class="btn primary" type="button">Continue with passkey</button>
        </div>
        <button id="signup-passkey" class="altlink" type="button">First time? Register a new passkey.</button>
      </div>

      <!-- Email / password panel. -->
      <div id="panel-password" class="panel" role="tabpanel" aria-labelledby="tab-password" data-active="false">
        <form id="form-password" novalidate>
          <div class="field">
            <label for="pw-email">Email</label>
            <input id="pw-email" name="email" type="email" autocomplete="email" required />
          </div>
          <div class="field">
            <label for="pw-password">Password</label>
            <input id="pw-password" name="password" type="password" autocomplete="current-password" minlength="8" required />
            <p class="note" style="margin-top:6px">New here? Use at least 8 characters, then tap <strong>Register</strong> below.</p>
          </div>
          <div class="actions">
            <button id="signin-password" class="btn primary" type="submit">Sign in</button>
          </div>
          <button id="register-password" class="altlink" type="button">First time? Register a new account.</button>
        </form>
      </div>

      <!-- Google panel — gated on the env. -->
      <div id="panel-google" class="panel" role="tabpanel" aria-labelledby="tab-google" data-active="false">
        ${
          googleEnabled
            ? `<div class="actions">
                 <a id="signin-google" class="btn primary" href="/auth/google/start" rel="noopener">Continue with Google</a>
               </div>`
            : `<p class="note">${ICON_SHIELD}<span>Google sign-in is not enabled on this server. Use a passkey, email + password, or your wallet to continue.</span></p>`
        }
      </div>

      <!-- SIWE panel — the existing EIP-4361 flow, restyled. Preserves the
           injected/walletconnect button IDs the SIWE e2e test asserts on. -->
      <div id="panel-siwe" class="panel" role="tabpanel" aria-labelledby="tab-siwe" data-active="false">
        <div class="connected" id="connected" role="status">
          ${ICON_WALLET}<span>Connected as <span class="addr" id="connected-addr"></span></span>
        </div>
        <div class="actions">
          <button id="signin-injected" class="btn primary" type="button">Connect a browser wallet</button>
          ${hasWalletConnect ? '<button id="signin-walletconnect" class="btn" type="button">Use WalletConnect (mobile / QR)</button>' : ''}
        </div>
        <p class="note" style="margin-top: 12px;">${ICON_SHIELD}<span>You'll sign a Sign-In with Ethereum (EIP-4361) message bound to <span style="font-family: var(--font-mono);">${escapeHtml(opts.domain)}</span> on chain ${opts.chainId}. It proves you control your address &mdash; never a transaction.</span></p>
      </div>

      <p id="status" role="status" aria-live="polite"></p>
    </section>

    <p class="footer-eyebrow">${escapeHtml(opts.domain)}<span class="sep">·</span>CHAIN ${opts.chainId}<span class="sep">·</span>VERSION ${escapeHtml(opts.version)}</p>
  </div>
</main>

<script>
const CFG = ${cfg};
const statusEl = document.getElementById('status');

function setStatus(msg, isError) {
  statusEl.textContent = msg || '';
  statusEl.classList.toggle('error', Boolean(isError));
}
function describeError(err) {
  if (err && (err.code === 4001 || err.code === 'ACTION_REJECTED')) {
    return 'You declined the request. Try again when ready.';
  }
  return (err && err.message ? err.message : String(err));
}

// --- Tab switching. ---
const tabs = Array.from(document.querySelectorAll('[role="tab"]'));
const panels = Array.from(document.querySelectorAll('[role="tabpanel"]'));
function activate(method) {
  tabs.forEach((t) => t.setAttribute('aria-selected', t.dataset.method === method ? 'true' : 'false'));
  panels.forEach((p) => p.setAttribute('data-active', p.id === 'panel-' + method ? 'true' : 'false'));
  setStatus('');
}
tabs.forEach((t) => t.addEventListener('click', () => activate(t.dataset.method)));

// --- PASSKEY flow (/auth/webauthn/authenticate-{options,verify}). ---
const passkeyBtn = document.getElementById('signin-passkey');
passkeyBtn.addEventListener('click', async () => {
  passkeyBtn.disabled = true;
  try {
    if (!window.PublicKeyCredential) {
      setStatus('This browser does not support passkeys.', true);
      passkeyBtn.disabled = false; return;
    }
    setStatus('Asking your device to pick a passkey…');
    const optsRes = await fetch('/auth/webauthn/authenticate-options', {
      method: 'POST', credentials: 'same-origin',
      headers: { 'content-type': 'application/json' }, body: '{}',
    });
    if (!optsRes.ok) {
      const err = await optsRes.json().catch(() => ({}));
      setStatus('Could not start passkey sign-in: ' + (err.reason || optsRes.status), true);
      passkeyBtn.disabled = false; return;
    }
    const options = await optsRes.json();
    // SimpleWebAuthn's browser helper would do this for us; inlined to keep
    // the page dependency-free.
    const publicKey = {
      ...options,
      challenge: b64uToBuf(options.challenge),
      allowCredentials: (options.allowCredentials || []).map((c) => ({ ...c, id: b64uToBuf(c.id) })),
    };
    const assertion = await navigator.credentials.get({ publicKey });
    if (!assertion) {
      setStatus('No credential returned.', true);
      passkeyBtn.disabled = false; return;
    }
    const response = serializeAssertion(assertion);
    setStatus('Verifying…');
    const verifyRes = await fetch('/auth/webauthn/authenticate-verify', {
      method: 'POST', credentials: 'same-origin',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ response }),
    });
    const result = await verifyRes.json();
    if (!verifyRes.ok || !result.redirectTo) {
      setStatus('Passkey sign-in failed: ' + (result.reason || result.error || verifyRes.status), true);
      passkeyBtn.disabled = false; return;
    }
    setStatus('Signed in. Redirecting…');
    window.location = result.redirectTo;
  } catch (err) {
    setStatus('Error: ' + describeError(err), true);
    passkeyBtn.disabled = false;
  }
});

function b64uToBuf(s) {
  const pad = '='.repeat((4 - (s.length % 4)) % 4);
  const b64 = (s + pad).replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out.buffer;
}
function bufToB64u(buf) {
  const bytes = new Uint8Array(buf);
  let s = '';
  for (let i = 0; i < bytes.byteLength; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
}
function serializeAssertion(c) {
  return {
    id: c.id,
    rawId: bufToB64u(c.rawId),
    type: c.type,
    response: {
      clientDataJSON: bufToB64u(c.response.clientDataJSON),
      authenticatorData: bufToB64u(c.response.authenticatorData),
      signature: bufToB64u(c.response.signature),
      userHandle: c.response.userHandle ? bufToB64u(c.response.userHandle) : null,
    },
    clientExtensionResults: c.getClientExtensionResults ? c.getClientExtensionResults() : {},
  };
}
function serializeAttestation(c) {
  return {
    id: c.id,
    rawId: bufToB64u(c.rawId),
    type: c.type,
    response: {
      clientDataJSON: bufToB64u(c.response.clientDataJSON),
      attestationObject: bufToB64u(c.response.attestationObject),
      transports: typeof c.response.getTransports === 'function' ? c.response.getTransports() : [],
    },
    clientExtensionResults: c.getClientExtensionResults ? c.getClientExtensionResults() : {},
  };
}

// --- PASSKEY SIGNUP flow (/auth/webauthn/signup-{options,verify}). ---
const passkeySignupBtn = document.getElementById('signup-passkey');
passkeySignupBtn.addEventListener('click', async () => {
  passkeySignupBtn.disabled = true;
  try {
    if (!window.PublicKeyCredential) {
      setStatus('This browser does not support passkeys.', true);
      passkeySignupBtn.disabled = false; return;
    }
    setStatus('Asking your device to create a new passkey…');
    const optsRes = await fetch('/auth/webauthn/signup-options', {
      method: 'POST', credentials: 'same-origin',
      headers: { 'content-type': 'application/json' }, body: '{}',
    });
    if (!optsRes.ok) {
      const err = await optsRes.json().catch(() => ({}));
      setStatus('Could not start passkey signup: ' + (err.reason || optsRes.status), true);
      passkeySignupBtn.disabled = false; return;
    }
    const options = await optsRes.json();
    const publicKey = {
      ...options,
      challenge: b64uToBuf(options.challenge),
      user: { ...options.user, id: b64uToBuf(options.user.id) },
      excludeCredentials: (options.excludeCredentials || []).map((c) => ({ ...c, id: b64uToBuf(c.id) })),
    };
    const attestation = await navigator.credentials.create({ publicKey });
    if (!attestation) {
      setStatus('No credential returned.', true);
      passkeySignupBtn.disabled = false; return;
    }
    const response = serializeAttestation(attestation);
    setStatus('Verifying…');
    const verifyRes = await fetch('/auth/webauthn/signup-verify', {
      method: 'POST', credentials: 'same-origin',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ response }),
    });
    const result = await verifyRes.json();
    if (!verifyRes.ok || !result.redirectTo) {
      setStatus('Passkey signup failed: ' + (result.reason || result.error || verifyRes.status), true);
      passkeySignupBtn.disabled = false; return;
    }
    setStatus('Account created. Redirecting…');
    window.location = result.redirectTo;
  } catch (err) {
    setStatus('Error: ' + describeError(err), true);
    passkeySignupBtn.disabled = false;
  }
});

// --- EMAIL / PASSWORD flow (/auth/password/{login,register}). ---
const pwForm = document.getElementById('form-password');
const pwSubmit = document.getElementById('signin-password');
const pwRegister = document.getElementById('register-password');
async function pwPost(path, email, password) {
  const res = await fetch(path, {
    method: 'POST', credentials: 'same-origin',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });
  return { ok: res.ok, status: res.status, body: await res.json() };
}
pwForm.addEventListener('submit', async (ev) => {
  ev.preventDefault();
  pwSubmit.disabled = true;
  const email = document.getElementById('pw-email').value.trim();
  const password = document.getElementById('pw-password').value;
  if (!email || !password) { setStatus('Email and password are required.', true); pwSubmit.disabled = false; return; }
  setStatus('Signing in…');
  const r = await pwPost('/auth/password/login', email, password);
  if (!r.ok || !r.body.redirectTo) {
    setStatus('Sign-in failed: ' + (r.body.reason || r.body.error || r.status), true);
    pwSubmit.disabled = false; return;
  }
  setStatus('Signed in. Redirecting…');
  window.location = r.body.redirectTo;
});
pwRegister.addEventListener('click', async () => {
  pwRegister.disabled = true;
  const email = document.getElementById('pw-email').value.trim();
  const password = document.getElementById('pw-password').value;
  if (!email || !password) { setStatus('Email and password are required to register.', true); pwRegister.disabled = false; return; }
  if (password.length < 8) { setStatus('Password must be at least 8 characters.', true); pwRegister.disabled = false; return; }
  setStatus('Creating your account…');
  const r = await pwPost('/auth/password/register', email, password);
  if (!r.ok || !r.body.redirectTo) {
    setStatus('Registration failed: ' + (r.body.reason || r.body.error || r.status), true);
    pwRegister.disabled = false; return;
  }
  setStatus('Account created. Redirecting…');
  window.location = r.body.redirectTo;
});

// --- SIWE flow (preserves /siwe/challenge + /siwe/verify + personal_sign). ---
const injectedBtn = document.getElementById('signin-injected');
const wcBtn = document.getElementById('signin-walletconnect');
const connectedEl = document.getElementById('connected');
const connectedAddrEl = document.getElementById('connected-addr');
function showConnected(address) {
  connectedAddrEl.textContent = address;
  connectedEl.classList.add('show');
}
function setSiweBusy(busy) {
  injectedBtn.disabled = busy;
  if (wcBtn) wcBtn.disabled = busy;
}
// EIP-55 checksum the address. The server parses the SIWE message with
// \`new SiweMessage(...)\` (@spruceid/siwe-parser), which REJECTS a non-checksummed
// address as a "malformed message". Many wallets (and WalletConnect in particular)
// return a lowercase address, so we must checksum it before it goes into the
// signed message. Pure-JS keccak (no bundler / no viem in the page) via esm.sh.
let _keccak = null;
async function toChecksumAddress(addr) {
  const a = String(addr).toLowerCase().replace(/^0x/, '');
  if (!/^[0-9a-f]{40}$/.test(a)) return addr; // not an address — leave as-is
  if (!_keccak) {
    const mod = await import('https://esm.sh/@noble/hashes@1.3.3/sha3');
    _keccak = mod.keccak_256;
  }
  const hash = _keccak(new TextEncoder().encode(a)); // keccak256 of the ascii lowercase hex
  let hex = '';
  for (const b of hash) hex += b.toString(16).padStart(2, '0');
  let out = '0x';
  for (let i = 0; i < 40; i++) {
    out += parseInt(hex[i], 16) >= 8 ? a[i].toUpperCase() : a[i];
  }
  return out;
}
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
async function completeSiwe(provider, address) {
  // Checksum the address so the signed message parses server-side (EIP-55).
  address = await toChecksumAddress(address);
  setStatus('Fetching challenge…');
  const challengeRes = await fetch('/siwe/challenge', { credentials: 'same-origin' });
  const { nonce } = await challengeRes.json();
  const message = buildSiweMessage(address, nonce);
  setStatus('Check your wallet to sign the message…');
  const signature = await provider.request({ method: 'personal_sign', params: [message, address] });
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
injectedBtn.addEventListener('click', async () => {
  setSiweBusy(true);
  try {
    if (!window.ethereum) {
      setStatus('No browser wallet found. Install one (e.g. MetaMask) or use WalletConnect.', true);
      setSiweBusy(false); return;
    }
    setStatus('Requesting wallet…');
    const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
    const address = accounts[0];
    showConnected(address);
    const ok = await completeSiwe(window.ethereum, address);
    if (!ok) setSiweBusy(false);
  } catch (err) {
    setStatus('Error: ' + describeError(err), true);
    setSiweBusy(false);
  }
});
${
  hasWalletConnect
    ? `wcBtn.addEventListener('click', async () => {
  setSiweBusy(true);
  try {
    setStatus('Starting WalletConnect…');
    const { EthereumProvider } = await import('https://esm.sh/@walletconnect/ethereum-provider@2');
    const wc = await EthereumProvider.init({
      projectId: CFG.walletConnectProjectId,
      chains: [CFG.chainId],
      showQrModal: true,
      metadata: { name: 'Citrate', description: 'Sign in to Citrate', url: CFG.uri, icons: [] },
    });
    setStatus('Scan the QR code or approve in your wallet…');
    await wc.connect();
    const accounts = wc.accounts || (await wc.request({ method: 'eth_accounts' }));
    const address = accounts[0];
    if (!address) throw new Error('WalletConnect returned no account');
    if (typeof wc.chainId === 'number' && wc.chainId !== CFG.chainId) {
      setStatus('Wrong network: please switch your wallet to Citrate (chain ' + CFG.chainId + ').', true);
      try { await wc.disconnect(); } catch (e) {}
      setSiweBusy(false); return;
    }
    showConnected(address);
    const ok = await completeSiwe(wc, address);
    if (!ok) { try { await wc.disconnect(); } catch (e) {} setSiweBusy(false); }
  } catch (err) {
    setStatus('Error: ' + describeError(err), true);
    setSiweBusy(false);
  }
});`
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
            googleEnabled: options.googleEnabled ?? false,
            version: options.version ?? 'dev',
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
