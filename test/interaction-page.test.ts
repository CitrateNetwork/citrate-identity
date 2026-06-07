import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { createHash, randomBytes } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createProvider } from '../src/server.js';

/**
 * The branded /interaction/:uid login surface (WP-6 slice B of EW-S1).
 *
 * We drive a real /auth request to obtain a live login interaction, follow the
 * 303 to the interaction URL, and GET that page with the interaction cookie so
 * the authority renders the actual login surface. We then assert on the HTML:
 *
 *   - The four-method shell: Citrate brand (green #8ecc09), the new welcome
 *     headline, the four method tabs, the eyebrow label, the canonical
 *     warm-paper canvas, the self-hosted brand wordmark.
 *   - The tab-state default is "passkey" (the first tab is aria-selected on
 *     render so users without JS see the right panel).
 *   - SIWE-flow preservation: same `signin-injected` / `signin-walletconnect`
 *     button IDs and same /siwe/challenge + /siwe/verify + personal_sign +
 *     `Chain ID: ` script hooks the SIWE e2e relies on.
 *   - WalletConnect: WITH a project id → BOTH connector buttons render;
 *     WITHOUT one → ONLY the injected connector renders (not fail-closed).
 *   - Google federation: WITHOUT `googleEnabled` → the tab still appears but
 *     shows the "Google sign-in is not enabled on this server" copy.
 */

class CookieJar {
  private readonly jar = new Map<string, string>();
  absorb(res: Response): void {
    const setCookies =
      typeof (res.headers as Headers & { getSetCookie?: () => string[] })
        .getSetCookie === 'function'
        ? (res.headers as Headers & { getSetCookie: () => string[] }).getSetCookie()
        : [];
    for (const sc of setCookies) {
      const [pair] = sc.split(';');
      const eq = pair.indexOf('=');
      if (eq === -1) continue;
      const name = pair.slice(0, eq).trim();
      const value = pair.slice(eq + 1).trim();
      if (value === '' || value === 'undefined') this.jar.delete(name);
      else this.jar.set(name, value);
    }
  }
  header(): string {
    return Array.from(this.jar.entries())
      .map(([k, v]) => `${k}=${v}`)
      .join('; ');
  }
}

function base64url(buf: Buffer): string {
  return buf
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

interface Harness {
  server: Server;
  baseUrl: string;
}

async function listenProvider(options: {
  walletConnectProjectId?: string;
  googleEnabled?: boolean;
}): Promise<Harness> {
  const probe = createServer();
  await new Promise<void>((res) => probe.listen(0, '127.0.0.1', res));
  const { port } = probe.address() as AddressInfo;
  probe.close();
  const baseUrl = `http://127.0.0.1:${port}`;
  // googleEnabled defaults to false in the harness so an env-set
  // CITRATE_AA_GOOGLE_CLIENT_ID can't flip the rendered copy mid-test.
  const provider = await createProvider(baseUrl, {
    googleEnabled: options.googleEnabled ?? false,
    ...(options.walletConnectProjectId
      ? { walletConnectProjectId: options.walletConnectProjectId }
      : {}),
  });
  const server = createServer(provider.callback());
  await new Promise<void>((res) => server.listen(port, '127.0.0.1', res));
  return { server, baseUrl };
}

/** Drive /auth → 303 → GET the login interaction page; return its HTML. */
async function renderLoginPage(
  baseUrl: string,
  clientId = 'citrate-explorer',
  redirectUri = 'http://localhost:3001/auth/callback',
): Promise<string> {
  const jar = new CookieJar();
  const codeVerifier = base64url(randomBytes(32));
  const codeChallenge = base64url(
    createHash('sha256').update(codeVerifier).digest(),
  );
  const state = base64url(randomBytes(16));
  const authUrl =
    `${baseUrl}/auth?response_type=code&client_id=${encodeURIComponent(clientId)}` +
    `&redirect_uri=${encodeURIComponent(redirectUri)}` +
    `&scope=${encodeURIComponent('openid profile wallet')}` +
    `&code_challenge=${codeChallenge}&code_challenge_method=S256&state=${state}`;
  const authRes = await fetch(authUrl, { redirect: 'manual' });
  jar.absorb(authRes);
  const interactionLoc = authRes.headers.get('location')!;
  const pageRes = await fetch(
    `${baseUrl}${new URL(interactionLoc, baseUrl).pathname}`,
    { headers: { cookie: jar.header() }, redirect: 'manual' },
  );
  expect(pageRes.status).toBe(200);
  return pageRes.text();
}

describe('branded /interaction/:uid login surface', () => {
  describe('headline + brand shell', () => {
    let h: Harness;
    let html: string;
    let status: number;
    beforeAll(async () => {
      h = await listenProvider({});
      // Drive /auth + 303 manually so we can capture the status, separately
      // from renderLoginPage which only returns the body.
      const jar = new CookieJar();
      const codeVerifier = base64url(randomBytes(32));
      const codeChallenge = base64url(
        createHash('sha256').update(codeVerifier).digest(),
      );
      const state = base64url(randomBytes(16));
      const authUrl =
        `${h.baseUrl}/auth?response_type=code&client_id=citrate-explorer` +
        `&redirect_uri=${encodeURIComponent('http://localhost:3001/auth/callback')}` +
        `&scope=${encodeURIComponent('openid profile wallet')}` +
        `&code_challenge=${codeChallenge}&code_challenge_method=S256&state=${state}`;
      const authRes = await fetch(authUrl, { redirect: 'manual' });
      jar.absorb(authRes);
      const interactionLoc = authRes.headers.get('location')!;
      const pageRes = await fetch(
        `${h.baseUrl}${new URL(interactionLoc, h.baseUrl).pathname}`,
        { headers: { cookie: jar.header() }, redirect: 'manual' },
      );
      status = pageRes.status;
      html = await pageRes.text();
    });
    afterAll(async () => {
      await new Promise<void>((res, rej) =>
        h.server.close((err) => (err ? rej(err) : res())),
      );
    });

    it('renders the page (HTTP 200) with the H1 "Welcome to Citrate"', () => {
      expect(status).toBe(200);
      expect(html).toContain('<h1>Welcome to Citrate</h1>');
    });

    it("defaults the active tab to passkey (aria-selected='true' on tab-passkey)", () => {
      // tab-passkey is the LEFTmost tab and has aria-selected="true" on
      // render so a user without JS still sees the right panel.
      expect(html).toMatch(
        /id="tab-passkey"[^>]*aria-selected="true"/,
      );
      // The other three tabs render aria-selected="false".
      expect(html).toMatch(/id="tab-password"[^>]*aria-selected="false"/);
      expect(html).toMatch(/id="tab-google"[^>]*aria-selected="false"/);
      expect(html).toMatch(/id="tab-siwe"[^>]*aria-selected="false"/);
      // And the passkey panel is the only one with data-active="true".
      expect(html).toMatch(/id="panel-passkey"[^>]*data-active="true"/);
      expect(html).toMatch(/id="panel-password"[^>]*data-active="false"/);
    });

    it('renders the "Google sign-in is not enabled" message when CITRATE_AA_GOOGLE_CLIENT_ID is unset', () => {
      // The Google tab is rendered unconditionally (so users can see why it
      // is unavailable), but with the env-disabled copy.
      expect(html).toContain('id="tab-google"');
      expect(html).toContain('Google sign-in is not enabled on this server');
      // The active "Continue with Google" button is NOT rendered when the
      // env is unset — the tab body shows only the disabled-copy note.
      expect(html).not.toMatch(/id="signin-google"[^>]*href="\/auth\/google\/start"/);
    });

    it('uses the canonical design tokens lifted from the explorer scan.css', () => {
      // Warm-paper canvas + Citrate accent green (verbatim from scan.css).
      expect(html).toContain('#f1eee6');
      expect(html).toContain('#8ecc09');
      // The dark evergreen header colour the explorer ships.
      expect(html).toContain('#0f2a1a');
    });

    it('self-hosts the brand fonts from /fonts/* (NO fonts.googleapis.com)', () => {
      expect(html).toContain("url('/fonts/Geist-Regular.woff2')");
      expect(html).toContain("url('/fonts/GeistMono-Regular.woff2')");
      expect(html).toContain("url('/fonts/SpaceGrotesk.ttf')");
      expect(html).toContain("url('/fonts/Cormorant.ttf')");
      expect(html).not.toContain('fonts.googleapis.com');
      expect(html).not.toContain('fonts.gstatic.com');
    });

    it('uses the canonical brand wordmark, not a CSS placeholder', () => {
      expect(html).toContain('/brand/citrate-wordmark-white.svg');
      // No `.dot` placeholder square (the prior page used one as a stand-in).
      expect(html).not.toMatch(/class="brand"[^>]*>[\s\S]*<span class="dot"/);
    });
  });

  describe('with WALLETCONNECT_PROJECT_ID set', () => {
    let h: Harness;
    let html: string;
    beforeAll(async () => {
      h = await listenProvider({ walletConnectProjectId: 'test-wc-project-id' });
      html = await renderLoginPage(h.baseUrl);
    });
    afterAll(async () => {
      await new Promise<void>((res, rej) =>
        h.server.close((err) => (err ? rej(err) : res())),
      );
    });

    it('carries the Citrate brand green #8ecc09', () => {
      expect(html).toContain('#8ecc09');
      expect(html).toContain('Citrate');
    });

    it('shows the app being signed into (the client_id)', () => {
      expect(html).toContain('citrate-explorer');
    });

    it('renders BOTH connector buttons (injected + WalletConnect)', () => {
      expect(html).toContain('id="signin-injected"');
      expect(html).toContain('id="signin-walletconnect"');
      // The CDN ESM WalletConnect provider import is present.
      expect(html).toContain('@walletconnect/ethereum-provider');
      // The configured project id is wired into the page config.
      expect(html).toContain('test-wc-project-id');
    });

    it('contains the SIWE script hooks (challenge/verify, personal_sign, EIP-4361)', () => {
      expect(html).toContain('/siwe/challenge');
      expect(html).toContain('/siwe/verify');
      expect(html).toContain('personal_sign');
      expect(html).toContain('Chain ID: ');
    });
  });

  describe('without WALLETCONNECT_PROJECT_ID', () => {
    let h: Harness;
    let html: string;
    beforeAll(async () => {
      h = await listenProvider({});
      html = await renderLoginPage(h.baseUrl);
    });
    afterAll(async () => {
      await new Promise<void>((res, rej) =>
        h.server.close((err) => (err ? rej(err) : res())),
      );
    });

    it('still renders the injected connector (login is not fail-closed)', () => {
      expect(html).toContain('id="signin-injected"');
      expect(html).toContain('#8ecc09');
    });

    it('hides the WalletConnect connector entirely', () => {
      expect(html).not.toContain('id="signin-walletconnect"');
      expect(html).not.toContain('@walletconnect/ethereum-provider');
    });
  });
});
