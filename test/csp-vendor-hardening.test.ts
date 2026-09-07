import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { createHash, randomBytes } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createProvider } from '../src/server.js';

/**
 * ID-B-004 (MEDIUM) tripwire — no third-party CDN script executes on the auth
 * origin, and a strict CSP denies external `script-src`.
 *
 * Before the fix the branded /interaction sign-in page (and the consent page)
 * `import()`ed JavaScript from https://esm.sh at RUNTIME (the @noble/hashes
 * keccak on the injected-wallet path, and @walletconnect/ethereum-provider on
 * the WalletConnect path), with NO Content-Security-Policy on any HTML surface.
 * A compromise of / MITM against esm.sh would execute attacker script in the
 * credential-entry origin.
 *
 * The fix self-hosts both modules under same-origin /vendor/*.mjs and emits a
 * strict CSP (`script-src 'self' 'nonce-…'`, `frame-ancestors 'none'`). This
 * test asserts:
 *   - The rendered interaction HTML references NO off-origin script host
 *     (no esm.sh, no absolute http(s) import), with WalletConnect on AND off.
 *   - A Content-Security-Policy header is present and denies external
 *     script-src (self + nonce only; esm.sh absent), on the interaction,
 *     consent (implicitly, same code path) and account surfaces.
 *   - The self-hosted /vendor/ modules are served same-origin and the keccak
 *     bundle exports keccak_256 with correct EIP-55 behaviour.
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
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

interface Harness {
  server: Server;
  baseUrl: string;
}

async function listenProvider(options: {
  walletConnectProjectId?: string;
}): Promise<Harness> {
  const probe = createServer();
  await new Promise<void>((res) => probe.listen(0, '127.0.0.1', res));
  const { port } = probe.address() as AddressInfo;
  probe.close();
  const baseUrl = `http://127.0.0.1:${port}`;
  const provider = await createProvider(baseUrl, {
    googleEnabled: false,
    ...(options.walletConnectProjectId
      ? { walletConnectProjectId: options.walletConnectProjectId }
      : {}),
  });
  const server = createServer(provider.callback());
  await new Promise<void>((res) => server.listen(port, '127.0.0.1', res));
  return { server, baseUrl };
}

/** Drive /auth → 303 → GET the interaction page; return its Response. */
async function fetchLoginPage(baseUrl: string): Promise<Response> {
  const jar = new CookieJar();
  const codeVerifier = base64url(randomBytes(32));
  const codeChallenge = base64url(createHash('sha256').update(codeVerifier).digest());
  const state = base64url(randomBytes(16));
  const authUrl =
    `${baseUrl}/auth?response_type=code&client_id=citrate-explorer` +
    `&redirect_uri=${encodeURIComponent('http://localhost:3001/auth/callback')}` +
    `&scope=${encodeURIComponent('openid profile wallet')}` +
    `&code_challenge=${codeChallenge}&code_challenge_method=S256&state=${state}`;
  const authRes = await fetch(authUrl, { redirect: 'manual' });
  jar.absorb(authRes);
  const interactionLoc = authRes.headers.get('location')!;
  return fetch(`${baseUrl}${new URL(interactionLoc, baseUrl).pathname}`, {
    headers: { cookie: jar.header() },
    redirect: 'manual',
  });
}

/** Any off-origin script reference: esm.sh, or an absolute-URL dynamic import. */
function assertNoOffOriginScript(html: string): void {
  expect(html).not.toContain('esm.sh');
  // No dynamic import() of an absolute (off-origin) URL — vendored imports are
  // same-origin ("/vendor/…").
  expect(html).not.toMatch(/import\(\s*['"]https?:\/\//);
  // No <script src="http…"> off-origin tag either.
  expect(html).not.toMatch(/<script[^>]+src=['"]https?:\/\//i);
}

describe('ID-B-004: no off-origin script on the auth origin + strict CSP', () => {
  describe('WalletConnect ENABLED', () => {
    let h: Harness;
    let res: Response;
    let html: string;
    beforeAll(async () => {
      h = await listenProvider({ walletConnectProjectId: 'test-wc-project-id' });
      res = await fetchLoginPage(h.baseUrl);
      html = await res.text();
    });
    afterAll(async () => {
      await new Promise<void>((r, j) => h.server.close((e) => (e ? j(e) : r())));
    });

    it('the interaction HTML references no off-origin script host', () => {
      expect(res.status).toBe(200);
      assertNoOffOriginScript(html);
      // The WalletConnect connector IS rendered, but from a same-origin vendor URL.
      expect(html).toContain('/vendor/walletconnect-ethereum-provider.mjs');
      expect(html).toContain('/vendor/noble-sha3.mjs');
    });

    it('emits a Content-Security-Policy that denies external script-src', () => {
      const csp = res.headers.get('content-security-policy');
      expect(csp).toBeTruthy();
      // script-src is self + a per-response nonce ONLY — no esm.sh, no
      // 'unsafe-inline' for scripts, so injected/third-party script is denied.
      expect(csp).toMatch(/script-src 'self' 'nonce-[^']+'/);
      expect(csp).not.toContain('esm.sh');
      expect(csp).not.toMatch(/script-src[^;]*'unsafe-inline'/);
      expect(csp).toContain("frame-ancestors 'none'");
      expect(csp).toContain("object-src 'none'");
    });

    it('the inline script carries the CSP nonce from the header', () => {
      const csp = res.headers.get('content-security-policy')!;
      const nonce = /script-src 'self' 'nonce-([^']+)'/.exec(csp)![1];
      expect(html).toContain(`<script nonce="${nonce}">`);
    });

    it('allows the WalletConnect relay only via connect-src (network, not script)', () => {
      const csp = res.headers.get('content-security-policy')!;
      expect(csp).toMatch(/connect-src[^;]*walletconnect\.org/);
      // …and never as a script source.
      expect(csp).not.toMatch(/script-src[^;]*walletconnect/);
    });
  });

  describe('WalletConnect DISABLED (default)', () => {
    let h: Harness;
    let res: Response;
    let html: string;
    beforeAll(async () => {
      h = await listenProvider({});
      res = await fetchLoginPage(h.baseUrl);
      html = await res.text();
    });
    afterAll(async () => {
      await new Promise<void>((r, j) => h.server.close((e) => (e ? j(e) : r())));
    });

    it('references no off-origin script host and no WalletConnect vendor import', () => {
      assertNoOffOriginScript(html);
      expect(html).not.toContain('/vendor/walletconnect-ethereum-provider.mjs');
      // The keccak (checksum) module is still same-origin self-hosted.
      expect(html).toContain('/vendor/noble-sha3.mjs');
    });

    it('CSP is present and connect-src is self-only when WalletConnect is off', () => {
      const csp = res.headers.get('content-security-policy');
      expect(csp).toBeTruthy();
      expect(csp).toMatch(/script-src 'self' 'nonce-[^']+'/);
      expect(csp).toContain("connect-src 'self'");
      expect(csp).not.toContain('walletconnect');
    });
  });

  describe('self-hosted /vendor/ modules are served same-origin', () => {
    let h: Harness;
    beforeAll(async () => {
      h = await listenProvider({});
    });
    afterAll(async () => {
      await new Promise<void>((r, j) => h.server.close((e) => (e ? j(e) : r())));
    });

    it('GET /vendor/noble-sha3.mjs → 200 JS, exports a working EIP-55 keccak', async () => {
      const r = await fetch(`${h.baseUrl}/vendor/noble-sha3.mjs`);
      expect(r.status).toBe(200);
      expect(r.headers.get('content-type')).toMatch(/javascript/);
      const src = await r.text();
      // Vendored bundle is itself self-contained (no CDN / node: imports).
      expect(src).not.toContain('esm.sh');
      expect(src).not.toMatch(/from\s*['"]node:/);
      // Load it and check an official EIP-55 checksum vector.
      const mod: { keccak_256: (b: Uint8Array) => Uint8Array } = await import(
        `data:text/javascript,${encodeURIComponent(src)}`
      );
      const a = '5aaeb6053f3e94c9b9a09f33669435e7ef1beaed';
      const hash = mod.keccak_256(new TextEncoder().encode(a));
      let hex = '';
      for (const b of hash) hex += b.toString(16).padStart(2, '0');
      let out = '0x';
      for (let i = 0; i < 40; i++) out += parseInt(hex[i], 16) >= 8 ? a[i].toUpperCase() : a[i];
      expect(out).toBe('0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed');
    });

    it('GET /vendor/walletconnect-ethereum-provider.mjs → 200 JS, self-contained', async () => {
      const r = await fetch(`${h.baseUrl}/vendor/walletconnect-ethereum-provider.mjs`);
      expect(r.status).toBe(200);
      expect(r.headers.get('content-type')).toMatch(/javascript/);
      const src = await r.text();
      // No off-origin module IMPORTS (string-literal endpoint URLs are fine —
      // those are runtime connect-src targets, not script sources).
      expect(src).not.toMatch(/(^|[^.\w])import\s*[({]?\s*['"]https?:\/\//m);
      expect(src).not.toMatch(/from\s*['"](https?:\/\/|node:)/);
    });
  });
});

describe('ID-B-004: the Account Hub ships a strict CSP', () => {
  it('GET /account emits script-src self and frame-ancestors none', async () => {
    const probe = createServer();
    await new Promise<void>((res) => probe.listen(0, '127.0.0.1', res));
    const { port } = probe.address() as AddressInfo;
    probe.close();
    const baseUrl = `http://127.0.0.1:${port}`;
    const provider = await createProvider(baseUrl, { googleEnabled: false });
    const server = createServer(provider.callback());
    await new Promise<void>((res) => server.listen(port, '127.0.0.1', res));
    try {
      // Unauthenticated → signed-out hub; the CSP header is set on the render path.
      const r = await fetch(`${baseUrl}/account`, { redirect: 'manual' });
      const csp = r.headers.get('content-security-policy');
      expect(csp).toBeTruthy();
      expect(csp).toContain("script-src 'self'");
      expect(csp).not.toMatch(/script-src[^;]*'unsafe-inline'/);
      expect(csp).toContain("frame-ancestors 'none'");
    } finally {
      await new Promise<void>((r, j) => server.close((e) => (e ? j(e) : r())));
    }
  });
});
