import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { createHash, randomBytes } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createProvider } from '../src/server.js';

/**
 * The branded SIWE interaction page (GET /interaction/:uid, login prompt).
 *
 * We drive a real /auth request to obtain a live login interaction, follow the
 * 303 to the interaction URL, and GET that page with the interaction cookie so
 * the authority renders the actual login surface. We then assert on the HTML:
 *
 *   - it carries the Citrate brand (green #8ecc09);
 *   - it shows the app being signed into (the client_id);
 *   - it has the SIWE script hooks (challenge/verify, personal_sign, EIP-4361);
 *   - WITH a WalletConnect project id → BOTH connector buttons render;
 *   - WITHOUT one → ONLY the injected connector renders (not fail-closed).
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
}): Promise<Harness> {
  const probe = createServer();
  await new Promise<void>((res) => probe.listen(0, '127.0.0.1', res));
  const { port } = probe.address() as AddressInfo;
  probe.close();
  const baseUrl = `http://127.0.0.1:${port}`;
  const provider = await createProvider(baseUrl, {
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

describe('branded SIWE interaction page', () => {
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
