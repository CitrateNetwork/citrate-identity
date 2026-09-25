/**
 * Test helper: drive a REAL SIWE admin login through createProvider() (the same
 * path a browser takes: /auth → interaction → /siwe/verify → resume), collecting
 * the cookies into a jar. Used by the PBA-L3a-001 / -006 regression tests so they
 * exercise the admin routes behind their real middleware, not a harness.
 */
import { createHash, randomBytes } from 'node:crypto';
import { SiweMessage } from 'siwe';
import type { PrivateKeyAccount } from 'viem/accounts';
import { CITRATE_CHAIN_ID } from '../../src/siwe.js';

export class Jar {
  m = new Map<string, string>();
  raw: string[] = [];
  absorb(r: Response): void {
    for (const sc of r.headers.getSetCookie()) {
      this.raw.push(sc);
      const [p] = sc.split(';');
      const i = p.indexOf('=');
      const k = p.slice(0, i).trim();
      const v = p.slice(i + 1).trim();
      if (!v) this.m.delete(k);
      else this.m.set(k, v);
    }
  }
  header(): string {
    return [...this.m].map(([k, v]) => `${k}=${v}`).join('; ');
  }
}

const b64u = (b: Buffer): string => b.toString('base64url');

/** Log `account` in as an OIDC session on the authority at `baseUrl`. */
export async function siweLogin(baseUrl: string, account: PrivateKeyAccount, jar: Jar): Promise<void> {
  const host = new URL(baseUrl).host;
  const verifier = b64u(randomBytes(32));
  const challenge = b64u(createHash('sha256').update(verifier).digest());
  const a = await fetch(
    `${baseUrl}/auth?response_type=code&client_id=citrate-explorer&redirect_uri=${encodeURIComponent('http://localhost:3001/auth/callback')}&scope=openid&code_challenge=${challenge}&code_challenge_method=S256&state=s`,
    { redirect: 'manual' },
  );
  jar.absorb(a);
  const loc = a.headers.get('location')!;
  jar.absorb(await fetch(loc.startsWith('http') ? loc : baseUrl + loc, { headers: { cookie: jar.header() } }));
  const { nonce } = (await (await fetch(`${baseUrl}/siwe/challenge`)).json()) as { nonce: string };
  const now = new Date();
  const message = new SiweMessage({
    domain: host,
    address: account.address,
    statement: 'Sign in to Citrate',
    uri: baseUrl,
    version: '1',
    chainId: CITRATE_CHAIN_ID,
    nonce,
    issuedAt: now.toISOString(),
    expirationTime: new Date(now.getTime() + 6e5).toISOString(),
  }).prepareMessage();
  const signature = await account.signMessage({ message });
  const v = await fetch(`${baseUrl}/siwe/verify`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie: jar.header() },
    body: JSON.stringify({ message, signature }),
  });
  jar.absorb(v);
  let next = ((await v.json()) as { redirectTo: string }).redirectTo;
  for (let i = 0; i < 10 && next && !next.startsWith('http://localhost:3001/'); i++) {
    const h = await fetch(next.startsWith('http') ? next : baseUrl + next, {
      headers: { cookie: jar.header() },
      redirect: 'manual',
    });
    jar.absorb(h);
    next = h.headers.get('location') ?? '';
  }
}

/**
 * Open the admin console the way a browser does (same-origin top-level GET) and
 * return the CSRF token the page embeds. Also absorbs the strict admin cookie.
 */
export async function openConsole(baseUrl: string, jar: Jar): Promise<string> {
  const r = await fetch(`${baseUrl}/admin/kyc`, {
    headers: { cookie: jar.header(), accept: 'text/html', 'sec-fetch-site': 'none' },
    redirect: 'manual',
  });
  jar.absorb(r);
  const html = await r.text();
  const m = /<meta name="csrf-token" content="([^"]+)"/.exec(html);
  return m ? m[1] : '';
}

/** Headers a same-origin console fetch sends. */
export function sameOriginJson(baseUrl: string, jar: Jar, csrf: string): Record<string, string> {
  return {
    'content-type': 'application/json',
    origin: new URL(baseUrl).origin,
    'sec-fetch-site': 'same-origin',
    'x-csrf-token': csrf,
    cookie: jar.header(),
  };
}
