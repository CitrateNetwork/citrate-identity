/**
 * EW-S1 WP-8/9 — RP clients for the two wallet surfaces.
 *
 * gui-native registers unconditionally (native loopback, RFC 8252,
 * same posture as citrate-studio). The wallet-extension client only
 * registers when WALLET_EXTENSION_REDIRECT_URI pins the
 * install-specific chromiumapp.org redirect.
 */

import { afterEach, describe, expect, it } from 'vitest';

import { buildConfiguration } from '../src/config.js';

type ClientShape = {
  client_id: string;
  application_type?: string;
  redirect_uris?: string[];
  token_endpoint_auth_method?: string;
};

async function clients(): Promise<ClientShape[]> {
  const cfg = await buildConfiguration();
  return (cfg.clients ?? []) as ClientShape[];
}

describe('wallet-surface RP clients', () => {
  const ENV_KEY = 'WALLET_EXTENSION_REDIRECT_URI';
  afterEach(() => {
    delete process.env[ENV_KEY];
  });

  it('registers citrate-gui-native as a native loopback PKCE client', async () => {
    const c = (await clients()).find((x) => x.client_id === 'citrate-gui-native');
    expect(c).toBeDefined();
    expect(c?.application_type).toBe('native');
    expect(c?.token_endpoint_auth_method).toBe('none');
    expect(c?.redirect_uris?.some((u) => u.startsWith('http://127.0.0.1'))).toBe(true);
  });

  it('omits citrate-wallet-extension when the redirect env is unset', async () => {
    const c = (await clients()).find(
      (x) => x.client_id === 'citrate-wallet-extension',
    );
    expect(c).toBeUndefined();
  });

  it('registers citrate-buyer-webapp as a public web PKCE client with an /auth/callback redirect (AUTHSPINE S3-WP1)', async () => {
    const c = (await clients()).find((x) => x.client_id === 'citrate-buyer-webapp');
    expect(c).toBeDefined();
    expect(c?.application_type).toBe('web');
    expect(c?.token_endpoint_auth_method).toBe('none'); // public client; PKCE carries PoP
    expect(c?.redirect_uris?.some((u) => u.endsWith('/auth/callback'))).toBe(true);
    expect(
      c?.redirect_uris?.includes('https://citrate-buyer-webapp.vercel.app/auth/callback'),
    ).toBe(true);
  });
});
