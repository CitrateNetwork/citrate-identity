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
});
