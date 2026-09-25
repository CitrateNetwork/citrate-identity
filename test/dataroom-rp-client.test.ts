/**
 * XR-2 (A) — RP client for the investor data room (dataroom.citrate.ai).
 *
 * Hosted web RP, PUBLIC client (no secret), Authorization Code + PKCE, rotating
 * refresh via offline_access — same posture as the explorer / atlas web RPs. Its
 * one distinguishing trait is the custom callback path `/access/callback` (the
 * data room drives the access flow itself), NOT `/auth/callback` or the atlas
 * `/api/auth/callback`. First-party + Citrate-owned, so consent is auto-granted.
 */

import { describe, expect, it } from 'vitest';

import {
  ALLOWED_CORS_ORIGINS,
  buildConfiguration,
  DATAROOM_ORIGIN,
  isTrustedFirstPartyClient,
} from '../src/config.js';

type ClientShape = {
  client_id: string;
  application_type?: string;
  grant_types?: string[];
  response_types?: string[];
  redirect_uris?: string[];
  post_logout_redirect_uris?: string[];
  token_endpoint_auth_method?: string;
  scope?: string;
};

async function dataroomClient(): Promise<ClientShape | undefined> {
  const cfg = await buildConfiguration();
  return ((cfg.clients ?? []) as ClientShape[]).find(
    (x) => x.client_id === 'citrate-dataroom',
  );
}

describe('citrate-dataroom RP client (XR-2 A)', () => {
  it('registers citrate-dataroom as a public web PKCE client', async () => {
    const c = await dataroomClient();
    expect(c).toBeDefined();
    expect(c?.application_type).toBe('web');
    expect(c?.token_endpoint_auth_method).toBe('none'); // PKCE, no secret
    expect(c?.grant_types).toEqual(['authorization_code', 'refresh_token']);
    expect(c?.response_types).toEqual(['code']);
    expect(c?.scope).toBe('openid profile wallet kyc offline_access');
  });

  it('uses the custom /access/callback path on prod + preview hosts', async () => {
    const c = await dataroomClient();
    expect(c?.redirect_uris).toContain(
      'https://dataroom.citrate.ai/access/callback',
    );
    expect(c?.redirect_uris).toContain(
      'https://citrate-dataroom.vercel.app/access/callback',
    );
    expect(c?.redirect_uris).toContain(`${DATAROOM_ORIGIN}/access/callback`);
    // It must NOT register the generic web-RP callback paths.
    expect(
      c?.redirect_uris?.some(
        (u) => u.endsWith('/auth/callback') || u.endsWith('/api/auth/callback'),
      ),
    ).toBe(false);
  });

  it('allows logout back to the prod domain and the vercel alias', async () => {
    const c = await dataroomClient();
    expect(c?.post_logout_redirect_uris).toContain('https://dataroom.citrate.ai');
    expect(c?.post_logout_redirect_uris).toContain(
      'https://citrate-dataroom.vercel.app',
    );
  });

  it('is a trusted first-party client (consent auto-granted)', () => {
    expect(isTrustedFirstPartyClient('citrate-dataroom')).toBe(true);
  });

  it('is on the CORS allow-list via DATAROOM_ORIGIN', () => {
    expect(ALLOWED_CORS_ORIGINS.has(DATAROOM_ORIGIN!)).toBe(true);
  });
});
