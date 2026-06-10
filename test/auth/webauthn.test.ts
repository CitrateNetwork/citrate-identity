import { describe, it, expect } from 'vitest';
import {
  buildRegistrationOptions,
  buildAuthenticationOptions,
  rpIdFromIssuer,
} from '../../src/auth/webauthn.js';

const RP = {
  rpId: 'auth.citrate.ai',
  rpName: 'Citrate',
  expectedOrigin: 'https://auth.citrate.ai',
} as const;

describe('rpIdFromIssuer', () => {
  it('returns just the hostname', () => {
    expect(rpIdFromIssuer('https://auth.citrate.ai/')).toBe('auth.citrate.ai');
    expect(rpIdFromIssuer('https://auth.citrate.ai:443/foo')).toBe('auth.citrate.ai');
    expect(rpIdFromIssuer('http://localhost:3000/')).toBe('localhost');
  });
});

describe('buildRegistrationOptions', () => {
  it('produces options with a 32-byte challenge', async () => {
    const opts = await buildRegistrationOptions({
      rp: RP,
      userId: 'user-uuid-123',
      userName: 'alice@example.com',
    });
    expect(opts.rp.id).toBe('auth.citrate.ai');
    expect(opts.rp.name).toBe('Citrate');
    expect(opts.user.name).toBe('alice@example.com');
    expect(opts.challenge.length).toBeGreaterThan(0);
    expect(opts.authenticatorSelection?.userVerification).toBe('required');
    expect(opts.authenticatorSelection?.residentKey).toBe('required');
  });

  it('includes excluded credentials when provided', async () => {
    const excluded = Buffer.from('cred-id-1', 'utf8');
    const opts = await buildRegistrationOptions({
      rp: RP,
      userId: 'u',
      userName: 'a',
      excludeCredentialIds: [excluded],
    });
    expect(opts.excludeCredentials?.length).toBe(1);
    expect(opts.excludeCredentials?.[0]?.id).toBe(excluded.toString('base64url'));
  });

  it('supports ES256 (-7) for the on-chain P-256 verifier', async () => {
    const opts = await buildRegistrationOptions({
      rp: RP,
      userId: 'u',
      userName: 'a',
    });
    expect(opts.pubKeyCredParams.some((p) => p.alg === -7)).toBe(true);
  });
});

describe('buildAuthenticationOptions', () => {
  it('produces options with a fresh challenge', async () => {
    const opts = await buildAuthenticationOptions({ rp: RP });
    expect(opts.rpId).toBe('auth.citrate.ai');
    expect(opts.userVerification).toBe('required');
    expect(opts.challenge.length).toBeGreaterThan(0);
  });

  it('emits two distinct challenges across calls (no fixed value)', async () => {
    const a = await buildAuthenticationOptions({ rp: RP });
    const b = await buildAuthenticationOptions({ rp: RP });
    expect(a.challenge).not.toBe(b.challenge);
  });

  it('forwards allow-credentials when provided', async () => {
    const id = Buffer.from('cred-id', 'utf8');
    const opts = await buildAuthenticationOptions({ rp: RP, allowCredentialIds: [id] });
    expect(opts.allowCredentials?.length).toBe(1);
    expect(opts.allowCredentials?.[0]?.id).toBe(id.toString('base64url'));
  });
});
