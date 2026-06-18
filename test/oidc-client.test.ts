/**
 * @citrate/oidc-client contract tests (AUTHSPINE S2-WP1).
 */
import { describe, it, expect } from 'vitest';
import {
  parseClaims,
  isKycVerified,
  effectiveTier,
  requireTier,
  requireRole,
  accountHubUrl,
  kycStartUrl,
  ENTITLEMENT_CLAIM,
} from '../packages/oidc-client/src/index.js';

const ent = (o: Record<string, unknown>) => ({ [ENTITLEMENT_CLAIM]: o });

describe('@citrate/oidc-client — parseClaims', () => {
  it('reads kyc + entitlement claims', () => {
    const a = parseClaims({
      sub: 'u1',
      email: 'a@b.c',
      email_verified: true,
      wallet_address: '0xabc',
      kyc_status: 'verified',
      kyc_expires_at: '2027-01-01T00:00:00Z',
      ...ent({ tier: 'commercial.kyc', orgId: null, citrateRole: 'auditor' }),
    });
    expect(a.kycStatus).toBe('verified');
    expect(a.entitlement?.tier).toBe('commercial.kyc');
    expect(a.entitlement?.citrateRole).toBe('auditor');
    expect(a.walletAddress).toBe('0xabc');
  });

  it('fails safe: absent claims → none / null (Public)', () => {
    const a = parseClaims({ sub: 'u2' });
    expect(a.kycStatus).toBe('none');
    expect(a.entitlement).toBeNull();
    expect(effectiveTier(a)).toBe('public');
  });

  it('ignores an unknown tier value', () => {
    const a = parseClaims(ent({ tier: 'superadmin' }));
    expect(a.entitlement).toBeNull();
  });
});

describe('@citrate/oidc-client — gates', () => {
  it('isKycVerified honors expiry', () => {
    expect(isKycVerified(parseClaims({ kyc_status: 'verified' }))).toBe(true);
    expect(isKycVerified(parseClaims({ kyc_status: 'verified', kyc_expires_at: '2000-01-01T00:00:00Z' }))).toBe(false);
    expect(isKycVerified(parseClaims({ kyc_status: 'pending' }))).toBe(false);
  });

  it('requireTier uses the ladder; commercial.kyc ≥ commercial', () => {
    const a = parseClaims(ent({ tier: 'commercial.kyc', orgId: null }));
    expect(requireTier(a, 'public')).toBe(true);
    expect(requireTier(a, 'commercial')).toBe(true);
    expect(requireTier(a, 'commercial.kyc')).toBe(true);
    expect(requireTier(a, 'confidential')).toBe(false);
    expect(requireTier(parseClaims({}), 'commercial')).toBe(false); // absent → public
  });

  it('expired entitlement collapses to public', () => {
    const a = parseClaims(ent({ tier: 'confidential', orgId: null, expiresAt: Date.now() - 1000 }));
    expect(effectiveTier(a)).toBe('public');
    expect(requireTier(a, 'commercial')).toBe(false);
  });

  it('requireRole matches citrateRole', () => {
    const a = parseClaims(ent({ tier: 'confidential', orgId: null, citrateRole: 'admin' }));
    expect(requireRole(a, 'admin')).toBe(true);
    expect(requireRole(a, 'auditor')).toBe(false);
  });
});

describe('@citrate/oidc-client — URLs', () => {
  it('accountHubUrl + kycStartUrl build correctly', () => {
    expect(accountHubUrl('https://auth.citrate.ai/', 'https://explorer.citrate.ai')).toBe(
      'https://auth.citrate.ai/account?return_to=https%3A%2F%2Fexplorer.citrate.ai',
    );
    const k = new URL(kycStartUrl('https://auth.citrate.ai', 'https://explorer.citrate.ai'));
    expect(k.pathname).toBe('/kyc/start');
    expect(k.searchParams.get('level')).toBe('T3');
    expect(k.searchParams.get('return_to')).toBe('https://explorer.citrate.ai');
  });
});
