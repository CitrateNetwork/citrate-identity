/**
 * Degenerate-expiry guard (isExpired / effectiveVerified): a verified claim whose
 * expires_at is at or before verified_at is a write anomaly (zero/negative TTL),
 * NOT a real expiry — it must still read as verified so a freshly-verified user is
 * never silently locked out.
 */
import { describe, expect, it } from 'vitest';
import { isExpired, effectiveVerified, type KycClaim } from '../src/kyc.js';

const at = (iso: string) => new Date(iso);

describe('isExpired — degenerate-expiry guard', () => {
  it('treats expires_at == verified_at as NOT expired (the real-world bug)', () => {
    const claim: KycClaim = {
      status: 'verified',
      vendor_ref: 'app1',
      verified_at: '2026-06-18T15:51:29.209Z',
      expires_at: '2026-06-18T15:51:29.209Z',
    };
    expect(isExpired(claim, at('2026-06-18T16:00:00Z'))).toBe(false);
    expect(effectiveVerified(claim, at('2026-06-18T16:00:00Z'))).toBe(true);
  });

  it('treats expires_at before verified_at as NOT expired', () => {
    const claim: KycClaim = {
      status: 'verified',
      vendor_ref: 'app1',
      verified_at: '2026-06-18T00:00:00Z',
      expires_at: '2026-06-17T00:00:00Z',
    };
    expect(isExpired(claim, at('2026-06-18T01:00:00Z'))).toBe(false);
  });

  it('still expires a claim with a real future expiry that has passed', () => {
    const claim: KycClaim = {
      status: 'verified',
      vendor_ref: 'app1',
      verified_at: '2026-06-18T00:00:00Z',
      expires_at: '2027-06-18T00:00:00Z',
    };
    expect(isExpired(claim, at('2027-06-19T00:00:00Z'))).toBe(true);
    expect(effectiveVerified(claim, at('2027-06-19T00:00:00Z'))).toBe(false);
    // ...and is verified before that expiry.
    expect(effectiveVerified(claim, at('2026-12-01T00:00:00Z'))).toBe(true);
  });
});
