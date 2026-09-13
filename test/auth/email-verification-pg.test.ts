/**
 * Unit tests for the email-verification OTP store (FWA #87.1):
 * single-use, TTL, attempt cap, resend rate-limit, code↔email binding.
 */
import { describe, expect, it, vi, afterEach } from 'vitest';
import {
  InMemoryEmailVerificationStore,
  MAX_ATTEMPTS,
  MAX_SENDS_PER_WINDOW,
  CODE_TTL_MS,
} from '../../src/auth/email-verification-pg.js';

afterEach(() => vi.useRealTimers());

describe('InMemoryEmailVerificationStore', () => {
  it('issues a 6-digit code and verifies it once (single-use)', async () => {
    const s = new InMemoryEmailVerificationStore();
    const { code, rateLimited } = await s.issue('a@b.co', 'pwhash');
    expect(rateLimited).toBe(false);
    expect(code).toMatch(/^\d{6}$/);
    const first = await s.consume('a@b.co', code!);
    expect(first).toEqual({ ok: true, passwordHash: 'pwhash' });
    // Second use of the same code fails — it was consumed.
    expect(await s.consume('a@b.co', code!)).toEqual({ ok: false });
  });

  it('rejects a wrong code and invalidates after MAX_ATTEMPTS', async () => {
    const s = new InMemoryEmailVerificationStore();
    const { code } = await s.issue('a@b.co');
    for (let i = 0; i < MAX_ATTEMPTS; i++) {
      expect(await s.consume('a@b.co', '000000')).toEqual({ ok: false });
    }
    // Even the CORRECT code no longer works once the attempt cap is hit.
    expect(await s.consume('a@b.co', code!)).toEqual({ ok: false });
  });

  it('expires a code after the TTL', async () => {
    vi.useFakeTimers();
    const s = new InMemoryEmailVerificationStore();
    const { code } = await s.issue('a@b.co');
    vi.advanceTimersByTime(CODE_TTL_MS + 1000);
    expect(await s.consume('a@b.co', code!)).toEqual({ ok: false });
  });

  it('rate-limits resends per email within the window', async () => {
    const s = new InMemoryEmailVerificationStore();
    for (let i = 0; i < MAX_SENDS_PER_WINDOW; i++) {
      expect((await s.issue('a@b.co')).rateLimited).toBe(false);
    }
    const over = await s.issue('a@b.co');
    expect(over.rateLimited).toBe(true);
    expect(over.code).toBeUndefined();
  });

  it('binds the code to the email (not portable to another address)', async () => {
    const s = new InMemoryEmailVerificationStore();
    const { code } = await s.issue('a@b.co');
    // Same code, different email → no match.
    expect(await s.consume('other@b.co', code!)).toEqual({ ok: false });
    // Correct email still works (the mismatch above was a different address,
    // it did not consume or count against a@b.co).
    expect((await s.consume('a@b.co', code!)).ok).toBe(true);
  });

  it('is enumeration-neutral: issue never signals whether an email exists', async () => {
    const s = new InMemoryEmailVerificationStore();
    const a = await s.issue('known@b.co', 'h');
    const b = await s.issue('unknown@b.co');
    // Same shape regardless of any account state (the store holds no user data).
    expect(a.rateLimited).toBe(false);
    expect(b.rateLimited).toBe(false);
    expect(a.code).toMatch(/^\d{6}$/);
    expect(b.code).toMatch(/^\d{6}$/);
  });
});
