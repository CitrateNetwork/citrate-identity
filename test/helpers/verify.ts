/**
 * Test helper for the verified-email flow (FWA #87.1). Arms an in-memory OTP
 * store + a capturing email transport so a test can complete register → verify
 * without real Resend delivery. Used by any suite that needs a signed-in
 * password session (register alone no longer signs in).
 */
import { setEmailSender } from '../../src/email-send.js';
import {
  setEmailVerificationStore,
  InMemoryEmailVerificationStore,
} from '../../src/auth/email-verification-pg.js';

let last: string | null = null;

/** Reset the OTP store + install a transport that captures the 6-digit code. */
export function armEmailCapture(): void {
  setEmailVerificationStore(new InMemoryEmailVerificationStore());
  last = null;
  setEmailSender(async (msg) => {
    const m = msg.subject.match(/(\d{6})/);
    last = m ? m[1] : null;
    return true;
  });
}

/** The code from the most recently "sent" verification email. */
export function lastVerificationCode(): string | null {
  return last;
}
