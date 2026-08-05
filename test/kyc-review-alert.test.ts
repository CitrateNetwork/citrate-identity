/**
 * Operator alert when a KYC case parks in review.
 *
 * WHY. `needs-review` is TERMINAL until a human acts, and nothing surfaced it.
 * A case could sit indefinitely with the applicant blocked and no operator aware
 * the queue had grown — the console had to be opened on a hunch. (Live on
 * 2026-08-05: one case pending, unnoticed.)
 *
 * The properties that matter, and why each is a property and not a detail:
 *  - it must NEVER block or fail an adjudication (a mail outage is not a KYC
 *    outage), so the engine fires it unawaited and it swallows its own errors;
 *  - it must not leak applicant PII into an inbox — case id and engine reasons
 *    only, with the evidence left behind the admin session;
 *  - it must be opt-in, so an unconfigured deployment stays silent rather than
 *    mailing whoever happens to be on an account record.
 */

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { isKycAlertConfigured, sendKycReviewNeededEmail } from '../src/kyc-mailer.js';

const SAVED = { ...process.env };

beforeEach(() => {
  delete process.env.KYC_ALERT_EMAIL;
  delete process.env.SMTP_HOST;
  delete process.env.KYC_EMAIL_RELAY_URL;
});
afterEach(() => {
  process.env = { ...SAVED };
});

describe('KYC review alert', () => {
  it('is opt-in: no recipients configured means not configured', () => {
    process.env.SMTP_HOST = 'smtp.example.com';
    expect(isKycAlertConfigured()).toBe(false);
  });

  it('needs a delivery path too, not just a recipient', () => {
    process.env.KYC_ALERT_EMAIL = 'larry@citrate.ai';
    // No SMTP_HOST and no relay → nothing can actually be delivered.
    expect(isKycAlertConfigured()).toBe(false);
  });

  it('is configured when both a recipient and SMTP exist', () => {
    process.env.KYC_ALERT_EMAIL = 'larry@citrate.ai';
    process.env.SMTP_HOST = 'smtp.example.com';
    expect(isKycAlertConfigured()).toBe(true);
  });

  it('parses a comma-separated recipient list, tolerating whitespace and blanks', () => {
    process.env.SMTP_HOST = 'smtp.example.com';
    process.env.KYC_ALERT_EMAIL = ' larry@citrate.ai , , ops@citrate.ai ';
    expect(isKycAlertConfigured()).toBe(true);
  });

  it('returns false (never throws) when no recipient is configured', async () => {
    // The engine calls this on every needs-review decision. If an unconfigured
    // deployment threw here, a mail setting would be able to fail a KYC run.
    await expect(sendKycReviewNeededEmail({ caseId: 'case_x' })).resolves.toBe(false);
  });

  it('returns false (never throws) when a recipient exists but SMTP does not', async () => {
    process.env.KYC_ALERT_EMAIL = 'larry@citrate.ai';
    await expect(
      sendKycReviewNeededEmail({ caseId: 'case_x', reasons: ['liveness flagged for review'] }),
    ).resolves.toBe(false);
  });

  it('does not fall back to the approved-email RELAY', async () => {
    // The relay takes only `{to}` and renders the fixed APPROVED template on the
    // far side. Routing an operator alert through it would send an applicant's
    // "you're verified" mail to an admin: wrong template, wrong meaning, wrong
    // recipient. A relay alone must not make the alert deliverable.
    process.env.KYC_ALERT_EMAIL = 'larry@citrate.ai';
    process.env.KYC_EMAIL_RELAY_URL = 'https://relay.example.com/kyc-approved';
    process.env.KYC_EMAIL_RELAY_SECRET = 'shhh';
    await expect(sendKycReviewNeededEmail({ caseId: 'case_x' })).resolves.toBe(false);
  });
});
