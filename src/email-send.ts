/**
 * Resend-backed transactional email (FWA #87.1).
 *
 * The DO droplet blocks outbound SMTP, so verification email MUST go over an
 * HTTPS API. We use Resend directly (no SDK dependency — a single `fetch` to
 * the documented REST endpoint), with the sending domain (`citrate.ai`)
 * verified in Resend so DKIM/SPF/DMARC pass. `kyc-mailer.ts` keeps its own
 * relay/SMTP paths for the KYC templates; this module is the general-purpose
 * sender the auth flow uses.
 *
 * ENV:
 *   RESEND_API_KEY   `re_…` key from resend.com — REQUIRED for delivery.
 *   MAIL_FROM        e.g. `Citrate <noreply@citrate.ai>` (falls back to
 *                    EMAIL_FROM, then a safe default). The domain must be
 *                    verified in Resend.
 *
 * Fail posture: `sendEmail` NEVER throws — it returns false on any skip/error
 * so a mail hiccup can't 500 an auth request. Callers that must fail closed
 * (a verification code the user will never receive) check the boolean and
 * surface a retryable error to the client instead of a silent success.
 */

const RESEND_ENDPOINT = 'https://api.resend.com/emails';

function fromAddress(): string {
  return (
    process.env.MAIL_FROM?.trim() ||
    process.env.EMAIL_FROM?.trim() ||
    'Citrate <noreply@citrate.ai>'
  );
}

/** True when a delivery transport is configured (Resend). */
export function isEmailConfigured(): boolean {
  return Boolean(process.env.RESEND_API_KEY?.trim());
}

export interface EmailMessage {
  to: string;
  subject: string;
  html: string;
  text: string;
}

export type EmailSender = (msg: EmailMessage) => Promise<boolean>;

/**
 * The active transport. Defaults to Resend; swappable for tests via
 * {@link setEmailSender} so specs can capture the code without real HTTP.
 */
let sender: EmailSender = resendSend;

/** Override the email transport (tests). */
export function setEmailSender(fn: EmailSender): void {
  sender = fn;
}

/** Restore the default Resend transport. */
export function resetEmailSender(): void {
  sender = resendSend;
}

/** Send via the active transport. Never throws (delegates to the transport). */
export async function sendEmail(msg: EmailMessage): Promise<boolean> {
  return sender(msg);
}

/**
 * Default transport: one transactional email via Resend. Returns true on a 2xx
 * from Resend, false on any skip (unconfigured) or error. Never throws.
 */
async function resendSend(msg: EmailMessage): Promise<boolean> {
  const apiKey = process.env.RESEND_API_KEY?.trim();
  if (!apiKey) {
    // eslint-disable-next-line no-console
    console.warn(
      '[citrate-identity] RESEND_API_KEY unset — cannot send email; skipping.',
    );
    return false;
  }
  try {
    const res = await fetch(RESEND_ENDPOINT, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${apiKey}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        from: fromAddress(),
        to: [msg.to],
        subject: msg.subject,
        html: msg.html,
        text: msg.text,
      }),
    });
    if (!res.ok) {
      // eslint-disable-next-line no-console
      console.warn(
        `[citrate-identity] Resend send failed: ${res.status} ${res.statusText}`,
      );
      return false;
    }
    return true;
  } catch (err) {
    // eslint-disable-next-line no-console
    console.warn('[citrate-identity] Resend send threw:', (err as Error).message);
    return false;
  }
}

/**
 * Send a 6-digit email-verification code. The code is the ONLY secret in the
 * body; we keep the copy minimal and never include a link that could be
 * proxied. Returns the sendEmail boolean so the caller can fail closed.
 */
export async function sendVerificationCode(
  to: string,
  code: string,
  ttlMinutes: number,
): Promise<boolean> {
  const subject = `Your Citrate verification code: ${code}`;
  // On-brand template — matches core-membership's email style (dark-green
  // #0e1a13 text, #5b6b60 eyebrow, #8a978d footer) with the citrus-green
  // #8ecc09 brand accent on the code. No link (code-only), no PII, no secret
  // other than the code itself.
  const html = `<!-- verification -->
<div style="font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;max-width:520px;margin:0 auto;color:#0e1a13">
  <p style="font-size:13px;letter-spacing:.06em;text-transform:uppercase;color:#5b6b60;margin:0 0 8px">Verify your email</p>
  <h1 style="font-size:22px;margin:0 0 12px">Confirm it's you.</h1>
  <p style="font-size:14px;line-height:1.6;margin:0">Enter this code in Citrate to verify your email address:</p>
  <p style="margin:20px 0"><span style="display:inline-block;font-family:ui-monospace,Menlo,monospace;font-size:32px;font-weight:700;letter-spacing:8px;color:#0e1a13;background:#e8f3c6;border:1px solid #8ecc09;border-radius:10px;padding:12px 20px">${code}</span></p>
  <p style="font-size:13px;line-height:1.6;color:#5b6b60;margin:0">It expires in ${ttlMinutes} minutes and can be used once.</p>
  <p style="font-size:12px;color:#8a978d;margin:24px 0 0">If you didn't request this, you can ignore this email — no account is created or changed until the code is entered.</p>
  <p style="font-size:12px;color:#8a978d;margin:16px 0 0">Citrate Network</p>
</div>`;
  const text = [
    'Verify your email — Citrate',
    '',
    `Your verification code is: ${code}`,
    '',
    `It expires in ${ttlMinutes} minutes and can be used once.`,
    '',
    "If you didn't request this, you can ignore this email — no account is created or changed until the code is entered.",
    '',
    'Citrate Network',
  ].join('\n');
  return sendEmail({ to, subject, html, text });
}
