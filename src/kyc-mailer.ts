/**
 * KYC transactional email (VERI) — the "your identity is verified" confirmation sent
 * when a case is approved (engine auto-verify OR admin adjudication). Uses the same
 * SMTP env the rest of the Citrate ecosystem uses (landing/dataroom): `SMTP_HOST`,
 * `SMTP_PORT`, `SMTP_SECURE`, `SMTP_USER`, `SMTP_PASSWORD` (or `SMTP_PASS`), and
 * `MAIL_FROM` (or `EMAIL_FROM`).
 *
 * GRACEFUL: if SMTP isn't configured the send is a logged no-op — it never blocks a
 * verification or crashes boot. `nodemailer` is imported lazily so dev/test that never
 * send mail don't pull the driver in.
 */

import type { Transporter } from 'nodemailer';

let cached: Transporter | null | undefined;

interface SmtpConfig {
  host: string;
  port: number;
  secure: boolean;
  user: string;
  pass: string;
  from: string;
}

function smtpConfig(): SmtpConfig | null {
  const host = process.env.SMTP_HOST?.trim();
  if (!host) return null;
  return {
    host,
    port: Number(process.env.SMTP_PORT || 587),
    secure: /^(1|true|yes)$/i.test((process.env.SMTP_SECURE || '').trim()),
    user: (process.env.SMTP_USER || '').trim(),
    pass: (process.env.SMTP_PASSWORD ?? process.env.SMTP_PASS ?? '').trim(),
    from: (process.env.MAIL_FROM ?? process.env.EMAIL_FROM ?? 'Citrate <no-reply@citrate.ai>').trim(),
  };
}

/** True when a delivery path (HTTPS relay or SMTP) is configured. */
export function isMailerConfigured(): boolean {
  const relay = Boolean(process.env.KYC_EMAIL_RELAY_URL?.trim() && process.env.KYC_EMAIL_RELAY_SECRET?.trim());
  return relay || smtpConfig() !== null;
}

async function transporter(): Promise<Transporter | null> {
  if (cached !== undefined) return cached;
  const cfg = smtpConfig();
  if (!cfg) {
    cached = null;
    return null;
  }
  const nodemailer = (await import('nodemailer')).default;
  cached = nodemailer.createTransport({
    host: cfg.host,
    port: cfg.port,
    secure: cfg.secure,
    requireTLS: !cfg.secure,
    auth: cfg.user ? { user: cfg.user, pass: cfg.pass } : undefined,
    tls: { minVersion: 'TLSv1.2', rejectUnauthorized: true },
  });
  return cached;
}

function approvedHtml(): string {
  return `<!doctype html><html><body style="margin:0;background:#f1eee6;font-family:'Geist',system-ui,Segoe UI,sans-serif;color:#0e0f0c">
  <div style="max-width:520px;margin:0 auto;padding:24px">
    <div style="background:#0f2a1a;color:#f1eee6;border-radius:9px 9px 0 0;padding:16px 20px;font-weight:600;letter-spacing:-.01em">Citrate</div>
    <div style="background:#faf8f3;border:1px solid #dbdcd5;border-top:0;border-radius:0 0 9px 9px;padding:24px 20px">
      <h1 style="font-size:22px;margin:0 0 10px;letter-spacing:-.015em">You're verified ✓</h1>
      <p style="color:#555851;line-height:1.55;margin:0 0 14px">Good news — your identity has been confirmed. You now have full verified-member access across the Citrate ecosystem.</p>
      <p style="color:#555851;line-height:1.55;margin:0 0 20px">Nothing else is needed. If you didn't request this verification, please contact us right away.</p>
      <a href="https://citrate.ai" style="display:inline-block;background:#8ecc09;color:#112005;text-decoration:none;font-weight:600;padding:11px 18px;border-radius:6px">Continue to Citrate →</a>
      <p style="color:#8a8c84;font-size:12px;margin:22px 0 0">Your ID and face were encrypted on your device and your face was deleted right after the identity match. Questions? Reply to this email.</p>
    </div>
  </div></body></html>`;
}

/**
 * Send the "identity verified" confirmation. Returns true if it was accepted for
 * delivery, false if skipped/errored — never throws.
 *
 * PATH 1 — HTTPS relay (preferred, and the ONLY path that works on the DO droplet,
 * where all outbound SMTP ports are blocked): POST `{ to }` to `KYC_EMAIL_RELAY_URL`
 * (a small authed endpoint on the landing site, which runs on Vercel and CAN reach
 * Office 365) with `Authorization: Bearer KYC_EMAIL_RELAY_SECRET`. Reuses the existing
 * email system without giving the droplet SMTP egress.
 *
 * PATH 2 — direct SMTP fallback (for hosts that allow SMTP egress; not the droplet).
 */
export async function sendKycApprovedEmail(to: string): Promise<boolean> {
  const relayUrl = process.env.KYC_EMAIL_RELAY_URL?.trim();
  const relaySecret = process.env.KYC_EMAIL_RELAY_SECRET?.trim();
  if (relayUrl && relaySecret) {
    try {
      const r = await fetch(relayUrl, {
        method: 'POST',
        headers: { 'content-type': 'application/json', authorization: `Bearer ${relaySecret}` },
        body: JSON.stringify({ to }),
      });
      if (r.ok) return true;
      // eslint-disable-next-line no-console
      console.error(`[citrate-identity] KYC email relay returned ${r.status}`);
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error('[citrate-identity] KYC email relay error:', (err as Error).message);
    }
    return false;
  }

  const cfg = smtpConfig();
  const t = await transporter();
  if (!cfg || !t) {
    // eslint-disable-next-line no-console
    console.warn(
      '[citrate-identity] KYC approval email skipped — SMTP not configured. Set ' +
        'SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, SMTP_SECURE, MAIL_FROM.',
    );
    return false;
  }
  try {
    await t.sendMail({
      from: cfg.from,
      to,
      subject: 'Your Citrate identity is verified ✓',
      text: "Good news — your identity has been verified. You now have full verified-member access across the Citrate ecosystem. If you didn't request this, contact support@citrate.ai.",
      html: approvedHtml(),
      headers: { 'X-Citrate-Mail': 'kyc-approved' },
    });
    return true;
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('[citrate-identity] KYC approval email failed:', (err as Error).message);
    return false;
  }
}
