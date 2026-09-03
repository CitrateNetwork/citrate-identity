/**
 * AUTHSPINE S1-WP3 — the Account Hub (`GET /account`).
 *
 * The one authenticated surface every Citrate app links to ("Manage account /
 * Upgrade"). It reads the user's auth.citrate.ai session and shows: who they are,
 * their Citrate wallet address, KYC status with a Start/Finish-verification CTA,
 * and their current access tier/role. Finishing KYC here auto-grants the baseline
 * tier (S1-WP2), so this page is where a user upgrades their account ecosystem-wide.
 *
 * Auth model: relies on the existing OIDC session cookie (the user is signed in to
 * some RP, so the authority has a session). No session → a friendly "sign in first"
 * page (the hub is normally reached from a logged-in RP via `return_to`).
 *
 * No PII beyond what the session already exposes; the page never stores anything.
 */
import type Provider from 'oidc-provider';
import type { ServerResponse } from 'node:http';

import { getKycStore, effectiveVerified, type KycStatus, type KycClaim } from './kyc.js';
import { resolveEntitlementClaim, type EntitlementClaim } from './entitlements.js';
import { getUserStore } from './auth/stores.js';
import { predictedWalletForAccount } from './aa/wallet-claims.js';
import type { HandoffStore } from './handoff-store.js';

function escapeHtml(v: string): string {
  return v
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function sendHtml(res: ServerResponse, status: number, html: string): void {
  res.writeHead(status, {
    'content-type': 'text/html; charset=utf-8',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
  });
  res.end(html);
}

/** The authority's own origin (for return_to round-trips + branding). */
function selfOrigin(): string {
  return (process.env.ISSUER_URL || 'https://auth.citrate.ai').replace(/\/+$/, '');
}

/** Validate an optional ?return_to back-link to a Citrate app (https + *.citrate.ai or vercel.app). */
function validatedBackLink(v: unknown): string | undefined {
  if (typeof v !== 'string' || !v) return undefined;
  let u: URL;
  try {
    u = new URL(v);
  } catch {
    return undefined;
  }
  if (u.protocol !== 'https:') return undefined;
  const h = u.hostname;
  return h.endsWith('.citrate.ai') || h.endsWith('.vercel.app') ? v : undefined;
}

const PAGE_CSS = `
:root{--paper:#f1eee6;--ink:#1a1a17;--muted:#6b675e;--line:#dcd7ca;--card:#fbfaf6;--green:#8ecc09;--green-ink:#1a1a17;--bad:#b4453a;--warn:#b07a17}
*{box-sizing:border-box}body{margin:0;font-family:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;background:var(--paper);color:var(--ink);line-height:1.5}
.wrap{max-width:560px;margin:0 auto;padding:32px 20px 64px}
h1{font-size:22px;margin:0 0 2px}.sub{color:var(--muted);font-size:13px;margin:0 0 22px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px 18px;margin:0 0 14px}
.card h2{font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin:0 0 12px}
.row{display:flex;justify-content:space-between;gap:12px;padding:6px 0;font-size:14px}
.row .k{color:var(--muted)}.row .v{text-align:right;word-break:break-all}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px}
.badge{display:inline-block;padding:2px 9px;border-radius:999px;font-size:12px;font-weight:600;border:1px solid var(--line)}
.badge.ok{background:var(--green);color:var(--green-ink);border-color:var(--green)}
.badge.warn{background:#f6ecd0;color:var(--warn);border-color:#e6d6a8}
.badge.bad{background:#f4dad6;color:var(--bad);border-color:#e6bcb5}
.badge.muted{background:#efece4;color:var(--muted)}
.btn{display:inline-block;width:100%;text-align:center;padding:11px 14px;border-radius:8px;border:1px solid var(--green);background:var(--green);color:var(--green-ink);font-weight:600;font-size:14px;text-decoration:none;cursor:pointer}
.btn.secondary{background:transparent;border-color:var(--line);color:var(--ink);font-weight:500}
.note{color:var(--muted);font-size:12.5px;margin:10px 0 0}
.back{display:inline-block;margin-bottom:18px;color:var(--muted);font-size:13px;text-decoration:none}
.back:hover{color:var(--ink)}
`;

function kycLive(claim: KycClaim | undefined): KycStatus | 'none' | 'expired' {
  if (!claim) return 'none';
  if (effectiveVerified(claim)) return 'verified';
  return claim.status === 'verified' ? 'expired' : claim.status;
}

function tierLabel(ent: EntitlementClaim | null): string {
  if (!ent || ent.tier === 'public') return 'Public';
  const t = ent.tier === 'commercial.kyc' ? 'Commercial (KYC-verified)' : ent.tier.charAt(0).toUpperCase() + ent.tier.slice(1);
  return ent.citrateRole ? `${t} · ${ent.citrateRole}` : t;
}

function renderHub(args: {
  email: string | null;
  signingMethod: string | null;
  wallet: string | undefined;
  kyc: KycStatus | 'none' | 'expired';
  verifiedAt?: string;
  expiresAt?: string;
  ent: EntitlementClaim | null;
  backLink?: string;
}): string {
  const { email, signingMethod, wallet, kyc, ent, backLink } = args;
  const kycBadge =
    kyc === 'verified' ? '<span class="badge ok">Verified</span>'
    : kyc === 'pending' ? '<span class="badge warn">In review</span>'
    : kyc === 'expired' ? '<span class="badge warn">Expired</span>'
    : kyc === 'revoked' ? '<span class="badge bad">Revoked</span>'
    : '<span class="badge muted">Not started</span>';
  const startUrl = `${selfOrigin()}/kyc/start?level=T3&return_to=${encodeURIComponent(`${selfOrigin()}/account`)}`;
  const kycCta =
    kyc === 'verified'
      ? `<p class="note">Identity verified${args.expiresAt ? ` — valid until ${escapeHtml(args.expiresAt.slice(0, 10))}` : ''}. This unlocks your baseline access across Citrate apps.</p>`
      : `<a class="btn" href="${escapeHtml(startUrl)}">${kyc === 'expired' || kyc === 'revoked' ? 'Re-verify identity' : 'Start identity verification'}</a>
         <p class="note">Optional — verifying your identity upgrades your account and unlocks verified-member access ecosystem-wide. Your ID and face are encrypted on your device before upload; your face is deleted right after the identity match.</p>`;
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Your Citrate account</title><style>${PAGE_CSS}</style></head><body><div class="wrap">
${backLink ? `<a class="back" href="${escapeHtml(backLink)}">&larr; Back to the app</a>` : ''}
<h1>Your Citrate account</h1>
<p class="sub">One identity across every Citrate site &amp; app.</p>

<div class="card"><h2>Identity</h2>
  <div class="row"><span class="k">Email</span><span class="v">${email ? escapeHtml(email) : '<span class="badge muted">none</span>'}</span></div>
  <div class="row"><span class="k">Sign-in method</span><span class="v">${escapeHtml(signingMethod || 'passkey/wallet')}</span></div>
  <div class="row"><span class="k">Wallet</span><span class="v mono">${wallet ? escapeHtml(wallet) : '<span class="badge muted">not provisioned</span>'}</span></div>
</div>

<div class="card"><h2>Identity verification (KYC)</h2>
  <div class="row"><span class="k">Status</span><span class="v">${kycBadge}</span></div>
  ${kycCta}
</div>

<div class="card"><h2>Access tier</h2>
  <div class="row"><span class="k">Tier</span><span class="v">${escapeHtml(tierLabel(ent))}</span></div>
  ${ent?.expiresAt ? `<div class="row"><span class="k">Expires</span><span class="v">${escapeHtml(new Date(ent.expiresAt).toISOString().slice(0,10))}</span></div>` : ''}
  <p class="note">Your tier is read by every Citrate app from this account. Higher tiers (academic, confidential, org roles) are granted by Citrate.</p>
</div>
</div></body></html>`;
}

function renderSignedOut(): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Your Citrate account</title><style>${PAGE_CSS}</style></head><body><div class="wrap">
<h1>Your Citrate account</h1>
<p class="sub">Sign in through any Citrate app, then return here to manage your account and verify your identity.</p>
<div class="card"><p class="note">You're not signed in. Open a Citrate app (e.g. the explorer or dashboard), sign in, and use its "Manage account" link to come back here.</p></div>
</div></body></html>`;
}

/** Options for {@link mountAccountRoute}. */
export interface AccountRouteOptions {
  /**
   * Authenticated hand-off store (item 2, 2026-08-06). When present, a
   * `?handoff=<nonce>` on `/account` resolves the acting subject from the nonce
   * the app minted at `POST /kyc/handoff`, IGNORING the browser cookie — so
   * "Manage account" opens the APP's account, not whichever one the browser
   * holds. Omitted → cookie-only behaviour, unchanged.
   */
  handoffStore?: HandoffStore;
}

/**
 * Mount `GET /account` — the Account Hub. Reads the OIDC session (or a `?handoff=`
 * nonce, which wins); renders the user's identity, wallet, KYC status (+
 * Start/Finish CTA), and access tier. Optional `?return_to=<https
 * *.citrate.ai|*.vercel.app>` shows a back-link to the calling app.
 */
export function mountAccountRoute(
  provider: Provider,
  options: AccountRouteOptions = {},
): void {
  const handoffStore = options.handoffStore;
  provider.use(async (ctx, next) => {
    if (ctx.method !== 'GET' || ctx.path !== '/account') return next();

    // Authenticated hand-off wins over the cookie (item 2): a single-use,
    // subject-bound nonce the desktop app minted with its own access token. A
    // present-but-invalid nonce falls through to the cookie/signed-out render
    // (this is a read-only page — unlike /kyc/start there is no wrong-account
    // side effect to guard against, so a stale link simply shows the hub for
    // whoever the browser is, or the signed-out copy).
    let accountId: string | undefined;
    const handoffNonce = ctx.query['handoff'];
    if (handoffStore && typeof handoffNonce === 'string' && handoffNonce) {
      accountId = (await handoffStore.consume(handoffNonce)) ?? undefined;
    }
    if (!accountId) {
      try {
        const session = await provider.Session.get(ctx);
        accountId = session?.accountId;
      } catch {
        accountId = undefined;
      }
    }
    if (!accountId) {
      sendHtml(ctx.res, 200, renderSignedOut());
      return;
    }

    // Resolve the same facts findAccount mints, directly (findById throws on a
    // non-UUID sub like a SIWE address — tolerate that).
    let rec;
    try {
      rec = await getUserStore().findById(accountId);
    } catch {
      rec = undefined;
    }
    const wallet = rec?.primaryWallet ?? predictedWalletForAccount(accountId);
    const claim = await getKycStore().get(accountId);
    const kyc = kycLive(claim);
    const ent = await resolveEntitlementClaim(
      accountId,
      wallet ?? null,
      rec?.email ?? null,
      kyc,
      rec?.emailVerified ?? false, // F-01: only a verified email matches a grant
    );
    const backLink = validatedBackLink(ctx.query['return_to']);

    sendHtml(
      ctx.res,
      200,
      renderHub({
        email: rec?.email ?? null,
        signingMethod: rec?.lastSigningMethod ?? null,
        wallet,
        kyc,
        verifiedAt: claim?.verified_at,
        expiresAt: claim?.expires_at,
        ent,
        backLink,
      }),
    );
  });
}
