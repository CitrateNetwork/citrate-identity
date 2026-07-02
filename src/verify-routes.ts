/**
 * VERI capture flow — token-gated /verify/* routes (VERI-S2).
 *
 * These serve the 3-step identity-capture UI and accept the encrypted artifacts,
 * persisting them into the S1 encrypted case store via the in-house provider.
 *
 * AUTH MODEL: every /verify/* call authenticates by the **capture token** minted in
 * `InhouseKycProvider.mintClientSession` (or a hand-off token) — NOT the OIDC
 * session. That is what lets the flow run on a phone after a QR hand-off, where
 * there is no auth.citrate.ai session. The token is HMAC-signed, short-TTL, and
 * bound to a specific `caseId` — so a token only ever touches its own case.
 *
 * Routes:
 *   GET  /verify                — serve the capture UI (HTML+JS shell).
 *   GET  /verify/dek            — return the case DEK (client seals artifacts with it).
 *   POST /verify/consent        — Step 1: BIPA/terms consent + sealed identity fields.
 *   POST /verify/evidence       — Step 2/3: an encrypted document / liveness artifact.
 *   POST /verify/complete       — mark capture done (decision is VERI-S3's engine).
 *   GET  /verify/status         — desktop polls: {status, captureComplete}.
 *   POST /verify/handoff        — mint a fresh phone-scoped token → QR-able mobile URL.
 *
 * Only active when `KYC_PROVIDER=inhouse`; otherwise every route is a 404 passthrough.
 */

import type Provider from 'oidc-provider';
import type { IncomingMessage, ServerResponse } from 'node:http';
import QRCode from 'qrcode';

import { getKycProvider } from './kyc-providers/index.js';
import { InhouseKycProvider, type CaptureTokenClaims } from './kyc-providers/inhouse.js';
import { renderCaptureUI } from './verify-ui.js';
import { buildVerificationEngine } from './kyc-inference-client.js';
import { loadSanctionsList } from './kyc-screening.js';

/** POST a signed engine decision to the local /kyc/webhook — the entitlement path. */
async function deliverDecision(signed: { body: Buffer; headers: Record<string, string> }): Promise<void> {
  const issuer = (process.env.ISSUER_URL ?? 'http://localhost:3000').replace(/\/+$/, '');
  try {
    await fetch(`${issuer}/kyc/webhook`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...signed.headers },
      body: signed.body,
    });
  } catch {
    /* fail-closed: case stays pending → manual review in the admin dashboard */
  }
}

/** Max encrypted-artifact upload (a base64 ID/selfie image + envelope overhead). */
const MAX_BODY_BYTES = 12 * 1024 * 1024;
/** Hand-off token TTL (seconds) — short, single verification hop. */
const HANDOFF_TTL_SEC = 600;

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  const s = JSON.stringify(body);
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
  res.end(s);
}
function sendHtml(res: ServerResponse, status: number, html: string): void {
  res.writeHead(status, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
  res.end(html);
}

async function readJsonBody(req: IncomingMessage): Promise<Record<string, unknown> | null> {
  const chunks: Buffer[] = [];
  let total = 0;
  return new Promise((resolve) => {
    req.on('data', (c: Buffer) => {
      total += c.length;
      if (total > MAX_BODY_BYTES) {
        // Stop reading; caller sees null → 413-style rejection.
        req.destroy();
        resolve(null);
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => {
      if (chunks.length === 0) return resolve(null);
      try {
        const parsed = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        resolve(parsed && typeof parsed === 'object' ? (parsed as Record<string, unknown>) : null);
      } catch {
        resolve(null);
      }
    });
    req.on('error', () => resolve(null));
  });
}

function str(v: unknown): string | undefined {
  return typeof v === 'string' && v.length > 0 ? v : undefined;
}

function inhouseProvider(): InhouseKycProvider | null {
  const p = getKycProvider();
  return p instanceof InhouseKycProvider ? p : null;
}

/** Validate the capture token carried in the query or body; return its claims or null. */
function authToken(provider: InhouseKycProvider, token: string | undefined): CaptureTokenClaims | null {
  if (!token) return null;
  return provider.verifyCaptureToken(token);
}

export function mountVerifyRoutes(provider: Provider): void {
  provider.use(async (ctx, next) => {
    if (!ctx.path.startsWith('/verify')) return next();
    const ih = inhouseProvider();
    if (!ih) return next(); // not the in-house provider → 404 via the rest of the stack

    // GET /verify — serve the UI shell (JS reads ?session= and drives the API).
    if (ctx.method === 'GET' && ctx.path === '/verify') {
      sendHtml(ctx.res, 200, renderCaptureUI());
      return;
    }

    // GET /verify/dek?session= — hand the case DEK to the authenticated capture UI.
    if (ctx.method === 'GET' && ctx.path === '/verify/dek') {
      const claims = authToken(ih, str(ctx.query['session']));
      if (!claims) return sendJson(ctx.res, 401, { error: 'invalid_or_expired_session' });
      const dek = await ih.getCaseDek(claims.caseId);
      if (!dek) return sendJson(ctx.res, 404, { error: 'case_not_found' });
      sendJson(ctx.res, 200, { dek: dek.toString('base64'), caseId: claims.caseId });
      return;
    }

    // GET /verify/status?session= — desktop poll for hand-off completion.
    if (ctx.method === 'GET' && ctx.path === '/verify/status') {
      const claims = authToken(ih, str(ctx.query['session']));
      if (!claims) return sendJson(ctx.res, 401, { error: 'invalid_or_expired_session' });
      const c = await ih.caseStore.getCase(claims.caseId);
      if (!c) return sendJson(ctx.res, 404, { error: 'case_not_found' });
      const evidence = await ih.caseStore.listEvidence(c.caseId);
      const captureComplete = evidence.some((e) => e.kind === 'other' && e.tier === 3 && e.destroyAfter === undefined && e.ciphertext === 'capture-complete');
      sendJson(ctx.res, 200, { status: c.status, captureComplete, steps: stepFlags(evidence, c.identityCt !== undefined) });
      return;
    }

    // The remaining routes are POST + JSON.
    if (ctx.method !== 'POST') return next();
    const body = await readJsonBody(ctx.req);
    if (!body) return sendJson(ctx.res, 400, { error: 'invalid_or_too_large_body' });
    const claims = authToken(ih, str(body['session']));
    if (!claims) return sendJson(ctx.res, 401, { error: 'invalid_or_expired_session' });
    const store = ih.caseStore;

    // POST /verify/consent — { session, consent:{bipa,terms}, identityCt }
    if (ctx.path === '/verify/consent') {
      const consent = body['consent'] as { bipa?: unknown; terms?: unknown } | undefined;
      if (!consent || consent.bipa !== true || consent.terms !== true) {
        return sendJson(ctx.res, 400, { error: 'consent_required', reason: 'BIPA biometric consent + terms must be accepted' });
      }
      const identityCt = str(body['identityCt']);
      if (!identityCt) return sendJson(ctx.res, 400, { error: 'identity_required' });
      await store.setIdentityCiphertext(claims.caseId, identityCt);
      // Record the consent as a retained tier-3 evidence row (legal record, not PII).
      await store.addEvidence({
        caseId: claims.caseId,
        kind: 'other',
        tier: 3,
        ciphertext: JSON.stringify({ consent: 'bipa+terms', at: Date.now(), ua: str(ctx.headers['user-agent']) ?? null }),
      });
      return sendJson(ctx.res, 200, { ok: true, step: 'consent' });
    }

    // POST /verify/evidence — { session, kind, ciphertext }  (kind ∈ document|liveness|selfie)
    if (ctx.path === '/verify/evidence') {
      const kind = str(body['kind']);
      const ciphertext = str(body['ciphertext']);
      if (!kind || !ciphertext) return sendJson(ctx.res, 400, { error: 'kind_and_ciphertext_required' });
      if (kind !== 'document' && kind !== 'liveness' && kind !== 'selfie') {
        return sendJson(ctx.res, 400, { error: 'unsupported_kind' });
      }
      // Liveness/selfie = Tier-2 biometric → destroy right after the match (BIPA); the
      // engine sets the exact instant, but seed a short backstop window now.
      const isBiometric = kind === 'liveness' || kind === 'selfie';
      await store.addEvidence({
        caseId: claims.caseId,
        kind,
        tier: isBiometric ? 2 : 3,
        ciphertext,
        ...(isBiometric ? { destroyAfter: Date.now() + 24 * 60 * 60 * 1000 } : {}),
      });
      return sendJson(ctx.res, 200, { ok: true, kind });
    }

    // POST /verify/complete — capture finished; decision is the S3 engine's job.
    if (ctx.path === '/verify/complete') {
      await store.setStatus(claims.caseId, 'pending');
      await store.addEvidence({ caseId: claims.caseId, kind: 'other', tier: 3, ciphertext: 'capture-complete' });
      // Auto-verify: when the inference service is configured, run the engine (which
      // calls it), then deliver the decision to the entitlement path. Fire-and-forget so
      // the request returns fast; the /verify finalize poll picks up the decision. On any
      // failure the case stays pending → manual review (fail-closed). When KYC_INFERENCE_URL
      // is unset (dev/test) the engine never runs here — the capture stays pending.
      if (process.env.KYC_INFERENCE_URL) {
        const engine = buildVerificationEngine({
          provider: ih,
          screener: loadSanctionsList([], 'runtime'),
          webhookSecret: process.env.KYC_INHOUSE_WEBHOOK_SECRET ?? '',
          env: process.env,
        });
        void engine
          .runCase(claims.caseId)
          .then((r) => (r ? deliverDecision(r.signedWebhook) : undefined))
          .catch(() => undefined);
      }
      return sendJson(ctx.res, 200, { ok: true, status: 'pending' });
    }

    // POST /verify/handoff — mint a fresh phone-scoped token → QR-able mobile URL.
    if (ctx.path === '/verify/handoff') {
      const { token, expiresAt } = ih.mintCaptureToken(claims.caseId, claims.sub, HANDOFF_TTL_SEC);
      const origin = originOf(ctx);
      const mobileUrl = `${origin}/verify?session=${encodeURIComponent(token)}`;
      // Render the QR ourselves (self-hosted, no third-party service → the capability
      // token never leaves our origin). Brand paper/ink palette.
      const qrSvg = await QRCode.toString(mobileUrl, {
        type: 'svg',
        margin: 1,
        color: { dark: '#1b1a17', light: '#f1eee6' },
      });
      return sendJson(ctx.res, 200, { ok: true, token, expiresAt, mobileUrl, qrSvg });
    }

    return next();
  });
}

function stepFlags(evidence: { kind: string; tier: number }[], hasIdentity: boolean): Record<string, boolean> {
  return {
    consent: hasIdentity,
    document: evidence.some((e) => e.kind === 'document'),
    liveness: evidence.some((e) => e.kind === 'liveness' || e.kind === 'selfie'),
  };
}

function originOf(ctx: { headers: Record<string, string | string[] | undefined>; secure?: boolean }): string {
  const host = (ctx.headers['x-forwarded-host'] as string) ?? (ctx.headers['host'] as string) ?? 'localhost';
  const proto = (ctx.headers['x-forwarded-proto'] as string) ?? (ctx.secure ? 'https' : 'https');
  return `${proto}://${host}`;
}
