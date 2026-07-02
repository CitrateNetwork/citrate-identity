/**
 * VERI admin/compliance routes (VERI-S4) — a THIN wrapper over `admin-kyc-actions`.
 *
 * Every route is gated by the **session-subject allowlist** `KYC_ADMIN_SUBS` (same
 * pattern as `BUNDLER_KEY_ADMIN_SUBS`): the caller's live OIDC session `accountId`
 * must be in the list, else 403. MFA for admin sessions is a login-policy control
 * (NIST 800-171 3.5). Active only when `KYC_PROVIDER=inhouse`.
 *
 * Routes (all under /admin/kyc):
 *   GET  /cases?status=            list case metadata (no ciphertext)
 *   GET  /case?caseId=             one case's metadata + evidence metadata (audited)
 *   POST /adjudicate               {caseId, decision, reason} approve/reject a review
 *   POST /unlock/request           {caseId, reason} dual-control step 1
 *   POST /unlock/approve           {unlockId} dual-control step 2 → decrypt once
 *   POST /delete                   {sub} delete/tombstone a user (D3)
 *   GET  /dsar?sub=                export everything held about a subject
 *   GET  /audit?caseId=            audit log + chain-verification status
 */

import type Provider from 'oidc-provider';
import type { IncomingMessage, ServerResponse } from 'node:http';

import { getKycProvider } from './kyc-providers/index.js';
import { InhouseKycProvider } from './kyc-providers/inhouse.js';
import { renderAdminKycUI } from './admin-kyc-ui.js';
import { getKycAuditLog } from './kyc-audit-pg.js';
import { parseAdminSubs } from './aa/bundler-keys.js';
import type { CaseStatus } from './kyc-cases-pg.js';
import {
  adjudicateCase,
  approveUnlock,
  deleteUser,
  dsarExport,
  listCases,
  requestUnlock,
} from './admin-kyc-actions.js';

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
  res.end(JSON.stringify(body));
}
async function readJson(req: IncomingMessage): Promise<Record<string, unknown> | null> {
  const chunks: Buffer[] = [];
  let total = 0;
  return new Promise((resolve) => {
    req.on('data', (c: Buffer) => {
      total += c.length;
      if (total > 1_000_000) { req.destroy(); resolve(null); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      if (!chunks.length) return resolve(null);
      try {
        const p = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        resolve(p && typeof p === 'object' ? (p as Record<string, unknown>) : null);
      } catch { resolve(null); }
    });
    req.on('error', () => resolve(null));
  });
}
const str = (v: unknown): string | undefined => (typeof v === 'string' && v.length > 0 ? v : undefined);

/** POST a signed decision to the local /kyc/webhook — the unchanged entitlement path. */
async function deliverDecision(signed: { body: Buffer; headers: Record<string, string> }): Promise<boolean> {
  const issuer = (process.env.ISSUER_URL ?? 'http://localhost:3000').replace(/\/+$/, '');
  try {
    const r = await fetch(`${issuer}/kyc/webhook`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...signed.headers },
      body: signed.body,
    });
    return r.ok;
  } catch {
    return false;
  }
}

export function mountAdminKycRoutes(provider: Provider): void {
  provider.use(async (ctx, next) => {
    if (!ctx.path.startsWith('/admin/kyc')) return next();
    const p = getKycProvider();
    const ih = p instanceof InhouseKycProvider ? p : null;
    const audit = getKycAuditLog();
    if (!ih || !audit) return next(); // in-house KYC not configured → 404 downstream

    // --- admin auth: live session subject ∈ KYC_ADMIN_SUBS ---
    let accountId: string | undefined;
    try {
      accountId = (await provider.Session.get(ctx))?.accountId;
    } catch {
      accountId = undefined;
    }
    const admins = parseAdminSubs(process.env.KYC_ADMIN_SUBS);
    if (!accountId || !admins.includes(accountId)) {
      sendJson(ctx.res, 403, { error: 'forbidden', reason: 'admin session required (KYC_ADMIN_SUBS)' });
      return;
    }
    const actor = accountId;
    const store = ih.caseStore;
    const getDek = (id: string) => ih.getCaseDek(id);
    const webhookSecret = process.env.KYC_INHOUSE_WEBHOOK_SECRET ?? '';

    // --- GET routes ---
    if (ctx.method === 'GET' && (ctx.path === '/admin/kyc' || ctx.path === '/admin/kyc/')) {
      ctx.res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
      ctx.res.end(renderAdminKycUI());
      return;
    }
    if (ctx.method === 'GET' && ctx.path === '/admin/kyc/cases') {
      const status = str(ctx.query['status']) as CaseStatus | undefined;
      return sendJson(ctx.res, 200, { cases: await listCases(store, status) });
    }
    if (ctx.method === 'GET' && ctx.path === '/admin/kyc/case') {
      const caseId = str(ctx.query['caseId']);
      if (!caseId) return sendJson(ctx.res, 400, { error: 'caseId_required' });
      const c = await store.getCase(caseId);
      if (!c) return sendJson(ctx.res, 404, { error: 'case_not_found' });
      await audit.record({ actor, action: 'case.view', caseId });
      const evidence = (await store.listEvidence(caseId)).map((e) => ({ kind: e.kind, tier: e.tier, present: !!e.ciphertext, destroyedAt: e.destroyedAt }));
      return sendJson(ctx.res, 200, {
        case: { caseId: c.caseId, externalUserId: c.externalUserId, status: c.status, decision: c.decision, screeningResult: c.screeningResult, legalHold: c.legalHold, verifiedAt: c.verifiedAt, expiresAt: c.expiresAt, retentionUntil: c.retentionUntil },
        evidence,
      });
    }
    if (ctx.method === 'GET' && ctx.path === '/admin/kyc/dsar') {
      const sub = str(ctx.query['sub']);
      if (!sub) return sendJson(ctx.res, 400, { error: 'sub_required' });
      return sendJson(ctx.res, 200, await dsarExport(store, audit, { actor, sub, getDek }));
    }
    if (ctx.method === 'GET' && ctx.path === '/admin/kyc/audit') {
      const caseId = str(ctx.query['caseId']);
      const [entries, chain] = await Promise.all([audit.list({ caseId }), audit.verifyChain()]);
      return sendJson(ctx.res, 200, { entries, chain });
    }

    // --- POST routes ---
    if (ctx.method === 'POST') {
      const body = await readJson(ctx.req);
      if (!body) return sendJson(ctx.res, 400, { error: 'invalid_body' });

      if (ctx.path === '/admin/kyc/adjudicate') {
        const caseId = str(body['caseId']);
        const decision = str(body['decision']);
        const reason = str(body['reason']) ?? '';
        if (!caseId || (decision !== 'verified' && decision !== 'rejected')) {
          return sendJson(ctx.res, 400, { error: 'caseId + decision(verified|rejected) required' });
        }
        const r = await adjudicateCase(store, audit, { actor, caseId, decision, reason, webhookSecret });
        if (r.ok) {
          // Deliver the decision to the unchanged /kyc/webhook entitlement path (D1)
          // so a `verified` adjudication mints the baseline entitlement claim.
          const granted = await deliverDecision(r.signedWebhook);
          return sendJson(ctx.res, 200, { ok: true, decision, entitlementDelivered: granted });
        }
        return sendJson(ctx.res, 400, r);
      }
      if (ctx.path === '/admin/kyc/unlock/request') {
        const caseId = str(body['caseId']);
        const reason = str(body['reason']);
        if (!caseId || !reason) return sendJson(ctx.res, 400, { error: 'caseId + reason required' });
        return sendJson(ctx.res, 200, await requestUnlock(store, audit, { actor, caseId, reason }));
      }
      if (ctx.path === '/admin/kyc/unlock/approve') {
        const unlockId = str(body['unlockId']);
        if (!unlockId) return sendJson(ctx.res, 400, { error: 'unlockId_required' });
        const r = await approveUnlock(store, audit, { approver: actor, unlockId, getDek });
        return sendJson(ctx.res, r.ok ? 200 : 400, r);
      }
      if (ctx.path === '/admin/kyc/delete') {
        const sub = str(body['sub']);
        if (!sub) return sendJson(ctx.res, 400, { error: 'sub_required' });
        return sendJson(ctx.res, 200, await deleteUser(store, audit, { actor, sub }));
      }
    }

    return next();
  });
}
