/**
 * VERI admin/compliance actions (VERI-S4-WP1/2/3/4).
 *
 * Pure-ish action functions the admin routes wrap. Each takes the store + audit log
 * + the acting admin's sub, does its work against the encrypted case store, and
 * writes a PII-FREE audit row. Kept separate from the HTTP/session layer so the
 * compliance logic is unit-testable (the codebase's authorize*-is-pure pattern).
 *
 * Guarantees enforced here:
 *   - **Dual control** for subpoena decrypt: the approver MUST differ from the
 *     requester, the request must be unconsumed (single-use). Decrypted PII is
 *     returned once to the caller and never persisted; only the fact of access is
 *     logged (ADR-2026-07-01-kyc-data-controller-reversal).
 *   - **Delete** follows the three-tier rule (D3): tombstone under a legal hold,
 *     else hard-delete.
 *   - Nothing here writes plaintext PII into the audit log.
 */

import { createHmac } from 'node:crypto';
import type { KycCaseStore, CaseStatus } from './kyc-cases-pg.js';
import type { KycAuditLog } from './kyc-audit-pg.js';
import { openField } from './kyc-crypto.js';

/** Per-case DEK provider (least privilege — the actions never hold the master key). */
export type GetDek = (caseId: string) => Promise<Buffer | null>;

export interface CaseSummary {
  caseId: string;
  externalUserId: string;
  status: CaseStatus;
  decision?: string;
  screeningResult?: string;
  createdAt: number;
  updatedAt: number;
}

/** List cases (metadata only — never ciphertext or biometrics). */
export async function listCases(store: KycCaseStore, status: CaseStatus | undefined, limit = 100): Promise<CaseSummary[]> {
  // The store has no bulk list yet; add a narrow query here to keep the surface small.
  const anyStore = store as unknown as { ['pool']: { query(t: string, p?: unknown[]): Promise<{ rows: Record<string, unknown>[] }> } };
  const res = status
    ? await anyStore.pool.query(
        `SELECT case_id, external_user_id, status, decision, screening_result, created_at, updated_at
         FROM kyc_cases WHERE status = $1 AND tombstoned_at IS NULL ORDER BY created_at DESC LIMIT ${Math.min(Math.max(1, limit), 1000)}`,
        [status],
      )
    : await anyStore.pool.query(
        `SELECT case_id, external_user_id, status, decision, screening_result, created_at, updated_at
         FROM kyc_cases WHERE tombstoned_at IS NULL ORDER BY created_at DESC LIMIT ${Math.min(Math.max(1, limit), 1000)}`,
      );
  return res.rows.map((r) => ({
    caseId: String(r.case_id),
    externalUserId: String(r.external_user_id),
    status: String(r.status) as CaseStatus,
    decision: r.decision ? String(r.decision) : undefined,
    screeningResult: r.screening_result ? String(r.screening_result) : undefined,
    createdAt: Number(r.created_at),
    updatedAt: Number(r.updated_at),
  }));
}

/** Admin adjudicates a case (approve/reject). Returns the signed webhook for the entitlement path. */
export async function adjudicateCase(
  store: KycCaseStore,
  audit: KycAuditLog,
  opts: { actor: string; caseId: string; decision: 'verified' | 'rejected'; reason: string; webhookSecret: string },
): Promise<{ ok: true; signedWebhook: { body: Buffer; headers: Record<string, string> } } | { ok: false; error: string }> {
  const c = await store.getCase(opts.caseId);
  if (!c) return { ok: false, error: 'case_not_found' };
  if (c.tombstonedAt) return { ok: false, error: 'case_tombstoned' };
  const now = Date.now();
  await store.setDecision(opts.caseId, {
    decision: opts.decision,
    screeningResult: c.screeningResult,
    ...(opts.decision === 'verified'
      ? { verifiedAt: now, expiresAt: now + 365 * 864e5, retentionUntil: now + 365 * 864e5 }
      : { retentionUntil: now + 365 * 864e5 }),
  });
  // BIPA: destroy the biometric once a decision is recorded (D3.2).
  const biometricsDestroyed = await store.destroyBiometricsForCase(opts.caseId, now);
  await audit.record({ actor: opts.actor, action: 'case.adjudicate', caseId: opts.caseId, detail: { decision: opts.decision, reason: opts.reason, biometricsDestroyed } });
  const body = Buffer.from(
    JSON.stringify({ caseId: opts.caseId, externalUserId: c.externalUserId, kind: opts.decision, occurredAt: now, screeningResult: c.screeningResult }),
    'utf8',
  );
  const sig = createHmac('sha256', opts.webhookSecret).update(body).digest('hex');
  return { ok: true, signedWebhook: { body, headers: { 'x-citrate-kyc-sig': sig } } };
}

/** Step 1 of dual control: an admin requests a subpoena/dispute unlock. */
export async function requestUnlock(
  store: KycCaseStore,
  audit: KycAuditLog,
  opts: { actor: string; caseId: string; reason: string },
): Promise<{ ok: true; unlockId: string } | { ok: false; error: string }> {
  const c = await store.getCase(opts.caseId);
  if (!c) return { ok: false, error: 'case_not_found' };
  const req = await store.createUnlockRequest(opts.caseId, opts.actor, opts.reason);
  await audit.record({ actor: opts.actor, action: 'unlock.request', caseId: opts.caseId, detail: { unlockId: req.unlockId, reason: opts.reason } });
  return { ok: true, unlockId: req.unlockId };
}

/** Step 2: a DIFFERENT admin approves → decrypt identity ONCE (returned, never persisted). */
export async function approveUnlock(
  store: KycCaseStore,
  audit: KycAuditLog,
  opts: { approver: string; unlockId: string; getDek: GetDek },
): Promise<{ ok: true; caseId: string; identity: unknown; evidenceAvailable: string[] } | { ok: false; error: string }> {
  const req = await store.getUnlockRequest(opts.unlockId);
  if (!req) return { ok: false, error: 'unlock_not_found' };
  if (req.consumedAt) return { ok: false, error: 'unlock_already_used' };
  if (req.requestedBy === opts.approver) return { ok: false, error: 'dual_control_violation: approver must differ from requester' };
  const c = await store.getCase(req.caseId);
  if (!c) return { ok: false, error: 'case_not_found' };

  const dek = await opts.getDek(req.caseId);
  if (!dek) return { ok: false, error: 'case_not_found' };
  const identity = c.identityCt ? JSON.parse(openField(c.identityCt, dek)) : null;
  const evidence = await store.listEvidence(req.caseId);
  const evidenceAvailable = evidence.filter((e) => e.ciphertext).map((e) => e.kind); // biometrics are usually already destroyed

  await store.consumeUnlockRequest(opts.unlockId, opts.approver);
  // Audit the ACCESS — never the plaintext.
  await audit.record({
    actor: opts.approver,
    action: 'unlock.decrypt',
    caseId: req.caseId,
    detail: { unlockId: req.unlockId, requestedBy: req.requestedBy, approvedBy: opts.approver, evidenceAvailable },
  });
  return { ok: true, caseId: req.caseId, identity, evidenceAvailable };
}

/** Delete a user (D3): tombstone under a legal hold, else hard-delete every case. */
export async function deleteUser(
  store: KycCaseStore,
  audit: KycAuditLog,
  opts: { actor: string; sub: string },
): Promise<{ ok: true; cases: { caseId: string; mode: string }[] }> {
  const results: { caseId: string; mode: string }[] = [];
  // Delete all cases for the user (there may be several across re-verifications).
  let latest = await store.getLatestCaseForUser(opts.sub);
  const seen = new Set<string>();
  while (latest && !seen.has(latest.caseId)) {
    seen.add(latest.caseId);
    const mode = await store.deleteCase(latest.caseId);
    results.push({ caseId: latest.caseId, mode });
    latest = await store.getLatestCaseForUser(opts.sub);
  }
  await audit.record({ actor: opts.actor, action: 'user.delete', detail: { sub: opts.sub, cases: results } });
  return { ok: true, cases: results };
}

/** DSAR "export my data": everything held about a subject, decrypted for the export. */
export async function dsarExport(
  store: KycCaseStore,
  audit: KycAuditLog,
  opts: { actor: string; sub: string; getDek: GetDek },
): Promise<{ ok: true; sub: string; cases: unknown[] }> {
  // Gather (non-tombstoned) cases for the sub via the admin list, then decrypt each.
  const summaries = (await listCases(store, undefined)).filter((s) => s.externalUserId === opts.sub);
  const cases: unknown[] = [];
  for (const s of summaries) {
    const c = await store.getCase(s.caseId);
    if (!c) continue;
    const dek = await opts.getDek(c.caseId);
    const identity = dek && c.identityCt ? JSON.parse(openField(c.identityCt, dek)) : null;
    const evidence = (await store.listEvidence(c.caseId)).map((e) => ({ kind: e.kind, tier: e.tier, present: !!e.ciphertext, destroyedAt: e.destroyedAt }));
    cases.push({
      caseId: c.caseId,
      status: c.status,
      decision: c.decision,
      screeningResult: c.screeningResult,
      verifiedAt: c.verifiedAt,
      expiresAt: c.expiresAt,
      retentionUntil: c.retentionUntil,
      identity, // biometrics are destroyed after the match — not present to export
      evidence,
    });
  }
  await audit.record({ actor: opts.actor, action: 'dsar.export', detail: { sub: opts.sub, caseCount: cases.length } });
  return { ok: true, sub: opts.sub, cases };
}
