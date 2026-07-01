/**
 * VERI immutable, tamper-evident KYC audit log (VERI-S4-WP5).
 *
 * Every admin action and every access to KYC PII writes one append-only row here.
 * Rows are **hash-chained** (`hash = SHA256(prev_hash || canonical(entry))`), so
 * altering or deleting any historical row breaks the chain from that point on —
 * `verifyChain()` detects it. This is the Rule-3 "audits are immutable" guarantee
 * and the accountability half of the NIST 800-171 mapping (S0 threat model).
 *
 * The log stores only NON-PII metadata: actor (admin sub), action, case id, and a
 * JSON detail blob the caller MUST keep PII-free (e.g. a reason string, a decision,
 * counts). It never holds identity fields or biometrics.
 *
 * pg-mem-safe schema (information_schema probe, like the other stores). Append is a
 * read-tail-then-insert; for the single-instance authority that is correct — a
 * multi-instance deployment would serialize appends (a note, not a v1 concern).
 */

import { createHash } from 'node:crypto';
import type { Pool, QueryResult } from 'pg';

export interface PgLike {
  query(text: string, params?: unknown[]): Promise<QueryResult>;
  end?(): Promise<void>;
}

export interface AuditEntry {
  /** Admin OIDC sub, or 'system' for engine/job actions. */
  actor: string;
  /** Dotted action, e.g. 'case.view' | 'case.adjudicate' | 'unlock.decrypt' | 'user.delete' | 'dsar.export'. */
  action: string;
  caseId?: string;
  /** PII-FREE structured metadata (reason, decision, counts…). */
  detail?: Record<string, unknown>;
}

export interface AuditRow extends AuditEntry {
  auditId: string;
  prevHash: string;
  hash: string;
  at: number;
}

const GENESIS = 'veri-audit-genesis';

const CREATE_SQL = `
CREATE TABLE IF NOT EXISTS kyc_audit (
  audit_id  text   PRIMARY KEY,
  case_id   text,
  actor     text   NOT NULL,
  action    text   NOT NULL,
  detail    text,
  prev_hash text   NOT NULL,
  hash      text   NOT NULL,
  at        bigint NOT NULL
)`;
const EXISTS_SQL = `SELECT 1 FROM information_schema.tables WHERE table_name = 'kyc_audit' LIMIT 1`;

/** Canonical string hashed into the chain. Order + fields are fixed. */
function digest(prevHash: string, e: { actor: string; action: string; caseId?: string; detail?: unknown; at: number }): string {
  const canonical = JSON.stringify({
    prevHash,
    actor: e.actor,
    action: e.action,
    caseId: e.caseId ?? null,
    detail: e.detail ?? null,
    at: e.at,
  });
  return createHash('sha256').update(canonical).digest('hex');
}

let counter = 0;
function auditId(at: number): string {
  counter = (counter + 1) % 1e6;
  return `aud_${at.toString(36)}_${counter.toString(36)}`;
}

export class KycAuditLog {
  constructor(private readonly pool: PgLike) {}

  static async connect(databaseUrl: string): Promise<KycAuditLog> {
    const { Pool } = await import('pg');
    const pool: Pool = new Pool({ connectionString: databaseUrl });
    const log = new KycAuditLog(pool);
    await log.ensureSchema();
    return log;
  }

  async ensureSchema(): Promise<void> {
    if ((await this.pool.query(EXISTS_SQL)).rows.length === 0) {
      await this.pool.query(CREATE_SQL);
    }
  }

  /** The most recent row's hash, or GENESIS when the log is empty. */
  private async tailHash(): Promise<string> {
    const res = await this.pool.query('SELECT hash FROM kyc_audit ORDER BY at DESC, audit_id DESC LIMIT 1');
    const row = res.rows[0] as { hash?: unknown } | undefined;
    return row?.hash ? String(row.hash) : GENESIS;
  }

  /** Append one entry to the chain. Returns the written row. */
  async record(entry: AuditEntry, at: number = Date.now()): Promise<AuditRow> {
    const prevHash = await this.tailHash();
    const hash = digest(prevHash, { ...entry, at });
    const id = auditId(at);
    await this.pool.query(
      `INSERT INTO kyc_audit (audit_id, case_id, actor, action, detail, prev_hash, hash, at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [id, entry.caseId ?? null, entry.actor, entry.action, entry.detail ? JSON.stringify(entry.detail) : null, prevHash, hash, at],
    );
    return { auditId: id, prevHash, hash, at, ...entry };
  }

  /** List entries (newest first), optionally filtered by case. */
  async list(opts: { caseId?: string; limit?: number } = {}): Promise<AuditRow[]> {
    const limit = Math.min(Math.max(1, opts.limit ?? 100), 1000);
    const res = opts.caseId
      ? await this.pool.query(`SELECT * FROM kyc_audit WHERE case_id = $1 ORDER BY at DESC, audit_id DESC LIMIT ${limit}`, [opts.caseId])
      : await this.pool.query(`SELECT * FROM kyc_audit ORDER BY at DESC, audit_id DESC LIMIT ${limit}`);
    return (res.rows as Record<string, unknown>[]).map((r) => ({
      auditId: String(r.audit_id),
      caseId: r.case_id ? String(r.case_id) : undefined,
      actor: String(r.actor),
      action: String(r.action),
      detail: r.detail ? (JSON.parse(String(r.detail)) as Record<string, unknown>) : undefined,
      prevHash: String(r.prev_hash),
      hash: String(r.hash),
      at: Number(r.at),
    }));
  }

  /**
   * Recompute the chain from the oldest row forward and confirm every stored hash
   * matches. Returns { ok } and, on failure, the audit_id where the chain breaks.
   */
  async verifyChain(): Promise<{ ok: boolean; brokenAt?: string; count: number }> {
    const res = await this.pool.query('SELECT * FROM kyc_audit ORDER BY at ASC, audit_id ASC');
    const rows = res.rows as Record<string, unknown>[];
    let prev = GENESIS;
    for (const r of rows) {
      const at = Number(r.at);
      const expect = digest(prev, {
        actor: String(r.actor),
        action: String(r.action),
        caseId: r.case_id ? String(r.case_id) : undefined,
        detail: r.detail ? JSON.parse(String(r.detail)) : null,
        at,
      });
      if (String(r.prev_hash) !== prev || String(r.hash) !== expect) {
        return { ok: false, brokenAt: String(r.audit_id), count: rows.length };
      }
      prev = String(r.hash);
    }
    return { ok: true, count: rows.length };
  }

  async close(): Promise<void> {
    await this.pool.end?.();
  }
}

/** Process-wide audit-log singleton (mirrors the store/provider singletons). */
let liveAuditLog: KycAuditLog | undefined;
export function getKycAuditLog(): KycAuditLog | undefined {
  return liveAuditLog;
}
export function setKycAuditLog(log: KycAuditLog | undefined): void {
  liveAuditLog = log;
}
