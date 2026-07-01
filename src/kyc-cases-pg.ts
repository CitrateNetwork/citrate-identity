/**
 * VERI in-house KYC case store (VERI-S1-WP2/WP3/WP4).
 *
 * This is the DELIBERATE REVERSAL of the no-PII posture in `kyc-pg.ts`
 * (`ADR-2026-07-01-kyc-data-controller-reversal`): with Sumsub gone, Citrate is
 * the data controller, so we hold identity + evidence — but **only as ciphertext**.
 * Every PII field and evidence blob is sealed with a per-case DEK; the DEK is
 * stored wrapped by the master key (`kyc-crypto.ts`). A DB/blob exfil yields only
 * `{ wrapped_dek, ciphertext }`.
 *
 * Three data tiers (`ADR-2026-07-01-kyc-not-msb-retention-erasure`, planset D3):
 *   Tier 1  retained identity record   → `kyc_cases.identity_ct` + decision fields;
 *           kept a short policy window (`retention_until`), tombstonable.
 *   Tier 2  biometric/liveness evidence → `kyc_evidence` rows with `tier=2`,
 *           `destroy_after` set so the destruction job wipes them after the match.
 *   Tier 3  convenience evidence        → `kyc_evidence` rows with `tier=3`.
 *
 * SQL is parameterized; `ensureSchema` gates CREATE on an information_schema probe
 * so it is idempotent on real Postgres AND pg-mem (same reasons as `kyc-pg.ts`).
 * Instants are epoch-ms bigints. This store holds ciphertext + metadata only — it
 * never imports `kyc-crypto`; sealing/opening is the caller's (adapter's) job, so
 * the store cannot accidentally hold a key.
 */

import type { Pool, PoolClient, QueryResult } from 'pg';
import { randomUUID } from 'node:crypto';

/** Minimal `pg`-compatible surface (satisfied by `pg.Pool` and pg-mem). */
export interface PgLike {
  query(text: string, params?: unknown[]): Promise<QueryResult>;
  end?(): Promise<void>;
}

export type CaseStatus = 'created' | 'pending' | 'verified' | 'rejected';
export type CaseDecision = 'verified' | 'rejected' | 'needs-review';
export type EvidenceKind = 'document' | 'liveness' | 'selfie' | 'other';

export interface KycCase {
  caseId: string;
  externalUserId: string;
  status: CaseStatus;
  wrappedDek: string;
  /** Sealed Tier-1 identity fields (opaque ciphertext), or undefined until captured. */
  identityCt?: string;
  decision?: CaseDecision;
  decisionAt?: number;
  screeningResult?: string;
  verifiedAt?: number;
  expiresAt?: number;
  retentionUntil?: number;
  legalHold: boolean;
  tombstonedAt?: number;
  createdAt: number;
  updatedAt: number;
}

export interface EvidenceRow {
  evidenceId: string;
  caseId: string;
  kind: EvidenceKind;
  tier: number;
  /** Sealed blob (base64), or undefined once destroyed. */
  ciphertext?: string;
  destroyAfter?: number;
  destroyedAt?: number;
  createdAt: number;
}

const CREATE_CASES_SQL = `
CREATE TABLE IF NOT EXISTS kyc_cases (
  case_id          text   PRIMARY KEY,
  external_user_id text   NOT NULL,
  status           text   NOT NULL,
  wrapped_dek      text   NOT NULL,
  identity_ct      text,
  decision         text,
  decision_at      bigint,
  screening_result text,
  verified_at      bigint,
  expires_at       bigint,
  retention_until  bigint,
  legal_hold       boolean NOT NULL DEFAULT false,
  tombstoned_at    bigint,
  created_at       bigint NOT NULL,
  updated_at       bigint NOT NULL
)`;

const CREATE_EVIDENCE_SQL = `
CREATE TABLE IF NOT EXISTS kyc_evidence (
  evidence_id   text   PRIMARY KEY,
  case_id       text   NOT NULL,
  kind          text   NOT NULL,
  tier          integer NOT NULL,
  ciphertext    text,
  destroy_after bigint,
  destroyed_at  bigint,
  created_at    bigint NOT NULL
)`;

const CASES_EXISTS_SQL = `SELECT 1 FROM information_schema.tables WHERE table_name = 'kyc_cases' LIMIT 1`;
const EVIDENCE_EXISTS_SQL = `SELECT 1 FROM information_schema.tables WHERE table_name = 'kyc_evidence' LIMIT 1`;

function num(v: unknown): number | undefined {
  if (v === null || v === undefined) return undefined;
  const n = typeof v === 'string' ? Number(v) : (v as number);
  return Number.isFinite(n) ? n : undefined;
}
function str(v: unknown): string | undefined {
  return v === null || v === undefined ? undefined : String(v);
}

const CASE_COLS =
  'case_id, external_user_id, status, wrapped_dek, identity_ct, decision, decision_at, screening_result, verified_at, expires_at, retention_until, legal_hold, tombstoned_at, created_at, updated_at';

function rowToCase(r: Record<string, unknown>): KycCase {
  return {
    caseId: String(r.case_id),
    externalUserId: String(r.external_user_id),
    status: String(r.status) as CaseStatus,
    wrappedDek: String(r.wrapped_dek),
    identityCt: str(r.identity_ct),
    decision: str(r.decision) as CaseDecision | undefined,
    decisionAt: num(r.decision_at),
    screeningResult: str(r.screening_result),
    verifiedAt: num(r.verified_at),
    expiresAt: num(r.expires_at),
    retentionUntil: num(r.retention_until),
    legalHold: r.legal_hold === true || r.legal_hold === 'true' || r.legal_hold === 't',
    tombstonedAt: num(r.tombstoned_at),
    createdAt: num(r.created_at) ?? 0,
    updatedAt: num(r.updated_at) ?? 0,
  };
}

function rowToEvidence(r: Record<string, unknown>): EvidenceRow {
  return {
    evidenceId: String(r.evidence_id),
    caseId: String(r.case_id),
    kind: String(r.kind) as EvidenceKind,
    tier: num(r.tier) ?? 0,
    ciphertext: str(r.ciphertext),
    destroyAfter: num(r.destroy_after),
    destroyedAt: num(r.destroyed_at),
    createdAt: num(r.created_at) ?? 0,
  };
}

export class KycCaseStore {
  constructor(private readonly pool: PgLike) {}

  static async connect(databaseUrl: string): Promise<KycCaseStore> {
    const { Pool } = await import('pg');
    const pool: Pool = new Pool({ connectionString: databaseUrl });
    const store = new KycCaseStore(pool);
    await store.ensureSchema();
    return store;
  }

  async ensureSchema(): Promise<void> {
    if ((await this.pool.query(CASES_EXISTS_SQL)).rows.length === 0) {
      await this.pool.query(CREATE_CASES_SQL);
    }
    if ((await this.pool.query(EVIDENCE_EXISTS_SQL)).rows.length === 0) {
      await this.pool.query(CREATE_EVIDENCE_SQL);
    }
  }

  /** Create a new case. `wrappedDek` is the case DEK wrapped by the master key. */
  async createCase(externalUserId: string, wrappedDek: string): Promise<KycCase> {
    const now = Date.now();
    const caseId = `case_${randomUUID()}`;
    await this.pool.query(
      `INSERT INTO kyc_cases (case_id, external_user_id, status, wrapped_dek, legal_hold, created_at, updated_at)
       VALUES ($1, $2, 'created', $3, false, $4, $4)`,
      [caseId, externalUserId, wrappedDek, now],
    );
    const c = await this.getCase(caseId);
    if (!c) throw new Error('kyc-cases: createCase failed to read back the row');
    return c;
  }

  async getCase(caseId: string): Promise<KycCase | undefined> {
    const res = await this.pool.query(
      `SELECT ${CASE_COLS} FROM kyc_cases WHERE case_id = $1`,
      [caseId],
    );
    const row = res.rows[0] as Record<string, unknown> | undefined;
    return row ? rowToCase(row) : undefined;
  }

  /** The most recent (non-tombstoned) case for a user, if any. */
  async getLatestCaseForUser(externalUserId: string): Promise<KycCase | undefined> {
    const res = await this.pool.query(
      `SELECT ${CASE_COLS} FROM kyc_cases
       WHERE external_user_id = $1 AND tombstoned_at IS NULL
       ORDER BY created_at DESC LIMIT 1`,
      [externalUserId],
    );
    const row = res.rows[0] as Record<string, unknown> | undefined;
    return row ? rowToCase(row) : undefined;
  }

  async setStatus(caseId: string, status: CaseStatus): Promise<void> {
    await this.pool.query(
      `UPDATE kyc_cases SET status = $2, updated_at = $3 WHERE case_id = $1`,
      [caseId, status, Date.now()],
    );
  }

  /** Store the sealed Tier-1 identity fields for a case. */
  async setIdentityCiphertext(caseId: string, identityCt: string): Promise<void> {
    await this.pool.query(
      `UPDATE kyc_cases SET identity_ct = $2, updated_at = $3 WHERE case_id = $1`,
      [caseId, identityCt, Date.now()],
    );
  }

  /** Record the verification decision + derived lifecycle fields. */
  async setDecision(
    caseId: string,
    d: {
      decision: CaseDecision;
      screeningResult?: string;
      verifiedAt?: number;
      expiresAt?: number;
      retentionUntil?: number;
    },
  ): Promise<void> {
    const now = Date.now();
    const status: CaseStatus =
      d.decision === 'verified' ? 'verified' : d.decision === 'rejected' ? 'rejected' : 'pending';
    await this.pool.query(
      `UPDATE kyc_cases SET
         status = $2, decision = $3, decision_at = $4, screening_result = $5,
         verified_at = $6, expires_at = $7, retention_until = $8, updated_at = $4
       WHERE case_id = $1`,
      [
        caseId,
        status,
        d.decision,
        now,
        d.screeningResult ?? null,
        d.verifiedAt ?? null,
        d.expiresAt ?? null,
        d.retentionUntil ?? null,
      ],
    );
  }

  async setLegalHold(caseId: string, hold: boolean): Promise<void> {
    await this.pool.query(
      `UPDATE kyc_cases SET legal_hold = $2, updated_at = $3 WHERE case_id = $1`,
      [caseId, hold, Date.now()],
    );
  }

  /** Add an evidence row (sealed ciphertext). Tier-2 sets `destroyAfter`. */
  async addEvidence(input: {
    caseId: string;
    kind: EvidenceKind;
    tier: number;
    ciphertext: string;
    destroyAfter?: number;
  }): Promise<EvidenceRow> {
    const now = Date.now();
    const evidenceId = `ev_${randomUUID()}`;
    await this.pool.query(
      `INSERT INTO kyc_evidence (evidence_id, case_id, kind, tier, ciphertext, destroy_after, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [evidenceId, input.caseId, input.kind, input.tier, input.ciphertext, input.destroyAfter ?? null, now],
    );
    return {
      evidenceId,
      caseId: input.caseId,
      kind: input.kind,
      tier: input.tier,
      ciphertext: input.ciphertext,
      destroyAfter: input.destroyAfter,
      createdAt: now,
    };
  }

  async listEvidence(caseId: string): Promise<EvidenceRow[]> {
    const res = await this.pool.query(
      `SELECT evidence_id, case_id, kind, tier, ciphertext, destroy_after, destroyed_at, created_at
       FROM kyc_evidence WHERE case_id = $1 ORDER BY created_at ASC`,
      [caseId],
    );
    return (res.rows as Record<string, unknown>[]).map(rowToEvidence);
  }

  /**
   * DESTRUCTION JOB PRIMITIVE (VERI-S1-WP4, BIPA D3.2):
   * null out the ciphertext of every not-yet-destroyed Tier-2 (biometric) row whose
   * `destroy_after <= now`, stamping `destroyed_at`. Returns the count destroyed.
   * Idempotent: already-destroyed rows are skipped (ciphertext IS NULL guard).
   */
  async destroyDueBiometrics(now: number = Date.now()): Promise<number> {
    const res = await this.pool.query(
      `UPDATE kyc_evidence
         SET ciphertext = NULL, destroyed_at = $1
       WHERE tier = 2 AND ciphertext IS NOT NULL
         AND destroy_after IS NOT NULL AND destroy_after <= $1`,
      [now],
    );
    return res.rowCount ?? 0;
  }

  /**
   * IMMEDIATE biometric destruction for one case (VERI-S3, BIPA D3.2): wipe the
   * ciphertext of every not-yet-destroyed Tier-2 evidence row for the case, right
   * after the 1:1 match decision — regardless of `destroy_after`. Returns the count.
   */
  async destroyBiometricsForCase(caseId: string, now: number = Date.now()): Promise<number> {
    const res = await this.pool.query(
      `UPDATE kyc_evidence SET ciphertext = NULL, destroyed_at = $2
       WHERE case_id = $1 AND tier = 2 AND ciphertext IS NOT NULL`,
      [caseId, now],
    );
    return res.rowCount ?? 0;
  }

  /**
   * Delete a user's case (planset D3). No AML retention duty (not an MSB), so:
   *   - legal_hold set → **tombstone** (lock the record, wipe evidence ciphertext,
   *     keep the row for the hold);
   *   - otherwise → **hard delete** the case + its evidence.
   * Returns the mode taken.
   */
  async deleteCase(caseId: string): Promise<'tombstoned' | 'deleted' | 'absent'> {
    const c = await this.getCase(caseId);
    if (!c) return 'absent';
    if (c.legalHold) {
      const now = Date.now();
      await this.pool.query(
        `UPDATE kyc_evidence SET ciphertext = NULL, destroyed_at = $2 WHERE case_id = $1 AND ciphertext IS NOT NULL`,
        [caseId, now],
      );
      await this.pool.query(
        `UPDATE kyc_cases SET tombstoned_at = $2, identity_ct = NULL, status = 'rejected', updated_at = $2 WHERE case_id = $1`,
        [caseId, now],
      );
      return 'tombstoned';
    }
    await this.pool.query(`DELETE FROM kyc_evidence WHERE case_id = $1`, [caseId]);
    await this.pool.query(`DELETE FROM kyc_cases WHERE case_id = $1`, [caseId]);
    return 'deleted';
  }

  /**
   * TIER-1 RETENTION ENFORCEMENT (VERI-S1-WP4, planset D3): hard-delete every case
   * whose `retention_until <= now`, is NOT on legal hold, and is NOT already
   * tombstoned — plus its evidence. Not an MSB → no AML duty to keep them. Returns
   * the count purged.
   */
  async purgeExpiredCases(now: number = Date.now()): Promise<number> {
    const due = await this.pool.query(
      `SELECT case_id FROM kyc_cases
       WHERE retention_until IS NOT NULL AND retention_until <= $1
         AND legal_hold = false AND tombstoned_at IS NULL`,
      [now],
    );
    const ids = (due.rows as Record<string, unknown>[]).map((r) => String(r.case_id));
    for (const id of ids) {
      await this.pool.query(`DELETE FROM kyc_evidence WHERE case_id = $1`, [id]);
      await this.pool.query(`DELETE FROM kyc_cases WHERE case_id = $1`, [id]);
    }
    return ids.length;
  }

  async ping(): Promise<boolean> {
    try {
      await this.pool.query('SELECT 1');
      return true;
    } catch {
      return false;
    }
  }

  async close(): Promise<void> {
    await this.pool.end?.();
  }
}

export type { Pool, PoolClient };
