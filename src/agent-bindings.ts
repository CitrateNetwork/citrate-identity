/**
 * Agent bindings — the Know-Your-Agent (KYA) store (ADR-XA-1 / handoff W1).
 *
 * Identity here is **per-agent**, not per-human. Before this store an agent could
 * only borrow a human's `sub`, so every action it took was indistinguishable from
 * its owner's and revoking the agent meant revoking the human. A binding gives an
 * agent its own subject, records who owns it, and makes revocation independent.
 *
 * ADR-XA-1 §2 splits two things §4 W1 of the handoff conflated, because
 * `ADR-2026-06-04-agent-signing-and-key-custody` (ACCEPTED) requires it:
 *
 *   - IDENTITY is unconditional and KEYLESS. A registered agent has a subject, a
 *     counterfactual wallet address, and a binding. It can spend NOTHING.
 *   - AUTHORITY is a separate, explicit, per-agent opt-in — default OFF, bounded
 *     on-chain by AgentSessionKeyValidator, revocable, and only after the owner
 *     accepts the liability waiver that ADR names.
 *
 * So `delegation_enabled` defaults to false and `spend_cap` is NULL until an owner
 * deliberately grants authority. A row in this table is not a licence to spend.
 *
 * The owner's verification status is NEVER copied here — it is read live at
 * claims() time (ADR-XA-1 D5) so a lapse or a revoke reflects on the next
 * /userinfo call rather than persisting a stale "verified".
 */

/*
 * ─────────────────────────────────────────────────────────────────────────────
 * SECURITY DISPOSITION — column encryption for `agent_bindings`
 * ADR-XA-1 D3. Follows the disposition already written for `entitlements`
 * (src/entitlements.ts) and the sealing bar met by `kyc_cases` (src/kyc-pg.ts).
 * ─────────────────────────────────────────────────────────────────────────────
 * NOT SEALED — every one of these is a query predicate, an authorization fact, or
 * a public chain value:
 *   agent_sub, parent_sub   opaque OIDC subjects. NOT PII: they identify a
 *                           principal to this authority and to nobody else.
 *                           Sealing them defeats the equality indexes that
 *                           enforcement and revocation depend on, for zero
 *                           confidentiality gain — the same trade documented at
 *                           length for `entitlements.sub`.
 *   scope, status, expiry   authorization facts, branched on by resolution.
 *   delegation_enabled,
 *   spend_cap,
 *   session_key_addr,
 *   recipients_root         the delegation bound. `session_key_addr` and
 *                           `recipients_root` are PUBLIC chain values — the
 *                           on-chain validator enforces against exactly these,
 *                           so they are readable on 40204 regardless.
 *   kya_decision_id         an index into a public append-only registry.
 *
 * SEALED — `label_ct` + `wrapped_dek`:
 *   The agent label is owner-authored free text ("Larry's trading bot") and can
 *   carry identifying content. It is display-only and never a predicate, so
 *   sealing costs nothing. AES-256-GCM under a per-row DEK wrapped by the KYC
 *   master key — the same envelope `kyc_cases` uses.
 *
 * NEVER STORED: KYC PII of any kind, and no credential plaintext — only the
 * SHA-256 of the `ag_` secret (see `credential_sha256`), so a database dump
 * cannot be replayed as a credential.
 * ─────────────────────────────────────────────────────────────────────────────
 */

import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

import type { PgLike } from './entitlements.js';
import {
  masterKeyFromEnv,
  newDek,
  wrapDek,
  unwrapDek,
  sealField,
  openField,
} from './kyc-crypto.js';

// --- types ------------------------------------------------------------------

/** Lifecycle of a binding. `expired` is DERIVED, never stored — see {@link effectiveAgentStatus}. */
export type AgentStatus = 'active' | 'revoked' | 'expired';

/**
 * The delegation bound. `enabled: false` (the default) means the agent has
 * identity but NO spending authority — ADR-2026-06-04's required posture.
 */
export interface AgentDelegation {
  enabled: boolean;
  /** Cumulative cap in wei, as a decimal string (pg `numeric` round-trips as text). */
  spendCapWei: string | null;
  /** The delegated session key (public address) the on-chain validator checks. */
  sessionKeyAddr: string | null;
  /** Merkle root of the recipient allow-list, enforced on-chain. */
  recipientsRoot: string | null;
  /** When the owner accepted the ADR-2026-06-04 liability waiver. */
  waiverAcceptedAt: number | null;
}

export interface AgentBinding {
  agentSub: string;
  parentSub: string;
  /** Opened plaintext, or null when unset / unopenable. */
  label: string | null;
  scope: string;
  /** As STORED. Callers wanting expiry applied use {@link effectiveAgentStatus}. */
  status: AgentStatus;
  /** epoch-ms; null = no expiry. */
  expiry: number | null;
  delegation: AgentDelegation;
  createdAt: number;
  revokedAt: number | null;
  /** AgentDecisionRegistry decision id for the binding attestation, or null. */
  kyaDecisionId: string | null;
}

/** What registration needs. `parentSub` MUST come from the authenticated principal. */
export interface CreateAgentInput {
  agentSub: string;
  parentSub: string;
  label?: string | null;
  scope?: string;
  /** epoch-ms; omit for no expiry. */
  expiry?: number | null;
  /** SHA-256 hex of the `ag_` secret. Plaintext is never persisted. */
  credentialSha256: string;
}

/** The delegation grant an owner makes. Rejected without `waiverAccepted`. */
export interface GrantDelegationInput {
  spendCapWei: string;
  sessionKeyAddr: string;
  recipientsRoot: string;
  waiverAccepted: boolean;
}

// --- credential contract (`ag_`) --------------------------------------------

const AGENT_KEY_PREFIX = 'ag_';

/**
 * Mint a fresh agent credential. Returns the PLAINTEXT — the caller returns it to
 * the owner exactly once and persists only {@link hashAgentCredential} of it.
 *
 * Mirrors the proven `bk_` contract in src/aa/bundler-keys.ts (prefix + 32 bytes
 * of entropy + SHA-256 at rest). Unlike `bk_` this hash lives in Postgres beside
 * the binding rather than in a Redis set, so revoking the agent and invalidating
 * its credential are the SAME row write and cannot diverge.
 */
export function mintAgentCredential(): string {
  return AGENT_KEY_PREFIX + randomBytes(32).toString('base64url');
}

/** SHA-256 hex of a credential string. */
export function hashAgentCredential(key: string): string {
  return createHash('sha256').update(key, 'utf8').digest('hex');
}

/** Shape check, mirroring `looksLikeBundlerApiKey`. */
export function looksLikeAgentCredential(key: string): boolean {
  return /^ag_[A-Za-z0-9_-]{32,}$/.test(key);
}

/** Constant-time hex compare — never leak a credential through timing. */
function hashesEqual(a: string, b: string): boolean {
  const ba = Buffer.from(a, 'utf8');
  const bb = Buffer.from(b, 'utf8');
  if (ba.length !== bb.length) return false;
  return timingSafeEqual(ba, bb);
}

// --- pure helpers -----------------------------------------------------------

/**
 * The status that ACTUALLY applies, with expiry evaluated against `now`.
 *
 * Expiry is derived rather than stored because a stored `expired` would need a
 * sweeper to stay honest, and a missed sweep would leave an expired agent
 * reading `active`. Mirrors `effectiveVerified` in src/kyc.ts.
 */
export function effectiveAgentStatus(
  binding: Pick<AgentBinding, 'status' | 'expiry'>,
  now: number = Date.now(),
): AgentStatus {
  if (binding.status === 'revoked') return 'revoked';
  if (binding.expiry != null && now > binding.expiry) return 'expired';
  return binding.status;
}

/**
 * Whether a binding may act at all. The single gate every agent-facing route and
 * the claims path funnel through, so "fails closed" has ONE definition.
 */
export function agentCanAct(
  binding: Pick<AgentBinding, 'status' | 'expiry'>,
  now: number = Date.now(),
): boolean {
  return effectiveAgentStatus(binding, now) === 'active';
}

/**
 * Whether delegated SPENDING is live. Deliberately stricter than
 * {@link agentCanAct}: identity outliving authority is the intended asymmetry
 * (ADR-XA-1 D1), so revoking spend must never be mistaken for revoking identity
 * or the reverse.
 */
export function agentCanSpend(binding: AgentBinding, now: number = Date.now()): boolean {
  return (
    agentCanAct(binding, now) &&
    binding.delegation.enabled &&
    binding.delegation.spendCapWei != null &&
    binding.delegation.waiverAcceptedAt != null
  );
}

/**
 * Narrow a requested scope to what the owner actually holds.
 *
 * Returns the disallowed entries rather than silently trimming (ADR-XA-1 D9):
 * silent trimming teaches callers that over-asking is free, and it hides a
 * privilege-escalation attempt that ought to surface as a 403.
 */
export function scopeViolations(requested: string, ownerScope: string): string[] {
  const owned = new Set(ownerScope.split(/\s+/).filter(Boolean));
  return requested
    .split(/\s+/)
    .filter(Boolean)
    .filter((s) => !owned.has(s));
}

// --- schema -----------------------------------------------------------------

const CREATE_TABLE_SQL = `
CREATE TABLE IF NOT EXISTS agent_bindings (
  id                  bigserial PRIMARY KEY,
  agent_sub           text        NOT NULL,
  parent_sub          text        NOT NULL,
  credential_sha256   text        NOT NULL,
  label_ct            text,
  wrapped_dek         text,
  scope               text        NOT NULL DEFAULT '',
  status              text        NOT NULL DEFAULT 'active',
  expiry              timestamptz,
  delegation_enabled  boolean     NOT NULL DEFAULT false,
  spend_cap           numeric(78,0),
  session_key_addr    text,
  recipients_root     text,
  waiver_accepted_at  timestamptz,
  kya_decision_id     numeric(78,0),
  created_at          timestamptz NOT NULL DEFAULT now(),
  revoked_at          timestamptz
)`;

const CREATE_IDX_SQL = [
  `CREATE UNIQUE INDEX IF NOT EXISTS agent_bindings_agent_sub_idx ON agent_bindings (agent_sub)`,
  `CREATE INDEX IF NOT EXISTS agent_bindings_parent_sub_idx ON agent_bindings (parent_sub)`,
];

const TABLE_EXISTS_SQL = `SELECT 1 AS present FROM information_schema.tables WHERE table_name = 'agent_bindings' LIMIT 1`;

const COLS = `agent_sub, parent_sub, credential_sha256, label_ct, wrapped_dek, scope,
  status, expiry, delegation_enabled, spend_cap, session_key_addr, recipients_root,
  waiver_accepted_at, kya_decision_id, created_at, revoked_at`;

const SELECT_BY_SUB_SQL = `SELECT ${COLS} FROM agent_bindings WHERE agent_sub = $1 LIMIT 1`;
const SELECT_BY_PARENT_SQL = `SELECT ${COLS} FROM agent_bindings WHERE parent_sub = $1 ORDER BY created_at DESC`;
const INSERT_SQL = `INSERT INTO agent_bindings
  (agent_sub, parent_sub, credential_sha256, label_ct, wrapped_dek, scope, expiry)
  VALUES ($1, $2, $3, $4, $5, $6, $7)`;

// --- store ------------------------------------------------------------------

function toMs(v: unknown): number | null {
  if (v == null) return null;
  const t = new Date(v as string).getTime();
  return Number.isNaN(t) ? null : t;
}

export class AgentBindingStore {
  constructor(private readonly pool: PgLike) {}

  static async connect(databaseUrl: string): Promise<AgentBindingStore> {
    const { Pool } = await import('pg');
    const pool = new Pool({ connectionString: databaseUrl }) as unknown as PgLike;
    const store = new AgentBindingStore(pool);
    await store.ensureSchema();
    return store;
  }

  /** Idempotent — safe on every boot, same posture as the KYC/entitlement stores. */
  async ensureSchema(): Promise<void> {
    const exists = await this.pool.query(TABLE_EXISTS_SQL);
    if (exists.rows.length === 0) {
      await this.pool.query(CREATE_TABLE_SQL);
    }
    for (const sql of CREATE_IDX_SQL) {
      await this.pool.query(sql);
    }
  }

  /**
   * Open the sealed label. Returns null when absent, or when the envelope cannot
   * be opened (no master key configured, or a key rotation left this row behind).
   *
   * Fail-SOFT is right here and only here: the label is cosmetic, so an
   * unopenable one must not take down the authorization decision that shares the
   * row. Every field that authorization actually reads is unsealed by design.
   */
  private openLabel(labelCt: unknown, wrappedDek: unknown): string | null {
    if (typeof labelCt !== 'string' || typeof wrappedDek !== 'string') return null;
    try {
      const master = masterKeyFromEnv();
      return openField(labelCt, unwrapDek(wrappedDek, master));
    } catch {
      return null;
    }
  }

  private hydrate(row: Record<string, unknown>): AgentBinding {
    return {
      agentSub: String(row.agent_sub),
      parentSub: String(row.parent_sub),
      label: this.openLabel(row.label_ct, row.wrapped_dek),
      scope: String(row.scope ?? ''),
      status: String(row.status) as AgentStatus,
      expiry: toMs(row.expiry),
      delegation: {
        enabled: Boolean(row.delegation_enabled),
        spendCapWei: row.spend_cap == null ? null : String(row.spend_cap),
        sessionKeyAddr: row.session_key_addr == null ? null : String(row.session_key_addr),
        recipientsRoot: row.recipients_root == null ? null : String(row.recipients_root),
        waiverAcceptedAt: toMs(row.waiver_accepted_at),
      },
      createdAt: toMs(row.created_at) ?? 0,
      revokedAt: toMs(row.revoked_at),
      kyaDecisionId: row.kya_decision_id == null ? null : String(row.kya_decision_id),
    };
  }

  /**
   * Insert a binding. Seals the label when one is given.
   *
   * THROWS when a label is supplied but no master key is configured, rather than
   * dropping it: silently discarding data the caller handed us is worse than a
   * clear failure, and in production the master key is always present (KYC is live).
   */
  async create(input: CreateAgentInput): Promise<void> {
    let labelCt: string | null = null;
    let wrapped: string | null = null;
    if (input.label != null && input.label !== '') {
      const master = masterKeyFromEnv(); // throws if unconfigured — intentional
      const dek = newDek();
      labelCt = sealField(input.label, dek);
      wrapped = wrapDek(dek, master);
    }
    await this.pool.query(INSERT_SQL, [
      input.agentSub,
      input.parentSub,
      input.credentialSha256,
      labelCt,
      wrapped,
      input.scope ?? '',
      input.expiry == null ? null : new Date(input.expiry).toISOString(),
    ]);
  }

  async get(agentSub: string): Promise<AgentBinding | null> {
    const res = await this.pool.query(SELECT_BY_SUB_SQL, [agentSub]);
    const row = res.rows[0];
    return row ? this.hydrate(row) : null;
  }

  async listByParent(parentSub: string): Promise<AgentBinding[]> {
    const res = await this.pool.query(SELECT_BY_PARENT_SQL, [parentSub]);
    return res.rows.map((r) => this.hydrate(r));
  }

  /**
   * Verify a presented `ag_` credential against the stored hash.
   *
   * Fails closed on a revoked/expired binding BEFORE comparing, so a leaked
   * credential for a revoked agent is inert (acceptance A4 / adversarial X6).
   */
  async verifyCredential(agentSub: string, presented: string): Promise<AgentBinding | null> {
    if (!looksLikeAgentCredential(presented)) return null;
    const res = await this.pool.query(
      `SELECT ${COLS}, credential_sha256 AS ch FROM agent_bindings WHERE agent_sub = $1 LIMIT 1`,
      [agentSub],
    );
    const row = res.rows[0];
    if (!row) return null;
    const binding = this.hydrate(row);
    if (!agentCanAct(binding)) return null;
    if (!hashesEqual(String(row.ch), hashAgentCredential(presented))) return null;
    return binding;
  }

  /** Revoke the agent entirely. Identity AND authority end. Idempotent. */
  async revoke(agentSub: string): Promise<boolean> {
    const res = await this.pool.query(
      `UPDATE agent_bindings
         SET status = 'revoked', revoked_at = now(),
             delegation_enabled = false
       WHERE agent_sub = $1 AND status <> 'revoked'
       RETURNING agent_sub`,
      [agentSub],
    );
    return res.rows.length > 0;
  }

  /**
   * Grant (or replace) bounded spending authority.
   *
   * REFUSES without `waiverAccepted` — ADR-2026-06-04 permits delegation only
   * behind an explicit liability waiver, so the waiver is a precondition in the
   * store itself and not merely in a route that could be bypassed.
   */
  async grantDelegation(agentSub: string, g: GrantDelegationInput): Promise<boolean> {
    if (!g.waiverAccepted) return false;
    const res = await this.pool.query(
      `UPDATE agent_bindings
         SET delegation_enabled = true,
             spend_cap = $2, session_key_addr = $3, recipients_root = $4,
             waiver_accepted_at = now()
       WHERE agent_sub = $1 AND status = 'active'
       RETURNING agent_sub`,
      [agentSub, g.spendCapWei, g.sessionKeyAddr, g.recipientsRoot],
    );
    return res.rows.length > 0;
  }

  /** Revoke spending authority; identity survives (the D1 asymmetry). */
  async revokeDelegation(agentSub: string): Promise<boolean> {
    const res = await this.pool.query(
      `UPDATE agent_bindings
         SET delegation_enabled = false, spend_cap = NULL,
             session_key_addr = NULL, recipients_root = NULL
       WHERE agent_sub = $1 AND delegation_enabled = true
       RETURNING agent_sub`,
      [agentSub],
    );
    return res.rows.length > 0;
  }

  /** Record the AgentDecisionRegistry id once the KYA attestation lands. */
  async setKyaDecisionId(agentSub: string, decisionId: string): Promise<void> {
    await this.pool.query(
      `UPDATE agent_bindings SET kya_decision_id = $2 WHERE agent_sub = $1`,
      [agentSub, decisionId],
    );
  }
}

// --- lazy singleton over DATABASE_URL (mirrors the KYC/entitlement stores) ---

let storePromise: Promise<AgentBindingStore | null> | null = null;

/**
 * The live store, or null when `DATABASE_URL` is unset (dev).
 *
 * Note the asymmetry with `entitlements.getStore()`: there, an unavailable store
 * degrades to "mint no claim", which is safe because absence resolves to Public.
 * Here a null store must make every agent route fail closed (503) and the claims
 * path mint NOTHING — never widen an agent to its owner's tier because a lookup
 * failed. See ADR-XA-1 D5.4.
 */
export function getAgentStore(): Promise<AgentBindingStore | null> {
  if (storePromise) return storePromise;
  const url = process.env.DATABASE_URL;
  storePromise = url
    ? AgentBindingStore.connect(url).catch((err) => {
        console.error('[agent-bindings] store unavailable — agent routes fail closed:', err);
        return null;
      })
    : Promise.resolve(null);
  return storePromise;
}

/** Test seam: inject a store (pg-mem) and bypass the DATABASE_URL singleton. */
export function _setAgentStoreForTests(store: AgentBindingStore | null): void {
  storePromise = Promise.resolve(store);
}
