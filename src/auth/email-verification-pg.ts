/**
 * Email-verification code store (FWA #87.1).
 *
 * Proves ownership of a typed email before it can bind to an account, provision
 * a wallet, or match a deferred grant / gift code. A 6-digit code is emailed
 * (see ../email-send.ts) and must be entered back; only then does the account
 * flow proceed. Mirrors the users-pg / wallet-registry-pg pattern: a small
 * `PgLike` seam, idempotent `ensureSchema`, an in-memory dev fallback, and a
 * process-wide singleton swapped at boot by {@link initEmailVerificationStoreFromEnv}.
 *
 * Security properties:
 *   - single-use: a code is deleted the instant it verifies;
 *   - short TTL (CODE_TTL_MS): expired codes never verify;
 *   - attempt-capped (MAX_ATTEMPTS): brute force invalidates the code;
 *   - resend rate-limited (MAX_SENDS_PER_WINDOW): can't be used to spam an inbox;
 *   - enumeration-safe: `issue` never reveals whether an account exists — the
 *     ROUTE returns the same "code sent" shape regardless (the store just holds
 *     the pending code + the signup passwordHash, if any).
 *   - constant-time compare on the code hash.
 */

import { createHash, randomInt, timingSafeEqual } from 'node:crypto';

export const CODE_TTL_MS = 10 * 60 * 1000; // 10 minutes
export const MAX_ATTEMPTS = 5; // verify tries per issued code
export const MAX_SENDS_PER_WINDOW = 5; // resends per email per window
export const SEND_WINDOW_MS = 15 * 60 * 1000; // rolling resend window

/** Postgres SQLSTATE for a unique-constraint violation. */
const UNIQUE_VIOLATION = '23505';

/** The minimal `pg`-compatible surface this store needs. */
export interface PgLike {
  query(text: string, params?: unknown[]): Promise<{ rows: unknown[] }>;
}

export interface IssueResult {
  /** The plaintext code to email. Absent when rate-limited. */
  code?: string;
  /** True when the per-email resend window is exhausted (no code issued). */
  rateLimited: boolean;
}

export interface ConsumeResult {
  ok: boolean;
  /** The signup passwordHash stashed at issue time (if this was a register). */
  passwordHash?: string;
}

export interface EmailVerificationStore {
  /**
   * Issue (or re-issue) a code for `email`, stashing an optional signup
   * `passwordHash`. Rate-limited per email. Returns the plaintext code for the
   * caller to email, or `{rateLimited:true}` when the window is exhausted.
   *
   * PBA-L3a-003: `binding` ties the code AND the stashed password to the
   * requester (the route passes a hash of the OIDC interaction uid). A code
   * then verifies only inside the interaction that asked for it, so a code an
   * attacker triggered for the victim's address cannot install the attacker's
   * password when the victim types it.
   */
  issue(email: string, passwordHash?: string, binding?: string): Promise<IssueResult>;
  /**
   * Verify `code` for `email`. On success the code is consumed (single-use) and
   * any stashed passwordHash is returned. On failure the attempt is counted and
   * the code invalidated once MAX_ATTEMPTS is reached.
   */
  consume(email: string, code: string, binding?: string): Promise<ConsumeResult>;
}

function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

function genCode(): string {
  // 6-digit, zero-padded, uniform over [0, 999999] via rejection-free randomInt.
  return String(randomInt(0, 1_000_000)).padStart(6, '0');
}

/** Bind the hash to the email so a code is not portable across addresses. */
function hashCode(email: string, code: string): string {
  return createHash('sha256').update(`${normalizeEmail(email)}:${code}`).digest('hex');
}

/**
 * PBA-L3a-003 binding rule. A bound code needs the same binding; an unbound
 * (pre-deploy, ≤ CODE_TTL_MS old) code accepts any caller.
 */
function bindingMatches(stored: string | null | undefined, presented: string | undefined): boolean {
  if (stored === null || stored === undefined) return true;
  return presented !== undefined && presented === stored;
}

function hashesEqual(a: string, b: string): boolean {
  const ba = Buffer.from(a, 'hex');
  const bb = Buffer.from(b, 'hex');
  if (ba.length !== bb.length) return false;
  return timingSafeEqual(ba, bb);
}

// ─────────────────────────────────────────────────────────────────────
//  In-memory (dev/test)
// ─────────────────────────────────────────────────────────────────────

interface Row {
  codeHash: string;
  passwordHash?: string;
  binding?: string;
  expiresAt: number;
  attempts: number;
  sendCount: number;
  windowStartedAt: number;
}

export class InMemoryEmailVerificationStore implements EmailVerificationStore {
  private readonly byEmail = new Map<string, Row>();

  async issue(email: string, passwordHash?: string, binding?: string): Promise<IssueResult> {
    const key = normalizeEmail(email);
    const now = Date.now();
    const existing = this.byEmail.get(key);
    let sendCount = 1;
    let windowStartedAt = now;
    if (existing && now - existing.windowStartedAt < SEND_WINDOW_MS) {
      if (existing.sendCount >= MAX_SENDS_PER_WINDOW) {
        return { rateLimited: true };
      }
      sendCount = existing.sendCount + 1;
      windowStartedAt = existing.windowStartedAt;
    }
    const code = genCode();
    this.byEmail.set(key, {
      codeHash: hashCode(key, code),
      ...(passwordHash !== undefined ? { passwordHash } : {}),
      ...(binding !== undefined ? { binding } : {}),
      expiresAt: now + CODE_TTL_MS,
      attempts: 0,
      sendCount,
      windowStartedAt,
    });
    return { code, rateLimited: false };
  }

  async consume(email: string, code: string, binding?: string): Promise<ConsumeResult> {
    const key = normalizeEmail(email);
    const row = this.byEmail.get(key);
    if (!row) return { ok: false };
    if (Date.now() > row.expiresAt || row.attempts >= MAX_ATTEMPTS) {
      this.byEmail.delete(key);
      return { ok: false };
    }
    if (!hashesEqual(row.codeHash, hashCode(key, code)) || !bindingMatches(row.binding, binding)) {
      row.attempts += 1;
      if (row.attempts >= MAX_ATTEMPTS) this.byEmail.delete(key);
      return { ok: false };
    }
    this.byEmail.delete(key); // single-use
    return { ok: true, ...(row.passwordHash !== undefined ? { passwordHash: row.passwordHash } : {}) };
  }
}

// ─────────────────────────────────────────────────────────────────────
//  Postgres
// ─────────────────────────────────────────────────────────────────────

const CREATE_TABLE_SQL = `
CREATE TABLE IF NOT EXISTS email_verification_codes (
  email             text PRIMARY KEY,
  code_hash         text NOT NULL,
  password_hash     text,
  binding           text,
  expires_at        timestamptz NOT NULL,
  attempts          integer NOT NULL DEFAULT 0,
  send_count        integer NOT NULL DEFAULT 1,
  window_started_at timestamptz NOT NULL DEFAULT now(),
  created_at        timestamptz NOT NULL DEFAULT now()
)`;

export class PgEmailVerificationStore implements EmailVerificationStore {
  constructor(private readonly pg: PgLike) {}

  async ensureSchema(): Promise<void> {
    // Probe first (the kyc-cases-pg pattern): pg-mem cannot re-plan a
    // CREATE TABLE IF NOT EXISTS against an existing table.
    const exists = await this.pg.query(
      `SELECT 1 FROM information_schema.tables
        WHERE table_schema = current_schema() AND table_name = 'email_verification_codes'`,
    );
    if (exists.rows.length === 0) await this.pg.query(CREATE_TABLE_SQL);
    // PBA-L3a-003: tables created before the requester binding existed. Probed
    // via information_schema (pg-mem cannot plan ADD COLUMN IF NOT EXISTS).
    const { rows } = await this.pg.query(
      `SELECT 1 FROM information_schema.columns
        WHERE table_schema = current_schema() AND table_name = 'email_verification_codes' AND column_name = 'binding'`,
    );
    if (rows.length === 0) {
      await this.pg.query('ALTER TABLE email_verification_codes ADD COLUMN binding text');
    }
  }

  /**
   * PBA-L3a-002 variant: the resend window used to be a read-then-write too, so
   * 30 concurrent requests issued 30 codes against a budget of 5. Now each step
   * is a single conditional statement:
   *   1. UPDATE the existing row only while its window has room (or has expired,
   *      which restarts the window) — a row-locked read-modify-write in Postgres;
   *   2. else INSERT the first row;
   *   3. if that INSERT lost a race to a concurrent first insert (unique
   *      violation), retry step 1.
   * No row back from any step → the budget is spent → rate-limited.
   */
  async issue(email: string, passwordHash?: string, binding?: string): Promise<IssueResult> {
    const key = normalizeEmail(email);
    const now = Date.now();
    const code = genCode();
    const bind = binding ?? null;
    const codeHash = hashCode(key, code);
    const pw = passwordHash ?? null;
    const expiresAt = new Date(now + CODE_TTL_MS).toISOString();
    const nowIso = new Date(now).toISOString();
    const windowFloor = new Date(now - SEND_WINDOW_MS).toISOString();
    const bump = () =>
      this.pg.query(
        `UPDATE email_verification_codes SET
           code_hash = $2, password_hash = $3, expires_at = $4, attempts = 0, binding = $8,
           send_count = CASE WHEN window_started_at <= $6 THEN 1 ELSE send_count + 1 END,
           window_started_at = CASE WHEN window_started_at <= $6 THEN $5 ELSE window_started_at END
         WHERE email = $1 AND (window_started_at <= $6 OR send_count < $7)
         RETURNING email`,
        [key, codeHash, pw, expiresAt, nowIso, windowFloor, MAX_SENDS_PER_WINDOW, bind],
      );
    if ((await bump()).rows.length > 0) return { code, rateLimited: false };
    try {
      // Plain INSERT (not ON CONFLICT DO NOTHING ... RETURNING, which pg-mem
      // answers with a row even on conflict): a lost first-insert race surfaces
      // as a unique violation and falls through to the retry below.
      await this.pg.query(
        `INSERT INTO email_verification_codes
           (email, code_hash, password_hash, expires_at, attempts, send_count, window_started_at, binding)
         VALUES ($1, $2, $3, $4, 0, 1, $5, $6)`,
        [key, codeHash, pw, expiresAt, nowIso, bind],
      );
      return { code, rateLimited: false };
    } catch (err) {
      if ((err as { code?: string }).code !== UNIQUE_VIOLATION) throw err;
    }
    if ((await bump()).rows.length > 0) return { code, rateLimited: false };
    return { rateLimited: true };
  }

  /**
   * PBA-L3a-002: the attempt is CLAIMED atomically before any comparison. The
   * old read-compare-write let N concurrent guesses all read `attempts = k` and
   * all be compared (79 comparisons against a cap of 5 through the HTTP route on
   * real Postgres). Now a single `UPDATE … attempts = attempts + 1 WHERE
   * attempts < MAX_ATTEMPTS … RETURNING` hands out at most MAX_ATTEMPTS claims
   * per issued code, whatever the interleaving; only a claim-holder compares.
   * Success is single-use via a conditional DELETE that exactly one caller wins.
   */
  async consume(email: string, code: string, binding?: string): Promise<ConsumeResult> {
    const key = normalizeEmail(email);
    const now = new Date(Date.now()).toISOString();
    const { rows } = await this.pg.query(
      `UPDATE email_verification_codes SET attempts = attempts + 1
        WHERE email = $1 AND attempts < $2 AND expires_at > $3
        RETURNING code_hash, password_hash, attempts, binding`,
      [key, MAX_ATTEMPTS, now],
    );
    if (rows.length === 0) {
      // Absent, expired or exhausted. Drop a dead row so it cannot linger.
      await this.pg.query(
        'DELETE FROM email_verification_codes WHERE email = $1 AND (attempts >= $2 OR expires_at <= $3)',
        [key, MAX_ATTEMPTS, now],
      );
      return { ok: false };
    }
    const r = rows[0] as { code_hash: string; password_hash: string | null; attempts: number; binding: string | null };
    if (!hashesEqual(r.code_hash, hashCode(key, code)) || !bindingMatches(r.binding, binding)) {
      if (r.attempts >= MAX_ATTEMPTS) {
        // Last claim spent: invalidate THIS code (a re-issued code is untouched).
        await this.pg.query('DELETE FROM email_verification_codes WHERE email = $1 AND code_hash = $2', [
          key,
          r.code_hash,
        ]);
      }
      return { ok: false };
    }
    const won = await this.pg.query(
      'DELETE FROM email_verification_codes WHERE email = $1 AND code_hash = $2 RETURNING email',
      [key, r.code_hash],
    );
    if (won.rows.length === 0) return { ok: false }; // a concurrent correct submit consumed it
    return {
      ok: true,
      ...(r.password_hash !== null ? { passwordHash: r.password_hash } : {}),
    };
  }
}

// ─────────────────────────────────────────────────────────────────────
//  Singleton + env init
// ─────────────────────────────────────────────────────────────────────

let store: EmailVerificationStore = new InMemoryEmailVerificationStore();

export function getEmailVerificationStore(): EmailVerificationStore {
  return store;
}

export function setEmailVerificationStore(s: EmailVerificationStore): void {
  store = s;
}

/**
 * Install the Postgres store when DATABASE_URL is set (same gate as the other
 * auth stores), in-memory otherwise. `pg` is imported lazily.
 */
export async function initEmailVerificationStoreFromEnv(
  env: { DATABASE_URL?: string } = process.env,
): Promise<void> {
  const databaseUrl = env.DATABASE_URL;
  if (databaseUrl && databaseUrl.trim() !== '') {
    const { Pool } = await import('pg');
    const pool = new Pool({ connectionString: databaseUrl });
    const s = new PgEmailVerificationStore(pool as unknown as PgLike);
    await s.ensureSchema();
    setEmailVerificationStore(s);
    return;
  }
  setEmailVerificationStore(new InMemoryEmailVerificationStore());
}
