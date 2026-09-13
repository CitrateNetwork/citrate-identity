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
   */
  issue(email: string, passwordHash?: string): Promise<IssueResult>;
  /**
   * Verify `code` for `email`. On success the code is consumed (single-use) and
   * any stashed passwordHash is returned. On failure the attempt is counted and
   * the code invalidated once MAX_ATTEMPTS is reached.
   */
  consume(email: string, code: string): Promise<ConsumeResult>;
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
  expiresAt: number;
  attempts: number;
  sendCount: number;
  windowStartedAt: number;
}

export class InMemoryEmailVerificationStore implements EmailVerificationStore {
  private readonly byEmail = new Map<string, Row>();

  async issue(email: string, passwordHash?: string): Promise<IssueResult> {
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
      expiresAt: now + CODE_TTL_MS,
      attempts: 0,
      sendCount,
      windowStartedAt,
    });
    return { code, rateLimited: false };
  }

  async consume(email: string, code: string): Promise<ConsumeResult> {
    const key = normalizeEmail(email);
    const row = this.byEmail.get(key);
    if (!row) return { ok: false };
    if (Date.now() > row.expiresAt || row.attempts >= MAX_ATTEMPTS) {
      this.byEmail.delete(key);
      return { ok: false };
    }
    if (!hashesEqual(row.codeHash, hashCode(key, code))) {
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
  expires_at        timestamptz NOT NULL,
  attempts          integer NOT NULL DEFAULT 0,
  send_count        integer NOT NULL DEFAULT 1,
  window_started_at timestamptz NOT NULL DEFAULT now(),
  created_at        timestamptz NOT NULL DEFAULT now()
)`;

export class PgEmailVerificationStore implements EmailVerificationStore {
  constructor(private readonly pg: PgLike) {}

  async ensureSchema(): Promise<void> {
    await this.pg.query(CREATE_TABLE_SQL);
  }

  async issue(email: string, passwordHash?: string): Promise<IssueResult> {
    const key = normalizeEmail(email);
    const { rows } = await this.pg.query(
      'SELECT send_count, window_started_at FROM email_verification_codes WHERE email = $1',
      [key],
    );
    const now = Date.now();
    let sendCount = 1;
    let windowStartedAt = new Date(now);
    if (rows.length > 0) {
      const r = rows[0] as { send_count: number; window_started_at: string | Date };
      const ws = new Date(r.window_started_at).getTime();
      if (now - ws < SEND_WINDOW_MS) {
        if (r.send_count >= MAX_SENDS_PER_WINDOW) return { rateLimited: true };
        sendCount = r.send_count + 1;
        windowStartedAt = new Date(ws);
      }
    }
    const code = genCode();
    await this.pg.query(
      `INSERT INTO email_verification_codes
         (email, code_hash, password_hash, expires_at, attempts, send_count, window_started_at)
       VALUES ($1, $2, $3, $4, 0, $5, $6)
       ON CONFLICT (email) DO UPDATE SET
         code_hash = EXCLUDED.code_hash,
         password_hash = EXCLUDED.password_hash,
         expires_at = EXCLUDED.expires_at,
         attempts = 0,
         send_count = EXCLUDED.send_count,
         window_started_at = EXCLUDED.window_started_at`,
      [
        key,
        hashCode(key, code),
        passwordHash ?? null,
        new Date(now + CODE_TTL_MS).toISOString(),
        sendCount,
        windowStartedAt.toISOString(),
      ],
    );
    return { code, rateLimited: false };
  }

  async consume(email: string, code: string): Promise<ConsumeResult> {
    const key = normalizeEmail(email);
    const { rows } = await this.pg.query(
      'SELECT code_hash, password_hash, expires_at, attempts FROM email_verification_codes WHERE email = $1',
      [key],
    );
    if (rows.length === 0) return { ok: false };
    const r = rows[0] as {
      code_hash: string;
      password_hash: string | null;
      expires_at: string | Date;
      attempts: number;
    };
    if (Date.now() > new Date(r.expires_at).getTime() || r.attempts >= MAX_ATTEMPTS) {
      await this.pg.query('DELETE FROM email_verification_codes WHERE email = $1', [key]);
      return { ok: false };
    }
    if (!hashesEqual(r.code_hash, hashCode(key, code))) {
      const attempts = r.attempts + 1;
      if (attempts >= MAX_ATTEMPTS) {
        await this.pg.query('DELETE FROM email_verification_codes WHERE email = $1', [key]);
      } else {
        await this.pg.query(
          'UPDATE email_verification_codes SET attempts = $2 WHERE email = $1',
          [key, attempts],
        );
      }
      return { ok: false };
    }
    await this.pg.query('DELETE FROM email_verification_codes WHERE email = $1', [key]); // single-use
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
