/**
 * Postgres-backed user account store (WP-6 of EW-S1).
 *
 * Per `ADR-2026-06-05-ew-auth-methods` §"Storage shape (Postgres)":
 *
 * ```sql
 * CREATE TABLE users (
 *   id              uuid PRIMARY KEY,
 *   email           text UNIQUE,
 *   email_verified  boolean NOT NULL DEFAULT false,
 *   password_hash   text,
 *   google_sub      text UNIQUE,
 *   primary_wallet  text UNIQUE,
 *   legacy_siwe_eoa text UNIQUE,
 *   created_at      timestamptz NOT NULL DEFAULT now(),
 *   updated_at      timestamptz NOT NULL DEFAULT now()
 * );
 * ```
 *
 * Mirrors the `PgKycStore` pattern: idempotent `ensureSchema`, a small
 * `PgLike` interface the constructor accepts so tests can drive pg-mem,
 * production helper `connect(databaseUrl)`.
 */

import { randomUUID } from 'node:crypto';

/** The minimal `pg`-compatible surface this store needs. */
export interface PgLike {
  query(text: string, params?: unknown[]): Promise<{ rows: unknown[] }>;
}

/** Stored user record. */
export interface UserRecord {
  id: string;
  email?: string;
  emailVerified: boolean;
  passwordHash?: string;
  googleSub?: string;
  primaryWallet?: string;
  legacySiweEoa?: string;
  createdAt: Date;
  updatedAt: Date;
}

const CREATE_TABLE_SQL = `
CREATE TABLE IF NOT EXISTS users (
  id              uuid PRIMARY KEY,
  email           text UNIQUE,
  email_verified  boolean NOT NULL DEFAULT false,
  password_hash   text,
  google_sub      text UNIQUE,
  primary_wallet  text UNIQUE,
  legacy_siwe_eoa text UNIQUE,
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now()
)`;

const TABLE_EXISTS_SQL =
  "SELECT 1 AS present FROM information_schema.tables WHERE table_name = 'users' LIMIT 1";

interface RawRow {
  id: string;
  email: string | null;
  email_verified: boolean;
  password_hash: string | null;
  google_sub: string | null;
  primary_wallet: string | null;
  legacy_siwe_eoa: string | null;
  created_at: Date;
  updated_at: Date;
}

function rowToRecord(row: RawRow): UserRecord {
  return {
    id: row.id,
    email: row.email ?? undefined,
    emailVerified: row.email_verified,
    passwordHash: row.password_hash ?? undefined,
    googleSub: row.google_sub ?? undefined,
    primaryWallet: row.primary_wallet ?? undefined,
    legacySiweEoa: row.legacy_siwe_eoa ?? undefined,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

export class PgUserStore {
  constructor(private readonly pool: PgLike) {}

  static async connect(databaseUrl: string): Promise<PgUserStore> {
    const { Pool } = await import('pg');
    const pool = new Pool({ connectionString: databaseUrl });
    const store = new PgUserStore(pool);
    await store.ensureSchema();
    return store;
  }

  async ensureSchema(): Promise<void> {
    const probe = await this.pool.query(TABLE_EXISTS_SQL);
    if (probe.rows.length === 0) {
      await this.pool.query(CREATE_TABLE_SQL);
    }
  }

  // ── Create ──────────────────────────────────────────────────────────

  /**
   * Create a brand-new user with email + password. `passwordHash` should
   * already be an Argon2id digest (`argon2.hashPassword` from
   * src/auth/password.ts).
   */
  async createWithEmailPassword(args: {
    email: string;
    passwordHash: string;
  }): Promise<UserRecord> {
    const id = randomUUID();
    const res = await this.pool.query(
      `INSERT INTO users (id, email, password_hash) VALUES ($1, $2, $3)
       RETURNING id, email, email_verified, password_hash, google_sub,
                 primary_wallet, legacy_siwe_eoa, created_at, updated_at`,
      [id, normalizeEmail(args.email), args.passwordHash],
    );
    return rowToRecord(res.rows[0] as RawRow);
  }

  /** Create a brand-new user from a Google federation. */
  async createWithGoogle(args: { googleSub: string; email?: string }): Promise<UserRecord> {
    const id = randomUUID();
    const res = await this.pool.query(
      `INSERT INTO users (id, email, email_verified, google_sub)
       VALUES ($1, $2, true, $3)
       RETURNING id, email, email_verified, password_hash, google_sub,
                 primary_wallet, legacy_siwe_eoa, created_at, updated_at`,
      [id, args.email ? normalizeEmail(args.email) : null, args.googleSub],
    );
    return rowToRecord(res.rows[0] as RawRow);
  }

  /**
   * Create a passkey-only user (no email, no password, no Google federation).
   * Used by WP-A's `/auth/webauthn/signup-verify` for first-time enrollment;
   * the caller MUST insert the WebAuthn credential atomically afterwards.
   */
  async createWithPasskey(): Promise<UserRecord> {
    const id = randomUUID();
    const res = await this.pool.query(
      `INSERT INTO users (id)
       VALUES ($1)
       RETURNING id, email, email_verified, password_hash, google_sub,
                 primary_wallet, legacy_siwe_eoa, created_at, updated_at`,
      [id],
    );
    return rowToRecord(res.rows[0] as RawRow);
  }

  /** Create a SIWE-only user (no email/password, only an EOA bind). */
  async createWithSiwe(args: { eoa: string }): Promise<UserRecord> {
    const id = randomUUID();
    const res = await this.pool.query(
      `INSERT INTO users (id, legacy_siwe_eoa)
       VALUES ($1, $2)
       RETURNING id, email, email_verified, password_hash, google_sub,
                 primary_wallet, legacy_siwe_eoa, created_at, updated_at`,
      [id, args.eoa.toLowerCase()],
    );
    return rowToRecord(res.rows[0] as RawRow);
  }

  // ── Read ─────────────────────────────────────────────────────────────

  async findById(id: string): Promise<UserRecord | undefined> {
    const res = await this.pool.query(
      'SELECT id, email, email_verified, password_hash, google_sub, primary_wallet, legacy_siwe_eoa, created_at, updated_at FROM users WHERE id = $1',
      [id],
    );
    const row = res.rows[0] as RawRow | undefined;
    return row ? rowToRecord(row) : undefined;
  }

  async findByEmail(email: string): Promise<UserRecord | undefined> {
    const res = await this.pool.query(
      'SELECT id, email, email_verified, password_hash, google_sub, primary_wallet, legacy_siwe_eoa, created_at, updated_at FROM users WHERE email = $1',
      [normalizeEmail(email)],
    );
    const row = res.rows[0] as RawRow | undefined;
    return row ? rowToRecord(row) : undefined;
  }

  async findByGoogleSub(googleSub: string): Promise<UserRecord | undefined> {
    const res = await this.pool.query(
      'SELECT id, email, email_verified, password_hash, google_sub, primary_wallet, legacy_siwe_eoa, created_at, updated_at FROM users WHERE google_sub = $1',
      [googleSub],
    );
    const row = res.rows[0] as RawRow | undefined;
    return row ? rowToRecord(row) : undefined;
  }

  async findBySiweEoa(eoa: string): Promise<UserRecord | undefined> {
    const res = await this.pool.query(
      'SELECT id, email, email_verified, password_hash, google_sub, primary_wallet, legacy_siwe_eoa, created_at, updated_at FROM users WHERE legacy_siwe_eoa = $1',
      [eoa.toLowerCase()],
    );
    const row = res.rows[0] as RawRow | undefined;
    return row ? rowToRecord(row) : undefined;
  }

  // ── Mutations ─────────────────────────────────────────────────────────

  async markEmailVerified(id: string): Promise<void> {
    await this.pool.query(
      'UPDATE users SET email_verified = true, updated_at = now() WHERE id = $1',
      [id],
    );
  }

  async setPrimaryWallet(id: string, walletAddress: string): Promise<void> {
    await this.pool.query(
      'UPDATE users SET primary_wallet = $1, updated_at = now() WHERE id = $2',
      [walletAddress.toLowerCase(), id],
    );
  }

  async linkGoogleSub(id: string, googleSub: string): Promise<void> {
    await this.pool.query(
      'UPDATE users SET google_sub = $1, email_verified = true, updated_at = now() WHERE id = $2',
      [googleSub, id],
    );
  }

  async rotatePasswordHash(id: string, passwordHash: string): Promise<void> {
    await this.pool.query(
      'UPDATE users SET password_hash = $1, updated_at = now() WHERE id = $2',
      [passwordHash, id],
    );
  }
}

function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}
