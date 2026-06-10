/**
 * Postgres-backed WebAuthn credential store (WP-6 of EW-S1).
 *
 * Per `ADR-2026-06-05-ew-auth-methods`:
 *
 * ```sql
 * CREATE TABLE webauthn_credentials (
 *   id                 uuid PRIMARY KEY,
 *   user_id            uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 *   credential_id      bytea NOT NULL UNIQUE,
 *   public_key_cose    bytea NOT NULL,
 *   sign_count         bigint NOT NULL DEFAULT 0,
 *   transports         text[] DEFAULT ARRAY[]::text[],
 *   aaguid             uuid,
 *   device_label       text,
 *   created_at         timestamptz NOT NULL DEFAULT now(),
 *   last_used_at       timestamptz
 * );
 * ```
 *
 * `credential_id` (a.k.a. the WebAuthn rawId) is the lookup key in the
 * SimpleWebAuthn assertion verification flow.
 */

import { randomUUID } from 'node:crypto';

import { type PgLike } from './users-pg.js';

export interface WebAuthnCredentialRecord {
  id: string;
  userId: string;
  credentialId: Buffer;
  publicKeyCose: Buffer;
  signCount: bigint;
  transports: string[];
  aaguid?: string;
  deviceLabel?: string;
  createdAt: Date;
  lastUsedAt?: Date;
}

const CREATE_TABLE_SQL = `
CREATE TABLE IF NOT EXISTS webauthn_credentials (
  id                 uuid PRIMARY KEY,
  user_id            uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  credential_id      bytea NOT NULL UNIQUE,
  public_key_cose    bytea NOT NULL,
  sign_count         bigint NOT NULL DEFAULT 0,
  transports         text[] DEFAULT ARRAY[]::text[],
  aaguid             uuid,
  device_label       text,
  created_at         timestamptz NOT NULL DEFAULT now(),
  last_used_at       timestamptz
)`;

const TABLE_EXISTS_SQL =
  "SELECT 1 AS present FROM information_schema.tables WHERE table_name = 'webauthn_credentials' LIMIT 1";

interface RawRow {
  id: string;
  user_id: string;
  credential_id: Buffer;
  public_key_cose: Buffer;
  sign_count: bigint | string;
  transports: string[];
  aaguid: string | null;
  device_label: string | null;
  created_at: Date;
  last_used_at: Date | null;
}

function rowToRecord(row: RawRow): WebAuthnCredentialRecord {
  return {
    id: row.id,
    userId: row.user_id,
    credentialId: row.credential_id,
    publicKeyCose: row.public_key_cose,
    signCount:
      typeof row.sign_count === 'bigint' ? row.sign_count : BigInt(row.sign_count),
    transports: row.transports ?? [],
    aaguid: row.aaguid ?? undefined,
    deviceLabel: row.device_label ?? undefined,
    createdAt: row.created_at,
    lastUsedAt: row.last_used_at ?? undefined,
  };
}

export class PgWebAuthnCredentialStore {
  constructor(private readonly pool: PgLike) {}

  static async connect(databaseUrl: string): Promise<PgWebAuthnCredentialStore> {
    const { Pool } = await import('pg');
    const pool = new Pool({ connectionString: databaseUrl });
    const store = new PgWebAuthnCredentialStore(pool);
    await store.ensureSchema();
    return store;
  }

  async ensureSchema(): Promise<void> {
    const probe = await this.pool.query(TABLE_EXISTS_SQL);
    if (probe.rows.length === 0) {
      await this.pool.query(CREATE_TABLE_SQL);
    }
  }

  /** Insert a new credential after a successful registration. */
  async insertCredential(args: {
    userId: string;
    credentialId: Buffer;
    publicKeyCose: Buffer;
    signCount?: bigint;
    transports?: string[];
    aaguid?: string;
    deviceLabel?: string;
  }): Promise<WebAuthnCredentialRecord> {
    const id = randomUUID();
    const res = await this.pool.query(
      `INSERT INTO webauthn_credentials
         (id, user_id, credential_id, public_key_cose, sign_count, transports, aaguid, device_label)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       RETURNING id, user_id, credential_id, public_key_cose, sign_count, transports, aaguid, device_label, created_at, last_used_at`,
      [
        id,
        args.userId,
        args.credentialId,
        args.publicKeyCose,
        args.signCount ?? 0n,
        args.transports ?? [],
        args.aaguid ?? null,
        args.deviceLabel ?? null,
      ],
    );
    return rowToRecord(res.rows[0] as RawRow);
  }

  async findByCredentialId(
    credentialId: Buffer,
  ): Promise<WebAuthnCredentialRecord | undefined> {
    const res = await this.pool.query(
      `SELECT id, user_id, credential_id, public_key_cose, sign_count, transports, aaguid, device_label, created_at, last_used_at
       FROM webauthn_credentials WHERE credential_id = $1`,
      [credentialId],
    );
    const row = res.rows[0] as RawRow | undefined;
    return row ? rowToRecord(row) : undefined;
  }

  async listByUserId(userId: string): Promise<WebAuthnCredentialRecord[]> {
    const res = await this.pool.query(
      `SELECT id, user_id, credential_id, public_key_cose, sign_count, transports, aaguid, device_label, created_at, last_used_at
       FROM webauthn_credentials WHERE user_id = $1 ORDER BY created_at ASC`,
      [userId],
    );
    return (res.rows as RawRow[]).map(rowToRecord);
  }

  /** Bump `sign_count` + `last_used_at` after a successful assertion. */
  async recordAssertion(credentialId: Buffer, newSignCount: bigint): Promise<void> {
    await this.pool.query(
      `UPDATE webauthn_credentials
         SET sign_count = $2, last_used_at = now()
       WHERE credential_id = $1`,
      [credentialId, newSignCount],
    );
  }

  async revoke(credentialId: Buffer): Promise<void> {
    await this.pool.query(
      'DELETE FROM webauthn_credentials WHERE credential_id = $1',
      [credentialId],
    );
  }
}
