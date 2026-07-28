/**
 * Postgres-backed identity↔wallet registry.
 *
 * # Why this exists
 *
 * `InMemoryWalletRegistry` was the ONLY implementation, and `setWalletRegistry`
 * had no production caller — so in production the registry lived in process
 * memory and there was no wallet table at all. Every identity redeploy (four on
 * 2026-07-28 alone) silently wiped it.
 *
 * That is not cosmetic, because a link is now money-relevant: a proven CANONICAL
 * link sets `users.primary_wallet`, which is the `wallet_address` claim, which is
 * the address the membership treasury bond-funds. With an in-memory registry:
 *
 *   - `GET /identity/:sub/wallets` returned `[]` after any restart even though the
 *     member had linked, so the `wallets` claim vanished;
 *   - the cross-identity uniqueness guard ("wallet already linked to another
 *     identity") reset, so one wallet could be linked to a second identity;
 *   - worst: `canonicalFor` returned null, so a member linking a SECOND wallet
 *     after a restart made THAT wallet canonical — and the canonical-change hook
 *     repointed `primary_wallet` to it. A restart plus a second link silently
 *     moved the member's pay-to address.
 *
 * `primary_wallet` itself lives on `users` and was always durable; it is the
 * registry around it that was not. This closes that.
 *
 * # Ordering
 *
 * Canonical = FIRST linked (the ADR rule). Ordering is by a monotonic `seq`, not
 * `linked_at`, so two links inside the same clock tick still have a total order
 * and "first" cannot flip between reads.
 */

import type { LinkedWallet, WalletRegistry } from './identity-registry.js';
import { WalletRegistryError } from './identity-registry.js';

/** The slice of `pg.Pool` this store needs (keeps tests off a real driver). */
export interface PgLike {
  query(text: string, values?: unknown[]): Promise<{ rows: Array<Record<string, unknown>> }>;
}

const TABLE_EXISTS_SQL = `
  SELECT 1 FROM information_schema.tables
   WHERE table_schema = 'public' AND table_name = 'linked_wallets'`;

const CREATE_TABLE_SQL = `
  CREATE TABLE IF NOT EXISTS linked_wallets (
    seq        BIGSERIAL PRIMARY KEY,
    sub        TEXT        NOT NULL,
    address    TEXT        NOT NULL,
    linked_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- One identity per wallet, enforced by the DB rather than by a read-then-write
    -- race in application code.
    CONSTRAINT linked_wallets_address_key UNIQUE (address)
  )`;

const CREATE_INDEX_SQL = `
  CREATE INDEX IF NOT EXISTS linked_wallets_sub_seq_idx ON linked_wallets (sub, seq)`;

/** Mirrors InMemoryWalletRegistry's cap so behaviour does not change with backing. */
const MAX_WALLETS_PER_SUB = 10;

export class PgWalletRegistry implements WalletRegistry {
  constructor(private readonly pool: PgLike) {}

  static async connect(databaseUrl: string): Promise<PgWalletRegistry> {
    const { Pool } = await import('pg');
    const pool = new Pool({ connectionString: databaseUrl });
    const store = new PgWalletRegistry(pool as unknown as PgLike);
    await store.ensureSchema();
    return store;
  }

  async ensureSchema(): Promise<void> {
    const probe = await this.pool.query(TABLE_EXISTS_SQL);
    if (probe.rows.length === 0) {
      await this.pool.query(CREATE_TABLE_SQL);
    }
    await this.pool.query(CREATE_INDEX_SQL);
  }

  async link(sub: string, address: string): Promise<LinkedWallet> {
    const addr = address.toLowerCase();

    // Already linked to THIS sub → idempotent, return the existing row rather
    // than raising. Re-proving control of a wallet you already linked is not an
    // error, and making it one would strand a client that retried.
    const mine = await this.pool.query(
      'SELECT seq, address, linked_at FROM linked_wallets WHERE sub = $1 AND address = $2',
      [sub, addr],
    );
    if (mine.rows.length > 0) {
      return this.rowToLinked(mine.rows[0]!, await this.canonicalFor(sub));
    }

    const owner = await this.pool.query('SELECT sub FROM linked_wallets WHERE address = $1', [addr]);
    if (owner.rows.length > 0) {
      throw new WalletRegistryError('wallet is already linked to another identity');
    }

    const count = await this.pool.query('SELECT seq FROM linked_wallets WHERE sub = $1', [sub]);
    if (count.rows.length >= MAX_WALLETS_PER_SUB) {
      throw new WalletRegistryError(`a sub may link at most ${MAX_WALLETS_PER_SUB} wallets`);
    }

    let inserted;
    try {
      inserted = await this.pool.query(
        'INSERT INTO linked_wallets (sub, address) VALUES ($1, $2) RETURNING seq, address, linked_at',
        [sub, addr],
      );
    } catch {
      // The UNIQUE(address) constraint is the real guard — the SELECT above is a
      // courtesy that gives a better message. A concurrent linker that beat us
      // here surfaces as the same conflict rather than a 500.
      throw new WalletRegistryError('wallet is already linked to another identity');
    }

    return this.rowToLinked(inserted.rows[0]!, await this.canonicalFor(sub));
  }

  async unlink(sub: string, address: string): Promise<void> {
    await this.pool.query('DELETE FROM linked_wallets WHERE sub = $1 AND address = $2', [
      sub,
      address.toLowerCase(),
    ]);
  }

  async list(sub: string): Promise<LinkedWallet[]> {
    const res = await this.pool.query(
      'SELECT seq, address, linked_at FROM linked_wallets WHERE sub = $1 ORDER BY seq ASC',
      [sub],
    );
    return res.rows.map((r, i) => ({
      address: String(r.address),
      canonical: i === 0, // first linked, by monotonic seq
      linkedAt: new Date(String(r.linked_at)),
    }));
  }

  async canonicalFor(sub: string): Promise<string | null> {
    const res = await this.pool.query(
      'SELECT address FROM linked_wallets WHERE sub = $1 ORDER BY seq ASC LIMIT 1',
      [sub],
    );
    return res.rows.length > 0 ? String(res.rows[0]!.address) : null;
  }

  private rowToLinked(row: Record<string, unknown>, canonical: string | null): LinkedWallet {
    const address = String(row.address);
    return {
      address,
      canonical: canonical === null || canonical === address,
      linkedAt: new Date(String(row.linked_at)),
    };
  }
}

/**
 * Install the registry for this environment: Postgres when `DATABASE_URL` is set
 * (production), otherwise leave the in-memory default in place (dev/test).
 *
 * `assertProductionConfig` already refuses to boot in production without
 * `DATABASE_URL`, so the in-memory fallback is genuinely dev-only — but it warns
 * anyway, because "links do not survive a restart" is exactly the kind of thing
 * that should never be discovered from behaviour.
 */
export async function initWalletRegistryFromEnv(
  env: NodeJS.ProcessEnv,
  setRegistry: (r: WalletRegistry) => void,
): Promise<void> {
  const url = (env.DATABASE_URL ?? '').trim();
  if (!url) {
    // eslint-disable-next-line no-console
    console.warn(
      '[wallet-registry] DATABASE_URL unset — using the IN-MEMORY registry. Links will NOT ' +
        'survive a restart, and the one-identity-per-wallet guard resets with the process.',
    );
    return;
  }
  setRegistry(await PgWalletRegistry.connect(url));
}
