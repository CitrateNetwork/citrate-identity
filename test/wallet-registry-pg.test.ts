/**
 * The DURABLE identity↔wallet registry.
 *
 * WHY. `InMemoryWalletRegistry` was the only implementation and nothing installed
 * a durable one, so in production the registry lived in process memory with no
 * table behind it. Every identity redeploy wiped it. That became money-relevant
 * once a proven CANONICAL link started setting `users.primary_wallet` — the
 * `wallet_address` claim, which is the address the treasury bond-funds.
 *
 * The failure that motivated this file: restart → `canonicalFor` returns null →
 * the member links a SECOND wallet → it is treated as "first" → the canonical
 * hook repoints `primary_wallet` to it. The member's pay-to address moves without
 * anyone doing anything wrong.
 */
import { beforeEach, describe, expect, it } from 'vitest';

import { PgWalletRegistry, type PgLike } from '../src/wallet-registry-pg.js';
import { WalletRegistryError } from '../src/identity-registry.js';

const A = '0x' + 'a1'.repeat(20);
const B = '0x' + 'b2'.repeat(20);

/**
 * A tiny in-process stand-in for the slice of Postgres this store uses. It models
 * the ONE property the correctness argument rests on — a monotonic `seq` and a
 * UNIQUE(address) constraint — rather than pretending to be a database.
 */
class FakePg implements PgLike {
  rows: Array<{
    seq: number;
    sub: string;
    address: string;
    linked_at: string;
    is_canonical: boolean;
  }> = [];
  private seq = 0;

  async query(text: string, values: unknown[] = []) {
    const t = text.replace(/\s+/g, ' ').trim();

    if (t.startsWith('SELECT 1 FROM information_schema.tables')) return { rows: [{ x: 1 }] };
    if (
      t.startsWith('CREATE TABLE') ||
      t.startsWith('CREATE INDEX') ||
      t.startsWith('CREATE UNIQUE INDEX') ||
      t.startsWith('ALTER TABLE')
    ) {
      return { rows: [] };
    }

    if (t.startsWith('SELECT seq, address, linked_at FROM linked_wallets WHERE sub = $1 AND address = $2')) {
      return { rows: this.rows.filter((r) => r.sub === values[0] && r.address === values[1]) };
    }
    if (t.startsWith('SELECT sub FROM linked_wallets WHERE address = $1')) {
      return { rows: this.rows.filter((r) => r.address === values[0]) };
    }
    if (t.startsWith('SELECT seq FROM linked_wallets WHERE sub = $1')) {
      return { rows: this.rows.filter((r) => r.sub === values[0]) };
    }
    if (t.startsWith('INSERT INTO linked_wallets')) {
      const [sub, address] = values as [string, string];
      if (this.rows.some((r) => r.address === address)) throw new Error('unique violation');
      const row = {
        seq: ++this.seq,
        sub,
        address,
        linked_at: new Date(this.seq * 1000).toISOString(),
        is_canonical: false,
      };
      this.rows.push(row);
      return { rows: [row] };
    }
    if (t.startsWith('DELETE FROM linked_wallets')) {
      this.rows = this.rows.filter((r) => !(r.sub === values[0] && r.address === values[1]));
      return { rows: [] };
    }
    if (t.startsWith('SELECT seq, address, linked_at FROM linked_wallets WHERE sub = $1 ORDER BY seq ASC')) {
      return { rows: this.rows.filter((r) => r.sub === values[0]).sort((x, y) => x.seq - y.seq) };
    }
    if (
      t.startsWith(
        'SELECT address FROM linked_wallets WHERE sub = $1 ORDER BY is_canonical DESC, seq ASC LIMIT 1',
      )
    ) {
      // Models the real ORDER BY: an explicit choice outranks first-linked.
      const mine = this.rows
        .filter((r) => r.sub === values[0])
        .sort((x, y) => Number(y.is_canonical) - Number(x.is_canonical) || x.seq - y.seq);
      return { rows: mine.length ? [mine[0]!] : [] };
    }
    if (t.startsWith('UPDATE linked_wallets SET is_canonical = (address = $2)')) {
      const [sub, addr] = values as [string, string];
      // The real statement's EXISTS guard: no row for (sub,address) => no rows
      // updated => the store throws. Model it, or the "refuses an unlinked
      // wallet" property is not actually under test here.
      if (!this.rows.some((r) => r.sub === sub && r.address === addr)) return { rows: [] };
      const touched = this.rows.filter((r) => r.sub === sub);
      for (const r of touched) r.is_canonical = r.address === addr;
      return { rows: touched.map((r) => ({ address: r.address })) };
    }
    throw new Error('unhandled SQL in FakePg: ' + t);
  }
}

let pg: FakePg;
let reg: PgWalletRegistry;

beforeEach(async () => {
  pg = new FakePg();
  reg = new PgWalletRegistry(pg);
  await reg.ensureSchema();
});

describe('PgWalletRegistry — links survive the process', () => {
  it('THE REGRESSION: a new instance over the same rows still knows the canonical wallet', async () => {
    await reg.link('sub-1', A);
    // A redeploy: brand-new store object, same durable rows.
    const afterRestart = new PgWalletRegistry(pg);
    expect(await afterRestart.canonicalFor('sub-1')).toBe(A.toLowerCase());
    expect(await afterRestart.list('sub-1')).toHaveLength(1);
  });

  it('and a SECOND wallet linked after a restart does NOT become canonical', async () => {
    await reg.link('sub-1', A);
    const afterRestart = new PgWalletRegistry(pg);
    await afterRestart.link('sub-1', B);

    // With the in-memory registry this returned B — and the canonical-change hook
    // would have repointed primary_wallet, moving the member's pay-to address.
    expect(await afterRestart.canonicalFor('sub-1')).toBe(A.toLowerCase());
    const list = await afterRestart.list('sub-1');
    expect(list[0]!.address).toBe(A.toLowerCase());
    expect(list[0]!.canonical).toBe(true);
    expect(list[1]!.canonical).toBe(false);
  });

  it('canonical is the FIRST linked, ordered by monotonic seq not wall-clock', async () => {
    await reg.link('sub-1', A);
    await reg.link('sub-1', B);
    expect(await reg.canonicalFor('sub-1')).toBe(A.toLowerCase());
  });
});

describe('PgWalletRegistry — the guards hold across restarts too', () => {
  it('one identity per wallet, enforced even for a fresh instance', async () => {
    await reg.link('sub-1', A);
    const afterRestart = new PgWalletRegistry(pg);
    await expect(afterRestart.link('sub-2', A)).rejects.toBeInstanceOf(WalletRegistryError);
  });

  it('re-linking a wallet you already hold is idempotent, not an error', async () => {
    const first = await reg.link('sub-1', A);
    const again = await reg.link('sub-1', A);
    expect(again.address).toBe(first.address);
    expect(await reg.list('sub-1')).toHaveLength(1);
  });

  it('addresses are stored lowercase, so casing cannot create a duplicate', async () => {
    await reg.link('sub-1', A.toUpperCase().replace('0X', '0x'));
    await expect(reg.link('sub-2', A.toLowerCase())).rejects.toBeInstanceOf(WalletRegistryError);
  });

  it('a concurrent insert that loses the UNIQUE race surfaces as a conflict, not a 500', async () => {
    // The pre-check passes, then the INSERT collides — exactly the interleaving the
    // courtesy SELECT cannot prevent.
    const racy = new PgWalletRegistry({
      async query(text: string, values?: unknown[]) {
        if (text.includes('SELECT sub FROM linked_wallets')) return { rows: [] };
        if (text.includes('INSERT INTO')) throw new Error('duplicate key');
        return pg.query(text, values);
      },
    });
    await expect(racy.link('sub-9', B)).rejects.toBeInstanceOf(WalletRegistryError);
  });

  it('unlinking promotes the next wallet to canonical', async () => {
    await reg.link('sub-1', A);
    await reg.link('sub-1', B);
    await reg.unlink('sub-1', A);
    expect(await reg.canonicalFor('sub-1')).toBe(B.toLowerCase());
  });

  it('unlinking the last wallet leaves no canonical', async () => {
    await reg.link('sub-1', A);
    await reg.unlink('sub-1', A);
    expect(await reg.canonicalFor('sub-1')).toBeNull();
    expect(await reg.list('sub-1')).toEqual([]);
  });

  it('caps a sub at 10 wallets, same as the in-memory registry', async () => {
    for (let i = 0; i < 10; i++) {
      await reg.link('sub-1', '0x' + String(i).padStart(2, '0').repeat(20));
    }
    await expect(reg.link('sub-1', B)).rejects.toBeInstanceOf(WalletRegistryError);
  });
});

describe('PgWalletRegistry — explicit canonical rebinding', () => {
  beforeEach(async () => {
    pg = new FakePg();
    reg = new PgWalletRegistry(pg);
    await reg.ensureSchema();
  });

  it('keeps first-linked canonical until asked otherwise', async () => {
    await reg.link('s1', A);
    await reg.link('s1', B);
    expect(await reg.canonicalFor('s1')).toBe(A);
  });

  it('promotes an already-linked wallet, durably', async () => {
    await reg.link('s1', A);
    await reg.link('s1', B);
    await reg.setCanonical('s1', B);
    expect(await reg.canonicalFor('s1')).toBe(B);

    // Survives a "restart": a fresh store over the SAME rows must agree, which
    // is the whole point of moving the override into the table rather than
    // holding it in process memory (the bug this file exists for).
    const restarted = new PgWalletRegistry(pg);
    expect(await restarted.canonicalFor('s1')).toBe(B);
  });

  it('refuses a wallet that is not linked to the sub', async () => {
    await reg.link('s1', A);
    await expect(reg.setCanonical('s1', B)).rejects.toBeInstanceOf(WalletRegistryError);
    expect(await reg.canonicalFor('s1')).toBe(A);
  });

  it('never leaves two canonical rows for one sub', async () => {
    await reg.link('s1', A);
    await reg.link('s1', B);
    await reg.setCanonical('s1', B);
    await reg.setCanonical('s1', A);
    expect(pg.rows.filter((r) => r.sub === 's1' && r.is_canonical)).toHaveLength(1);
    expect(await reg.canonicalFor('s1')).toBe(A);
  });

  it('list() reflects the override', async () => {
    await reg.link('s1', A);
    await reg.link('s1', B);
    await reg.setCanonical('s1', B);
    const wallets = await reg.list('s1');
    expect(wallets.find((w) => w.address === B)?.canonical).toBe(true);
    expect(wallets.filter((w) => w.canonical)).toHaveLength(1);
  });
});

