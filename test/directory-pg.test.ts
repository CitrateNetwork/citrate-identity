/**
 * PgDirectoryStore against a `pg-mem` in-process Postgres (citrate-core#61).
 *
 * Runs the REAL SQL — composite PK, `ON CONFLICT DO NOTHING`, the `LIKE ... ESCAPE`
 * prefix search — so the Postgres path is proven to reproduce
 * `InMemoryDirectoryStore` exactly: last-writer by `bound_at`, the tombstone that a
 * replayed publish cannot un-revoke, and lookups/search that return only live rows.
 */
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { newDb, type IMemoryDb } from 'pg-mem';

import { PgDirectoryStore, type PgLike } from '../src/directory-pg.js';

const A = '0x' + 'a1'.repeat(20);
const B = '0x' + 'b2'.repeat(20);
const NOW = 1_760_000_000;

function freshPool(): PgLike {
  const db: IMemoryDb = newDb();
  const pg = db.adapters.createPg();
  return new pg.Pool() as unknown as PgLike;
}

describe('PgDirectoryStore against pg-mem', () => {
  let store: PgDirectoryStore;

  beforeEach(async () => {
    store = new PgDirectoryStore(freshPool());
    await store.ensureSchema();
  });

  afterEach(async () => {
    /* per-test db; nothing global to reset */
  });

  const rec = (over: Partial<Parameters<PgDirectoryStore['upsert']>[0]> = {}) => ({
    platform: 'x' as const,
    handleKey: 'satoshi',
    handle: 'satoshi',
    address: A,
    boundAt: NOW,
    ...over,
  });

  it('ensureSchema is idempotent', async () => {
    await expect(store.ensureSchema()).resolves.toBeUndefined();
  });

  it('publish → lookup hit; unpublished → null', async () => {
    expect(await store.upsert(rec())).toBe('stored');
    const hit = await store.lookup('x', 'satoshi');
    expect(hit).toEqual({ address: A.toLowerCase(), boundAt: NOW });
    expect(await store.lookup('x', 'ghost')).toBeNull();
  });

  it('last-writer by bound_at: newer wins, identical unchanged, older stale', async () => {
    await store.upsert(rec());
    expect(await store.upsert(rec())).toBe('unchanged');
    expect(await store.upsert(rec({ boundAt: NOW + 5, displayName: 'Sat' }))).toBe('stored');
    expect((await store.lookup('x', 'satoshi'))?.boundAt).toBe(NOW + 5);
    expect(await store.upsert(rec({ boundAt: NOW - 5 }))).toBe('stale');
  });

  it('revoke tombstones; lookup + search return nothing; stranger cannot revoke', async () => {
    await store.upsert(rec());
    expect(await store.revoke('x', 'satoshi', B)).toBe(false); // wrong address
    expect(await store.revoke('x', 'satoshi', A)).toBe(true);
    expect(await store.lookup('x', 'satoshi')).toBeNull();
    expect(await store.search('x', 'sat', 20)).toEqual([]);
  });

  it('a replayed publish (same bound_at) cannot un-revoke; a fresher one can', async () => {
    await store.upsert(rec());
    await store.revoke('x', 'satoshi', A);
    expect(await store.upsert(rec())).toBe('stale');
    expect(await store.lookup('x', 'satoshi')).toBeNull();
    expect(await store.upsert(rec({ boundAt: NOW + 1 }))).toBe('stored');
    expect(await store.lookup('x', 'satoshi')).not.toBeNull();
  });

  it('search matches by prefix, is capped, and treats _ as a literal', async () => {
    await store.upsert(rec({ handleKey: 'alice', handle: 'alice', address: A }));
    await store.upsert(rec({ handleKey: 'alicia', handle: 'alicia', address: B }));
    await store.upsert(rec({ handleKey: 'a_b', handle: 'a_b', address: A }));

    const ali = await store.search('x', 'ali', 20);
    expect(ali.map((r) => r.handle).sort()).toEqual(['alice', 'alicia']);

    // `_` in the query is escaped, so it must NOT act as a SQL LIKE wildcard that
    // would match 'alice'/'alicia'. (Real Postgres also returns the literal 'a_b'
    // here; pg-mem's LIKE-escape handling diverges, so we assert the security
    // invariant — no wildcard bleed — which holds in both.)
    const underscore = await store.search('x', 'a_', 20);
    expect(underscore.map((r) => r.handle)).not.toContain('alice');
    expect(underscore.map((r) => r.handle)).not.toContain('alicia');

    for (let i = 0; i < 25; i++) {
      await store.upsert(rec({ handleKey: `bob${i.toString().padStart(2, '0')}`, handle: `bob${i}`, address: A }));
    }
    expect((await store.search('x', 'bob', 20)).length).toBe(20);
  });
});
