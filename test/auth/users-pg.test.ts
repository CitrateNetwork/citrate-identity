import { describe, it, expect, beforeEach } from 'vitest';
import { newDb, type IMemoryDb } from 'pg-mem';

import { PgUserStore } from '../../src/auth/users-pg.js';

function freshDb() {
  const db: IMemoryDb = newDb();
  const pg = db.adapters.createPg();
  return { db, makePool: () => new pg.Pool() };
}

describe('PgUserStore against pg-mem', () => {
  let ctx: ReturnType<typeof freshDb>;

  beforeEach(() => {
    ctx = freshDb();
  });

  it('ensureSchema is idempotent', async () => {
    const store = new PgUserStore(ctx.makePool());
    await store.ensureSchema();
    await expect(store.ensureSchema()).resolves.toBeUndefined();
  });

  it('createWithEmailPassword inserts a user and findById returns it', async () => {
    const store = new PgUserStore(ctx.makePool());
    await store.ensureSchema();
    const u = await store.createWithEmailPassword({
      email: 'Alice@Example.com',
      passwordHash: '$argon2id$v=19$m=19456,t=2,p=1$abc$def',
    });
    expect(u.email).toBe('alice@example.com'); // normalized
    expect(u.emailVerified).toBe(false);
    expect(u.passwordHash).toBeDefined();
    const found = await store.findById(u.id);
    expect(found?.id).toBe(u.id);
  });

  it('findByEmail normalizes case', async () => {
    const store = new PgUserStore(ctx.makePool());
    await store.ensureSchema();
    await store.createWithEmailPassword({
      email: 'BOB@example.com',
      passwordHash: '$argon2id$abc',
    });
    const found = await store.findByEmail('bob@example.com');
    expect(found?.email).toBe('bob@example.com');
  });

  it('createWithGoogle records the sub and pre-verifies the email', async () => {
    const store = new PgUserStore(ctx.makePool());
    await store.ensureSchema();
    const u = await store.createWithGoogle({
      googleSub: 'sub-12345',
      email: 'carol@example.com',
    });
    expect(u.googleSub).toBe('sub-12345');
    expect(u.emailVerified).toBe(true);
    const byGoogle = await store.findByGoogleSub('sub-12345');
    expect(byGoogle?.id).toBe(u.id);
  });

  it('createWithPasskey inserts a passkey-only user with no email/password', async () => {
    const store = new PgUserStore(ctx.makePool());
    await store.ensureSchema();
    const u = await store.createWithPasskey();
    expect(u.id).toMatch(/^[0-9a-f]{8}-/);
    expect(u.email).toBeUndefined();
    expect(u.emailVerified).toBe(false);
    expect(u.passwordHash).toBeUndefined();
    expect(u.googleSub).toBeUndefined();
    const found = await store.findById(u.id);
    expect(found?.id).toBe(u.id);
  });

  it('createWithSiwe normalizes EOA lowercase', async () => {
    const store = new PgUserStore(ctx.makePool());
    await store.ensureSchema();
    const u = await store.createWithSiwe({ eoa: '0xAaBbCcDdEeFf0011223344556677889900AaBbCc' });
    expect(u.legacySiweEoa).toBe('0xaabbccddeeff0011223344556677889900aabbcc');
    const byEoa = await store.findBySiweEoa('0xaabbccddeeff0011223344556677889900AAbbcc');
    expect(byEoa?.id).toBe(u.id);
  });

  it('markEmailVerified flips the flag', async () => {
    const store = new PgUserStore(ctx.makePool());
    await store.ensureSchema();
    const u = await store.createWithEmailPassword({
      email: 'dave@example.com',
      passwordHash: '$argon2id$abc',
    });
    expect(u.emailVerified).toBe(false);
    await store.markEmailVerified(u.id);
    const re = await store.findById(u.id);
    expect(re?.emailVerified).toBe(true);
  });

  it('setPrimaryWallet stores lowercase + roundtrips', async () => {
    const store = new PgUserStore(ctx.makePool());
    await store.ensureSchema();
    const u = await store.createWithEmailPassword({
      email: 'eve@example.com',
      passwordHash: '$argon2id$abc',
    });
    await store.setPrimaryWallet(u.id, '0xABCD0000000000000000000000000000000000EF');
    const re = await store.findById(u.id);
    expect(re?.primaryWallet).toBe('0xabcd0000000000000000000000000000000000ef');
  });

  it('linkGoogleSub binds an existing user to a Google account and verifies email', async () => {
    const store = new PgUserStore(ctx.makePool());
    await store.ensureSchema();
    const u = await store.createWithEmailPassword({
      email: 'frank@example.com',
      passwordHash: '$argon2id$abc',
    });
    await store.linkGoogleSub(u.id, 'sub-link-1');
    const re = await store.findById(u.id);
    expect(re?.googleSub).toBe('sub-link-1');
    expect(re?.emailVerified).toBe(true);
  });

  it('rotatePasswordHash updates the hash', async () => {
    const store = new PgUserStore(ctx.makePool());
    await store.ensureSchema();
    const u = await store.createWithEmailPassword({
      email: 'grace@example.com',
      passwordHash: '$argon2id$old',
    });
    await store.rotatePasswordHash(u.id, '$argon2id$new');
    const re = await store.findById(u.id);
    expect(re?.passwordHash).toBe('$argon2id$new');
  });
});
