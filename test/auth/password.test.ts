import { describe, it, expect } from 'vitest';
import {
  hashPassword,
  verifyPassword,
  PasswordError,
} from '../../src/auth/password.js';

describe('hashPassword', () => {
  it('produces an Argon2id-shaped hash string', async () => {
    const hash = await hashPassword('correct horse battery staple');
    expect(hash).toMatch(/^\$argon2id\$/);
  });

  it('produces different hashes for the same input (random salt)', async () => {
    const h1 = await hashPassword('correct horse battery staple');
    const h2 = await hashPassword('correct horse battery staple');
    expect(h1).not.toBe(h2);
  });

  it('rejects strings shorter than 8 characters', async () => {
    await expect(hashPassword('a'.repeat(7))).rejects.toThrow(PasswordError);
  });

  it('rejects strings longer than the upper bound', async () => {
    await expect(hashPassword('a'.repeat(1025))).rejects.toThrow(PasswordError);
  });

  it('rejects non-string input via type-safety + runtime guard', async () => {
    // @ts-expect-error — runtime guard test
    await expect(hashPassword(undefined)).rejects.toThrow(PasswordError);
    // @ts-expect-error — runtime guard test
    await expect(hashPassword(12345)).rejects.toThrow(PasswordError);
  });
});

describe('verifyPassword', () => {
  it('returns true for the right password', async () => {
    const hash = await hashPassword('correct horse battery staple');
    const ok = await verifyPassword('correct horse battery staple', hash);
    expect(ok).toBe(true);
  });

  it('returns false for the wrong password', async () => {
    const hash = await hashPassword('correct horse battery staple');
    const ok = await verifyPassword('wrong horse battery staple', hash);
    expect(ok).toBe(false);
  });

  it('returns false for a malformed stored hash without throwing', async () => {
    const ok = await verifyPassword('anything', 'not-a-valid-argon2-hash');
    expect(ok).toBe(false);
  });

  it('returns false for empty inputs', async () => {
    expect(await verifyPassword('', 'some-hash')).toBe(false);
    expect(await verifyPassword('password', '')).toBe(false);
  });
});
