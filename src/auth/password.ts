/**
 * Argon2id password hashing for email + password sign-up (WP-6 of EW-S1).
 *
 * Per `ADR-2026-06-05-ew-auth-methods` §"Library choices": OWASP 2024
 * Argon2id defaults wired through `@node-rs/argon2`.
 *
 *   memory cost: 19 MiB (19456 KiB)
 *   time cost:   2 iterations
 *   parallelism: 1
 *   hash length: 32 bytes (default)
 *
 * These are the OWASP-recommended values for Argon2id (cheat sheet 2024).
 * Adjust by experiment if the host CPU is much faster / slower — keep
 * the resulting hash time around 100ms.
 */

import { Algorithm, hash, verify } from '@node-rs/argon2';

/** Errors from password hashing. */
export class PasswordError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PasswordError';
  }
}

/** OWASP 2024 Argon2id defaults. */
const ARGON2_OPTIONS = {
  algorithm: Algorithm.Argon2id,
  memoryCost: 19456, // 19 MiB
  timeCost: 2,
  parallelism: 1,
} as const;

const MIN_PASSWORD_LENGTH = 8;
const MAX_PASSWORD_LENGTH = 1024;

/**
 * Hash a password with Argon2id. Throws `PasswordError` if the
 * candidate is outside the length bounds (a defence-in-depth check on
 * top of the UI validation).
 */
export async function hashPassword(plaintext: string): Promise<string> {
  if (typeof plaintext !== 'string') {
    throw new PasswordError('password must be a string');
  }
  if (plaintext.length < MIN_PASSWORD_LENGTH) {
    throw new PasswordError(`password must be at least ${MIN_PASSWORD_LENGTH} characters`);
  }
  if (plaintext.length > MAX_PASSWORD_LENGTH) {
    throw new PasswordError(`password must be at most ${MAX_PASSWORD_LENGTH} characters`);
  }
  return hash(plaintext, ARGON2_OPTIONS);
}

/**
 * Verify a password against a stored Argon2id digest. Constant-time
 * inside @node-rs/argon2; returns false on any error rather than
 * throwing, so a malformed stored hash is treated as "wrong password"
 * to a caller that doesn't want to distinguish.
 */
export async function verifyPassword(plaintext: string, storedHash: string): Promise<boolean> {
  if (typeof plaintext !== 'string' || typeof storedHash !== 'string' || storedHash.length === 0) {
    return false;
  }
  try {
    return await verify(storedHash, plaintext);
  } catch {
    return false;
  }
}
