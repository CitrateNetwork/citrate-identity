/**
 * VERI server-blind envelope crypto (VERI-S1-WP2).
 *
 * Implements the encryption primitives that make the in-house KYC case store
 * (`kyc-cases-pg.ts`) server-blind, per
 * `citrate-federation/.agentile/adrs/ADR-2026-07-01-kyc-data-controller-reversal.md`.
 *
 * MODEL (two-layer envelope):
 *   - Each verification case gets a random 256-bit **data encryption key (DEK)**.
 *   - Every PII/evidence field is sealed with the case DEK (AES-256-GCM).
 *   - The DEK itself is **wrapped** by the **master key** (AES-256-GCM) and stored
 *     next to the ciphertext. The master key (`KYC_MASTER_KEY`) is held separately
 *     (KMS / dual-control — see planset O7); the DB/blob store never holds it.
 *
 * SERVER-BLIND GUARANTEE (what a DB/blob exfil yields):
 *   Only `{ wrapped_dek, ciphertext }`. Without the master key the DEK cannot be
 *   unwrapped and no field can be opened. Proven by
 *   `test/kyc-crypto.test.ts` ("decryption fails without the master key").
 *
 * In S1 the sealing happens server-side (the master is in env). The stronger
 * "client seals before upload, server never sees the DEK in the clear" step is
 * VERI-S2 (the capture UI); this module is the store-side half it plugs into. The
 * layering is identical either way — only *who* holds the DEK at seal time changes.
 *
 * Envelope layout (base64):  [ 1-byte version | 12-byte iv | 16-byte tag | ct ].
 * Same wire format as citrate-landing `src/lib/encryption.ts`, so a future unified
 * crypto package can absorb both.
 */

import {
  createCipheriv,
  createDecipheriv,
  createHmac,
  randomBytes,
  timingSafeEqual,
} from 'node:crypto';

const ALG = 'aes-256-gcm';
const IV_LEN = 12;
const TAG_LEN = 16;
const KEY_LEN = 32;
const VERSION = 1;

/** Thrown on any crypto misconfiguration or authentication failure. Fail-closed. */
export class KycCryptoError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'KycCryptoError';
  }
}

/**
 * Load + validate the master key from env (default `KYC_MASTER_KEY`, 32 raw bytes
 * base64-encoded). Throws if unset or the wrong length — callers treat this as a
 * fail-closed boot error (mirrors `assertProductionConfig`).
 */
export function masterKeyFromEnv(env: NodeJS.ProcessEnv = process.env): Buffer {
  const raw = env.KYC_MASTER_KEY?.trim();
  if (!raw) {
    throw new KycCryptoError(
      'KYC_MASTER_KEY is unset. It must be 32 random bytes, base64-encoded ' +
        "(e.g. `openssl rand -base64 32`). The in-house KYC store won't seal PII without it.",
    );
  }
  return assertKey(Buffer.from(raw, 'base64'), 'KYC_MASTER_KEY');
}

function assertKey(key: Buffer, label: string): Buffer {
  if (key.length !== KEY_LEN) {
    throw new KycCryptoError(
      `${label} must decode to exactly ${KEY_LEN} bytes (256-bit AES key); got ${key.length}.`,
    );
  }
  return key;
}

/** A fresh random 256-bit data-encryption key for one case. */
export function newDek(): Buffer {
  return randomBytes(KEY_LEN);
}

/** AES-256-GCM seal of `plaintext` under `key`. Returns the base64 envelope. */
function seal(plaintext: string, key: Buffer): string {
  if (plaintext === '') return '';
  const iv = randomBytes(IV_LEN);
  const cipher = createCipheriv(ALG, key, iv);
  const enc = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([Buffer.from([VERSION]), iv, tag, enc]).toString('base64');
}

/** AES-256-GCM open of a base64 envelope under `key`. Throws on tamper/wrong key. */
function open(payload: string, key: Buffer): string {
  if (payload === '') return '';
  const buf = Buffer.from(payload, 'base64');
  if (buf.length < 1 + IV_LEN + TAG_LEN) {
    throw new KycCryptoError('ciphertext too short / malformed');
  }
  const iv = buf.subarray(1, 1 + IV_LEN);
  const tag = buf.subarray(1 + IV_LEN, 1 + IV_LEN + TAG_LEN);
  const enc = buf.subarray(1 + IV_LEN + TAG_LEN);
  const decipher = createDecipheriv(ALG, key, iv);
  decipher.setAuthTag(tag);
  try {
    return Buffer.concat([decipher.update(enc), decipher.final()]).toString('utf8');
  } catch {
    // GCM auth failure (wrong key or tampered ciphertext) — never leak which.
    throw new KycCryptoError('decryption failed (wrong key or tampered ciphertext)');
  }
}

/** Wrap a case DEK under the master key for at-rest storage. */
export function wrapDek(dek: Buffer, master: Buffer): string {
  assertKey(dek, 'DEK');
  assertKey(master, 'master');
  // A raw 32-byte key isn't valid UTF-8; carry it as base64 through the seal.
  return seal(dek.toString('base64'), master);
}

/** Unwrap a stored DEK under the master key. Throws if the master is wrong. */
export function unwrapDek(wrapped: string, master: Buffer): Buffer {
  assertKey(master, 'master');
  const dek = Buffer.from(open(wrapped, master), 'base64');
  return assertKey(dek, 'unwrapped DEK');
}

/** Seal one PII/evidence field under a case DEK. */
export function sealField(plaintext: string, dek: Buffer): string {
  assertKey(dek, 'DEK');
  return seal(plaintext, dek);
}

/** Open one field under a case DEK. */
export function openField(ciphertext: string, dek: Buffer): string {
  assertKey(dek, 'DEK');
  return open(ciphertext, dek);
}

/**
 * Byte-oriented seal/open for BINARY artifacts (ID images, face frames). Same
 * envelope format as {@link sealField}; the browser's WebCrypto sealer emits this
 * exact layout, so `openBytes` recovers the original image bytes. Use these (not
 * the string variants) for anything that is not valid UTF-8 text.
 */
export function sealBytes(plaintext: Buffer, dek: Buffer): string {
  assertKey(dek, 'DEK');
  if (plaintext.length === 0) return '';
  const iv = randomBytes(IV_LEN);
  const cipher = createCipheriv(ALG, dek, iv);
  const enc = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([Buffer.from([VERSION]), iv, tag, enc]).toString('base64');
}

export function openBytes(ciphertext: string, dek: Buffer): Buffer {
  assertKey(dek, 'DEK');
  if (ciphertext === '') return Buffer.alloc(0);
  const buf = Buffer.from(ciphertext, 'base64');
  if (buf.length < 1 + IV_LEN + TAG_LEN) throw new KycCryptoError('ciphertext too short / malformed');
  const iv = buf.subarray(1, 1 + IV_LEN);
  const tag = buf.subarray(1 + IV_LEN, 1 + IV_LEN + TAG_LEN);
  const enc = buf.subarray(1 + IV_LEN + TAG_LEN);
  const decipher = createDecipheriv(ALG, dek, iv);
  decipher.setAuthTag(tag);
  try {
    return Buffer.concat([decipher.update(enc), decipher.final()]);
  } catch {
    throw new KycCryptoError('decryption failed (wrong key or tampered ciphertext)');
  }
}

/**
 * Deterministic keyed lookup index (HMAC-SHA256 under the master key) so we can
 * find a case by e.g. a document-number hash WITHOUT storing the value. Not a
 * password hash; do not use for auth. Trim+lowercase-normalized like landing's.
 */
export function blindIndex(value: string, master: Buffer): string {
  assertKey(master, 'master');
  return createHmac('sha256', master)
    .update(Buffer.from(value.trim().toLowerCase(), 'utf8'))
    .digest('base64url');
}

/** Constant-time string compare (webhook/session secrets). */
export function safeEqual(a: string, b: string): boolean {
  const A = Buffer.from(a);
  const B = Buffer.from(b);
  if (A.length !== B.length) return false;
  return timingSafeEqual(A, B);
}
