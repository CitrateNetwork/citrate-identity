import { describe, expect, it } from 'vitest';
import { randomBytes } from 'node:crypto';
import {
  KycCryptoError,
  blindIndex,
  masterKeyFromEnv,
  newDek,
  openField,
  safeEqual,
  sealField,
  unwrapDek,
  wrapDek,
} from '../src/kyc-crypto.js';

/**
 * VERI-S1-WP2 — server-blind envelope crypto.
 * Proves the two-layer envelope (per-case DEK sealed data, master-wrapped DEK)
 * and the load-bearing invariant: without the master key, a DB/blob row yields
 * nothing. Backs ADR-2026-07-01-kyc-data-controller-reversal.
 */
function master(): Buffer {
  return randomBytes(32);
}

describe('kyc-crypto envelope (VERI-S1)', () => {
  it('seals + opens a field under a case DEK (round-trip)', () => {
    const dek = newDek();
    const ct = sealField('Ada Lovelace, DOB 1815-12-10', dek);
    expect(ct).not.toContain('Ada');
    expect(openField(ct, dek)).toBe('Ada Lovelace, DOB 1815-12-10');
  });

  it('wraps + unwraps a DEK under the master key', () => {
    const m = master();
    const dek = newDek();
    const wrapped = wrapDek(dek, m);
    expect(unwrapDek(wrapped, m).equals(dek)).toBe(true);
  });

  it('SERVER-BLIND: a stored { wrapped_dek, ciphertext } cannot be read without the master key', () => {
    const m = master();
    const dek = newDek();
    // What the DB/blob store actually holds:
    const wrapped_dek = wrapDek(dek, m);
    const ciphertext = sealField('passport A1234567', dek);

    // Attacker with the row but NOT the master key:
    const wrongMaster = randomBytes(32);
    expect(() => unwrapDek(wrapped_dek, wrongMaster)).toThrow(KycCryptoError);

    // And the ciphertext is useless without the (unwrappable) DEK:
    const wrongDek = newDek();
    expect(() => openField(ciphertext, wrongDek)).toThrow(KycCryptoError);

    // Legitimate holder of the master recovers everything:
    const recoveredDek = unwrapDek(wrapped_dek, m);
    expect(openField(ciphertext, recoveredDek)).toBe('passport A1234567');
  });

  it('tampered ciphertext fails closed (GCM auth)', () => {
    const dek = newDek();
    const ct = sealField('sensitive', dek);
    const buf = Buffer.from(ct, 'base64');
    buf[buf.length - 1] ^= 0xff; // flip a ciphertext byte
    expect(() => openField(buf.toString('base64'), dek)).toThrow(KycCryptoError);
  });

  it('empty string round-trips to empty (no envelope overhead for blank fields)', () => {
    const dek = newDek();
    expect(sealField('', dek)).toBe('');
    expect(openField('', dek)).toBe('');
  });

  it('blindIndex is deterministic + normalized, and hides the value', () => {
    const m = master();
    const a = blindIndex('  A1234567 ', m);
    const b = blindIndex('a1234567', m);
    expect(a).toBe(b); // trim + lowercase normalized
    expect(a).not.toContain('1234567');
    expect(blindIndex('a1234567', randomBytes(32))).not.toBe(a); // keyed
  });

  it('rejects wrong-length keys (fail-closed)', () => {
    expect(() => wrapDek(Buffer.alloc(16), master())).toThrow(KycCryptoError);
    expect(() => sealField('x', Buffer.alloc(31))).toThrow(KycCryptoError);
  });

  it('masterKeyFromEnv validates presence + length', () => {
    expect(() => masterKeyFromEnv({} as NodeJS.ProcessEnv)).toThrow(/KYC_MASTER_KEY is unset/);
    expect(() =>
      masterKeyFromEnv({ KYC_MASTER_KEY: Buffer.alloc(16).toString('base64') } as NodeJS.ProcessEnv),
    ).toThrow(/32 bytes/);
    const good = randomBytes(32).toString('base64');
    expect(masterKeyFromEnv({ KYC_MASTER_KEY: good } as NodeJS.ProcessEnv).length).toBe(32);
  });

  it('safeEqual is length-safe', () => {
    expect(safeEqual('abc', 'abc')).toBe(true);
    expect(safeEqual('abc', 'abd')).toBe(false);
    expect(safeEqual('abc', 'abcd')).toBe(false);
  });
});
