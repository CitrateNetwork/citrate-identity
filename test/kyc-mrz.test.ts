import { describe, expect, it } from 'vitest';
import { checkDigit, parseMrz } from '../src/kyc-mrz.js';

/**
 * VERI model-backend integration — MRZ parser + ICAO check digits.
 * Uses the canonical ICAO 9303 TD3 specimen (UTOPIA / ANNA MARIA ERIKSSON).
 */
const TD3_L1 = 'P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<';
const TD3_L2 = 'L898902C36UTO7408122F1204159ZE184226B<<<<<10';

describe('MRZ check digits (ICAO 7-3-1)', () => {
  it('computes the documented specimen digits', () => {
    expect(checkDigit('L898902C3')).toBe(6); // passport number
    expect(checkDigit('740812')).toBe(2); // date of birth
    expect(checkDigit('120415')).toBe(9); // expiry
  });
});

describe('parseMrz TD3 (VERI)', () => {
  it('parses + validates the ICAO specimen', () => {
    const r = parseMrz([TD3_L1, TD3_L2], new Date('2010-01-01'))!;
    expect(r.format).toBe('TD3');
    expect(r.documentNumber).toBe('L898902C3');
    expect(r.nationality).toBe('UTO');
    expect(r.birthDate).toBe('740812');
    expect(r.expiryDate).toBe('120415');
    expect(r.sex).toBe('F');
    expect(r.surname).toBe('ERIKSSON');
    expect(r.givenNames).toBe('ANNA MARIA');
    expect(r.checks.documentNumber).toBe(true);
    expect(r.checks.birthDate).toBe(true);
    expect(r.checks.expiryDate).toBe(true);
    expect(r.valid).toBe(true);
    expect(r.notExpired).toBe(true); // expiry 2012 > 2010
  });

  it('DETECTS a tampered document number (check digit no longer computes)', () => {
    const tampered = 'L898902C96UTO7408122F1204159ZE184226B<<<<<10'; // C3 → C9
    const r = parseMrz([TD3_L1, tampered])!;
    expect(r.checks.documentNumber).toBe(false);
    expect(r.valid).toBe(false);
  });

  it('flags an expired document', () => {
    const r = parseMrz([TD3_L1, TD3_L2], new Date('2026-01-01'))!;
    expect(r.notExpired).toBe(false); // expiry 2012-04-15 is in the past
  });

  it('returns null for non-MRZ / wrong-shape input', () => {
    expect(parseMrz('not an mrz')).toBeNull();
    expect(parseMrz([TD3_L1])).toBeNull(); // only one line
  });
});
