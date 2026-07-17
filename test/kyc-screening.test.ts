import { describe, expect, it } from 'vitest';
import { SanctionsScreener, loadSanctionsList, nameSimilarity, type SanctionsEntry } from '../src/kyc-screening.js';

/** VERI-S3-WP3 — in-house sanctions/export screening. */
const LIST: SanctionsEntry[] = [
  { name: 'Vladimir Ivanov', aliases: ['V. Ivanov'], type: 'individual', programs: ['UKRAINE-EO13662'], source: 'OFAC-SDN' },
  { name: 'Acme Weapons Trading LLC', type: 'entity', programs: ['NPWMD'], source: 'CSL-EL' },
  // AV-S5: carries a secondary identifier (DOB) for disambiguation.
  { name: 'Boris Petrov', dob: '1975-03-12', type: 'individual', programs: ['UKRAINE-EO13662'], source: 'OFAC-SDN' },
];

describe('nameSimilarity (Dice bigrams)', () => {
  it('scores identical names 1 and unrelated names low', () => {
    expect(nameSimilarity('Vladimir Ivanov', 'Vladimir Ivanov')).toBe(1);
    expect(nameSimilarity('Vladimir Ivanov', 'Ada Lovelace')).toBeLessThan(0.3);
  });
  it('is robust to case/punctuation/accents', () => {
    expect(nameSimilarity('José García', 'jose garcia')).toBeGreaterThan(0.9);
  });
});

describe('SanctionsScreener (VERI-S3)', () => {
  const screener = loadSanctionsList(LIST, '2026-07-01');

  it('a clean identity screens CLEAR', () => {
    const r = screener.screen({ name: 'Ada Lovelace', nationality: 'United Kingdom' });
    expect(r.result).toBe('clear');
    expect(r.hits).toHaveLength(0);
    expect(r.listVersion).toBe('2026-07-01');
  });

  it('a known sanctioned name is a HIT', () => {
    const r = screener.screen({ name: 'Vladimir Ivanov', nationality: 'Russia' });
    expect(r.result).toBe('hit');
    expect(r.hits[0].entry.source).toBe('OFAC-SDN');
    expect(r.hits[0].score).toBeGreaterThanOrEqual(0.87);
  });

  it('a near-miss name (typo-evasion) is FLAGGED, never cleared', () => {
    const r = screener.screen({ name: 'Vladimir Ivano', nationality: 'Kazakhstan' }); // one char off
    expect(r.result).not.toBe('clear'); // hit (strong) — caught, not evaded
    expect(r.hits.length).toBeGreaterThan(0);
  });

  it('an embargoed nationality routes to REVIEW even with a clean name', () => {
    const r = screener.screen({ name: 'Ada Lovelace', nationality: 'Iran' });
    expect(r.result).toBe('review');
    expect(r.reviewReason).toMatch(/embargoed/i);
  });

  it('an entity name matches the entity list', () => {
    const r = screener.screen({ name: 'ACME Weapons Trading LLC' });
    expect(r.result).toBe('hit');
    expect(r.hits[0].entry.type).toBe('entity');
  });
});

describe('secondary-identifier disambiguation (AV-S5)', () => {
  const screener = loadSanctionsList(LIST, '2026-07-01');

  it('DOB conflict suppresses a false hit: same name, different DOB → REVIEW, not HIT', () => {
    // A different Boris Petrov (born 1990, not 1975) must not be auto-treated as the SDN person.
    const r = screener.screen({ name: 'Boris Petrov', dob: '1990-08-20', nationality: 'Bulgaria' });
    expect(r.result).toBe('review');
    expect(r.corroboration).toBe('dob-conflict');
    expect(r.reviewReason).toMatch(/date of birth|dob/i);
  });

  it('DOB match corroborates a hit: same name AND same DOB → HIT, dob-match', () => {
    const r = screener.screen({ name: 'Boris Petrov', dob: '1975-03-12', nationality: 'Russia' });
    expect(r.result).toBe('hit');
    expect(r.corroboration).toBe('dob-match');
  });

  it('name-only hit (no comparable DOB supplied) stays HIT but is marked name-only, not auto-rejectable', () => {
    const r = screener.screen({ name: 'Boris Petrov', nationality: 'Russia' }); // no DOB provided
    expect(r.result).toBe('hit');
    expect(r.corroboration).toBe('name-only');
  });

  it('DOB does not affect a clean identity', () => {
    const r = screener.screen({ name: 'Ada Lovelace', dob: '1815-12-10' });
    expect(r.result).toBe('clear');
    expect(r.corroboration).toBeUndefined();
  });
});
