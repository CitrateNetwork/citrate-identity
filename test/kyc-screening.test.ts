import { describe, expect, it } from 'vitest';
import { SanctionsScreener, loadSanctionsList, nameSimilarity, type SanctionsEntry } from '../src/kyc-screening.js';

/** VERI-S3-WP3 — in-house sanctions/export screening. */
const LIST: SanctionsEntry[] = [
  { name: 'Vladimir Ivanov', aliases: ['V. Ivanov'], type: 'individual', programs: ['UKRAINE-EO13662'], source: 'OFAC-SDN' },
  { name: 'Acme Weapons Trading LLC', type: 'entity', programs: ['NPWMD'], source: 'CSL-EL' },
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
