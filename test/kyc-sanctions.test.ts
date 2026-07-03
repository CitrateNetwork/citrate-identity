import { describe, it, expect, beforeEach } from 'vitest';
import { parseCsl, getSanctionsScreener, _installForTest } from '../src/kyc-sanctions.js';

// A minimal CSL-shaped CSV: quoted fields, embedded commas, ';'-separated alt_names.
const SAMPLE = `source,entity_number,type,programs,name,alt_names,nationalities
"OFAC - SDN List","1","Individual","SDGT; IFSR","DOE, John","Johnny Doe; J. Doe","Iran"
"BIS Denied Persons List","2","Entity","EAR","ACME EXPORTS, LTD",""," "
"State Department","3","Individual","ISN","Normal Person",""," "
`;

describe('parseCsl', () => {
  it('parses names, ;-split aliases, type, programs, source (order-robust, quoted commas)', () => {
    const entries = parseCsl(SAMPLE);
    expect(entries).toHaveLength(3);
    const john = entries[0];
    expect(john.name).toBe('DOE, John');
    expect(john.aliases).toEqual(['Johnny Doe', 'J. Doe']);
    expect(john.type).toBe('individual');
    expect(john.programs).toEqual(['SDGT', 'IFSR']);
    expect(john.source).toBe('OFAC - SDN List');

    const acme = entries[1];
    expect(acme.name).toBe('ACME EXPORTS, LTD'); // embedded comma survived the quotes
    expect(acme.type).toBe('entity');
    expect(acme.aliases).toBeUndefined();
  });

  it('returns [] on an empty / header-only / malformed feed (fail-safe)', () => {
    expect(parseCsl('')).toEqual([]);
    expect(parseCsl('source,name\n')).toEqual([]);
    expect(parseCsl('nonsense')).toEqual([]);
  });
});

describe('live screener (post-ingest)', () => {
  beforeEach(() => _installForTest(parseCsl(SAMPLE), 'CSL-test'));

  it('flags a name matching a listed person (not clear)', () => {
    const r = getSanctionsScreener().screen({ name: 'John Doe' });
    expect(r.result).not.toBe('clear');
    expect(r.listVersion).toBe('CSL-test');
  });

  it('clears an unrelated honest applicant', () => {
    const r = getSanctionsScreener().screen({ name: 'Marie-Claire Fontaine' });
    expect(r.result).toBe('clear');
  });

  it('routes an embargoed nationality to review even with a clean name', () => {
    const r = getSanctionsScreener().screen({ name: 'Marie-Claire Fontaine', nationality: 'Iran' });
    expect(r.result).toBe('review');
  });
});
