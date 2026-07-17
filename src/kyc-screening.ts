/**
 * VERI sanctions + export-control screening (VERI-S3-WP3).
 *
 * Rebuilds Track A of `ADR-2026-06-18-ofac-sanctions-screening` in-house (it was the
 * Sumsub AML add-on) per `ADR-2026-07-01-sanctions-screening-inhouse`.
 *
 * DATA SOURCES (Rule 7 — named): production ingests the **OFAC SDN list**
 * (treasury.gov/ofac downloads) + the **trade.gov Consolidated Screening List**
 * (Denied Persons, Entity List, …). `loadSanctionsList` takes the parsed entries +
 * a version stamp; the fetch/parse of the official feeds is a scheduled ingest job
 * (the feeds change multiple times/week) that hands entries to this module. This
 * file is the matcher + adjudication logic, fully offline-testable.
 *
 * EMBARGO (ITAR/EAR + OFAC comprehensive): declared nationality against the
 * comprehensively-embargoed jurisdictions routes to `review` (human adjudication),
 * never an auto-grant. The exact list is confirmed by export-control counsel in the
 * go-live packet (planset O4); the default below is the standard comprehensive set.
 */

export interface SanctionsEntry {
  /** Primary name as listed. */
  name: string;
  /** Also-known-as / alternate spellings. */
  aliases?: string[];
  type: 'individual' | 'entity';
  programs: string[];
  /** Which list this came from (e.g. 'OFAC-SDN', 'CSL-DPL'). */
  source: string;
  /**
   * Secondary identifier for disambiguation (AV-S5). OFAC SDN individual entries often
   * carry a DOB (full or year-only); used to suppress a strong name match whose DOB
   * conflicts (a different person with the same name). Any ISO-ish or year-only form.
   */
  dob?: string;
  /** Listed nationality/citizenship, when present (supporting context, not a discriminator). */
  nationality?: string;
}

export interface SanctionsHit {
  entry: SanctionsEntry;
  /** 0..1 name-similarity score. */
  score: number;
  matchedOn: string;
}

export interface ScreeningResult {
  /** `clear` = no match; `hit` = strong match (block/adjudicate); `review` = weak/embargo. */
  result: 'clear' | 'hit' | 'review';
  hits: SanctionsHit[];
  /** Reason for a `review` that is not a name hit (e.g. embargoed nationality). */
  reviewReason?: string;
  /**
   * Secondary-identifier status of the strongest name hit (AV-S5), when there is one:
   *   `dob-match`    — the listed DOB matches the applicant's → corroborated hit.
   *   `dob-conflict` — the listed DOB conflicts → likely a different person; suppressed to review.
   *   `name-only`    — no comparable DOB → hit stands, but NOT corroborated.
   * Only a `dob-match` (or otherwise corroborated) `hit` is eligible for tier-3
   * auto-reject per ADR-AV-2; `name-only` must route to human review.
   */
  corroboration?: 'dob-match' | 'dob-conflict' | 'name-only';
  listVersion: string;
  screenedAt: number;
}

/** Comprehensive-embargo jurisdictions (default; counsel confirms — planset O4). */
export const DEFAULT_EMBARGOED = new Set(
  ['cuba', 'iran', 'north korea', 'dprk', 'syria', 'crimea', 'donetsk', 'luhansk'].map((s) => s),
);

/** Strong-match threshold (adjudicate as a hit) and weak-match (route to review). */
const HIT_THRESHOLD = 0.87;
const REVIEW_THRESHOLD = 0.72;

/** Normalize a name: lowercase, strip accents + punctuation, collapse whitespace. */
function normalizeName(s: string): string {
  return s
    .normalize('NFKD')
    .replace(/[̀-ͯ]/g, '')
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

/** Sørensen–Dice coefficient over character bigrams of the normalized names. */
export function nameSimilarity(a: string, b: string): number {
  const na = normalizeName(a);
  const nb = normalizeName(b);
  if (!na || !nb) return 0;
  if (na === nb) return 1;
  const bigrams = (s: string): Map<string, number> => {
    const m = new Map<string, number>();
    const compact = s.replace(/\s/g, '');
    for (let i = 0; i < compact.length - 1; i++) {
      const bg = compact.slice(i, i + 2);
      m.set(bg, (m.get(bg) ?? 0) + 1);
    }
    return m;
  };
  const ma = bigrams(na);
  const mb = bigrams(nb);
  if (ma.size === 0 || mb.size === 0) return 0;
  let overlap = 0;
  for (const [bg, count] of ma) {
    const other = mb.get(bg);
    if (other) overlap += Math.min(count, other);
  }
  const total = [...ma.values()].reduce((x, y) => x + y, 0) + [...mb.values()].reduce((x, y) => x + y, 0);
  return (2 * overlap) / total;
}

/** Parse a DOB into {y, m, d} with m/d optional (year-only lists are common). '' → null. */
function parseDob(s?: string): { y: number; m?: number; d?: number } | null {
  if (!s) return null;
  const digits = s.match(/\d+/g);
  if (!digits) return null;
  // Prefer an explicit 4-digit year token; otherwise take the first 4-digit run.
  const year = digits.find((t) => t.length === 4 && Number(t) >= 1900 && Number(t) <= 2100);
  if (!year) return null;
  const rest = digits.filter((t) => t !== year).map(Number);
  // Order-agnostic month/day: the ≤12 value is the month when ambiguous.
  let m: number | undefined;
  let d: number | undefined;
  if (rest.length >= 2) {
    const [a, b] = rest;
    if (a <= 12 && b > 12) { m = a; d = b; }
    else if (b <= 12 && a > 12) { m = b; d = a; }
    else { m = a; d = b; }
  }
  return { y: Number(year), m, d };
}

/**
 * Compare two DOBs for disambiguation (AV-S5). Conservative: only returns 'conflict'
 * when the evidence positively rules the two out as the same person.
 *   - unparseable on either side → 'unknown' (cannot corroborate)
 *   - different years → 'conflict'
 *   - same year, both full dates, different month/day → 'conflict'
 *   - equal (to the precision both provide) → 'match'
 */
export function dobCompare(a?: string, b?: string): 'match' | 'conflict' | 'unknown' {
  const pa = parseDob(a);
  const pb = parseDob(b);
  if (!pa || !pb) return 'unknown';
  if (pa.y !== pb.y) return 'conflict';
  // Same year: compare month/day only when BOTH sides provide them.
  if (pa.m != null && pb.m != null) {
    if (pa.m !== pb.m) return 'conflict';
    if (pa.d != null && pb.d != null && pa.d !== pb.d) return 'conflict';
  }
  return 'match';
}

export class SanctionsScreener {
  constructor(
    private readonly entries: SanctionsEntry[],
    private readonly listVersion: string,
    private readonly embargoed: Set<string> = DEFAULT_EMBARGOED,
  ) {}

  screen(input: { name: string; nationality?: string; dob?: string }, now: number = Date.now()): ScreeningResult {
    const hits: SanctionsHit[] = [];
    for (const entry of this.entries) {
      const candidates = [entry.name, ...(entry.aliases ?? [])];
      let best = 0;
      let bestName = entry.name;
      for (const cand of candidates) {
        const s = nameSimilarity(input.name, cand);
        if (s > best) {
          best = s;
          bestName = cand;
        }
      }
      if (best >= REVIEW_THRESHOLD) hits.push({ entry, score: best, matchedOn: bestName });
    }
    hits.sort((a, b) => b.score - a.score);

    // Embargoed nationality → route to review (adjudication), never auto-grant.
    const nat = input.nationality ? normalizeName(input.nationality) : '';
    const embargoHit = nat && [...this.embargoed].some((e) => nat.includes(e));

    let result: ScreeningResult['result'] = 'clear';
    let reviewReason: string | undefined;
    let corroboration: ScreeningResult['corroboration'];
    const top = hits[0];
    if (top && top.score >= HIT_THRESHOLD) {
      // A strong name match: disambiguate with the DOB secondary identifier (AV-S5).
      const cmp = dobCompare(input.dob, top.entry.dob);
      if (cmp === 'conflict') {
        // Same-ish name, but the DOB rules them out → likely a different person.
        // Suppress the false hit to review rather than block a real member.
        corroboration = 'dob-conflict';
        result = 'review';
        reviewReason = 'strong name match but date of birth conflicts — likely a different person; manual adjudication';
      } else {
        corroboration = cmp === 'match' ? 'dob-match' : 'name-only';
        result = 'hit';
      }
    } else if (hits.length > 0) {
      result = 'review';
      reviewReason = 'weak name match — manual adjudication';
    }
    if (embargoHit && result !== 'hit') {
      result = 'review';
      // Keep a DOB-conflict reason if we already set one; otherwise state the embargo.
      if (corroboration !== 'dob-conflict') {
        reviewReason = `declared nationality in an embargoed jurisdiction (${input.nationality})`;
      }
    }

    return { result, hits, reviewReason, corroboration, listVersion: this.listVersion, screenedAt: now };
  }
}

/** Build a screener from ingested entries + a version stamp (from the ingest job). */
export function loadSanctionsList(entries: SanctionsEntry[], listVersion: string): SanctionsScreener {
  return new SanctionsScreener(entries, listVersion);
}
