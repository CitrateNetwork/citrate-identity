/**
 * ICAO 9303 Machine-Readable-Zone (MRZ) parser + check-digit validation
 * (VERI model-backend integration, document authenticity — S3-WP2).
 *
 * This is the DETERMINISTIC half of document analysis: given the MRZ text (which the
 * OCR model in the inference service reads off the document image), this validates
 * the cryptographic-ish check digits and extracts the identity fields. It is real,
 * self-contained logic — no ML — so it is fully unit-tested against the ICAO sample
 * vectors. A document whose check digits don't compute is tampered/misread → the
 * document analyzer flags it. The OCR (image → these text lines) is the model step.
 *
 * Supports TD3 (passport, 2×44) and TD1 (ID card, 3×30).
 */

export interface MrzResult {
  format: 'TD3' | 'TD1';
  valid: boolean;
  /** Which check digits passed. */
  checks: Record<string, boolean>;
  documentNumber: string;
  nationality: string;
  birthDate: string; // YYMMDD
  expiryDate: string; // YYMMDD
  sex: string;
  surname: string;
  givenNames: string;
  issuingState: string;
  /** True when the expiry date (best-effort century) is in the future. */
  notExpired: boolean;
}

/** ICAO value of an MRZ character: 0-9 → 0-9, A-Z → 10-35, '<' → 0. */
function charValue(c: string): number {
  if (c >= '0' && c <= '9') return c.charCodeAt(0) - 48;
  if (c >= 'A' && c <= 'Z') return c.charCodeAt(0) - 55;
  return 0; // '<' and anything else
}

/** ICAO 7-3-1 weighted check digit over a field. */
export function checkDigit(field: string): number {
  const weights = [7, 3, 1];
  let sum = 0;
  for (let i = 0; i < field.length; i++) {
    sum += charValue(field[i]) * weights[i % 3];
  }
  return sum % 10;
}

function digitOk(field: string, provided: string): boolean {
  if (!/^[0-9]$/.test(provided)) return false;
  return checkDigit(field) === Number(provided);
}

/** YYMMDD → best-effort full date (windowing: >= 40 → 19xx, else 20xx). */
function toDate(yymmdd: string): Date | null {
  if (!/^[0-9]{6}$/.test(yymmdd)) return null;
  const yy = Number(yymmdd.slice(0, 2));
  const mm = Number(yymmdd.slice(2, 4));
  const dd = Number(yymmdd.slice(4, 6));
  if (mm < 1 || mm > 12 || dd < 1 || dd > 31) return null;
  const year = yy >= 40 ? 1900 + yy : 2000 + yy;
  return new Date(Date.UTC(year, mm - 1, dd));
}

const nameOf = (raw: string): { surname: string; givenNames: string } => {
  const [sur, given = ''] = raw.split('<<');
  const clean = (s: string) => s.replace(/</g, ' ').trim();
  return { surname: clean(sur), givenNames: clean(given) };
};

/** Parse a TD3 passport MRZ (two 44-char lines). */
function parseTD3(l1: string, l2: string, now: Date): MrzResult {
  const issuingState = l1.slice(2, 5).replace(/</g, '');
  const { surname, givenNames } = nameOf(l1.slice(5));

  const documentNumber = l2.slice(0, 9);
  const docCheck = l2[9];
  const nationality = l2.slice(10, 13).replace(/</g, '');
  const birthDate = l2.slice(13, 19);
  const birthCheck = l2[19];
  const sex = l2[20];
  const expiryDate = l2.slice(21, 27);
  const expiryCheck = l2[27];
  const personalNumber = l2.slice(28, 42);
  const personalCheck = l2[42];
  const compositeCheck = l2[43];

  const checks: Record<string, boolean> = {
    documentNumber: digitOk(documentNumber, docCheck),
    birthDate: digitOk(birthDate, birthCheck),
    expiryDate: digitOk(expiryDate, expiryCheck),
    // personal-number check may be '<' (=0) when the field is empty
    personalNumber: digitOk(personalNumber, personalCheck === '<' ? '0' : personalCheck),
    composite: digitOk(
      documentNumber + docCheck + nationality.padEnd(3, '<') + birthDate + birthCheck + sex + expiryDate + expiryCheck + personalNumber + (personalCheck === '<' ? '<' : personalCheck),
      compositeCheck,
    ),
  };
  // Composite over the exact substring of l2 (positions 0..42) is the canonical form:
  checks.composite = digitOk(l2.slice(0, 10) + l2.slice(13, 20) + l2.slice(21, 43), compositeCheck);

  const exp = toDate(expiryDate);
  return {
    format: 'TD3',
    valid: Object.values(checks).every(Boolean),
    checks,
    documentNumber: documentNumber.replace(/</g, ''),
    nationality,
    birthDate,
    expiryDate,
    sex: sex === '<' ? '' : sex,
    surname,
    givenNames,
    issuingState,
    notExpired: exp ? exp.getTime() >= now.getTime() : false,
  };
}

/** Parse a TD1 ID-card MRZ (three 30-char lines). */
function parseTD1(l1: string, l2: string, l3: string, now: Date): MrzResult {
  const issuingState = l1.slice(2, 5).replace(/</g, '');
  const documentNumber = l1.slice(5, 14);
  const docCheck = l1[14];

  const birthDate = l2.slice(0, 6);
  const birthCheck = l2[6];
  const sex = l2[7];
  const expiryDate = l2.slice(8, 14);
  const expiryCheck = l2[14];
  const nationality = l2.slice(15, 18).replace(/</g, '');

  const { surname, givenNames } = nameOf(l3);

  const checks: Record<string, boolean> = {
    documentNumber: digitOk(documentNumber, docCheck),
    birthDate: digitOk(birthDate, birthCheck),
    expiryDate: digitOk(expiryDate, expiryCheck),
    composite: digitOk(l1.slice(5, 30) + l2.slice(0, 7) + l2.slice(8, 15) + l2.slice(18, 29), l2[29]),
  };

  const exp = toDate(expiryDate);
  return {
    format: 'TD1',
    valid: checks.documentNumber && checks.birthDate && checks.expiryDate,
    checks,
    documentNumber: documentNumber.replace(/</g, ''),
    nationality,
    birthDate,
    expiryDate,
    sex: sex === '<' ? '' : sex,
    surname,
    givenNames,
    issuingState,
    notExpired: exp ? exp.getTime() >= now.getTime() : false,
  };
}

/**
 * Parse MRZ text (newline- or array-separated). Detects TD3 (2×44) vs TD1 (3×30).
 * Returns null when the shape isn't a recognized MRZ.
 */
export function parseMrz(text: string | string[], now: Date = new Date()): MrzResult | null {
  const lines = (Array.isArray(text) ? text : text.split(/\r?\n/))
    .map((l) => l.toUpperCase().replace(/[^A-Z0-9<]/g, ''))
    .filter((l) => l.length > 0);
  if (lines.length === 2 && lines[0].length === 44 && lines[1].length === 44) {
    return parseTD3(lines[0], lines[1], now);
  }
  if (lines.length === 3 && lines.every((l) => l.length === 30)) {
    return parseTD1(lines[0], lines[1], lines[2], now);
  }
  return null;
}
