import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { checkDigit } from '../src/kyc-mrz.js';
import { newDb } from 'pg-mem';
import { randomBytes } from 'node:crypto';
import {
  HttpDocumentAnalyzer,
  HttpLivenessAnalyzer,
  buildVerificationEngine,
  inferenceAnalyzersFromEnv,
} from '../src/kyc-inference-client.js';
import { KycCaseStore } from '../src/kyc-cases-pg.js';
import { InhouseKycProvider } from '../src/kyc-providers/inhouse.js';
import { loadSanctionsList } from '../src/kyc-screening.js';
import { sealBytes, sealField } from '../src/kyc-crypto.js';

/**
 * VERI model-backend integration — the inference HTTP client, tested against a
 * MOCK inference server (a test fixture, not a prod backend). Proves request/response
 * handling, the local MRZ validation, and FAIL-CLOSED behavior when the service is
 * down. The real service runs the ONNX models on US infra (D5).
 */

/** Build a valid, non-expired TD3 line 2 using the real ICAO check-digit function. */
function validTD3L2(expiry: string): { l1: string; l2: string } {
  const docNum = 'X1234567<';
  const nat = 'GBR';
  const dob = '900101';
  const sex = 'F';
  const personal = ''.padEnd(14, '<');
  const body =
    docNum + checkDigit(docNum) + nat + dob + checkDigit(dob) + sex + expiry + checkDigit(expiry) + personal + checkDigit(personal);
  const composite = checkDigit(body.slice(0, 10) + body.slice(13, 20) + body.slice(21, 43));
  return { l1: 'P<GBRSMITH<<JANE<<<<<<<<<<<<<<<<<<<<<<<<<<<<', l2: body + composite };
}

let server: Server;
let baseUrl: string;
let liveness: Record<string, unknown> = {};
let document: Record<string, unknown> = {};
let status = 200;

beforeAll(async () => {
  server = createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      res.writeHead(status, { 'content-type': 'application/json' });
      res.end(JSON.stringify(req.url?.includes('liveness') ? liveness : document));
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
afterAll(async () => {
  await new Promise<void>((res, rej) => server.close((e) => (e ? rej(e) : res())));
});

describe('HttpLivenessAnalyzer (VERI)', () => {
  const cfg = () => ({ baseUrl });
  it('passes through a positive PAD + match verdict', async () => {
    status = 200; liveness = { pass: true, confidence: 0.98 };
    const r = await new HttpLivenessAnalyzer(cfg()).analyze({ faceImage: Buffer.from('f'), idPortrait: Buffer.from('p') });
    expect(r.pass).toBe(true);
    expect(r.requiresReview).toBeUndefined();
  });
  it('passes through a negative verdict (reject)', async () => {
    status = 200; liveness = { pass: false, confidence: 0.9, reason: 'spoof' };
    const r = await new HttpLivenessAnalyzer(cfg()).analyze({ faceImage: Buffer.from('f') });
    expect(r.pass).toBe(false);
    expect(r.requiresReview).toBeUndefined(); // a real reject, not a review
  });
  it('FAIL-CLOSED: service 500 → requiresReview, never a pass', async () => {
    status = 500; liveness = {};
    const r = await new HttpLivenessAnalyzer(cfg()).analyze({ faceImage: Buffer.from('f') });
    expect(r.pass).toBe(false);
    expect(r.requiresReview).toBe(true);
  });
  it('FAIL-CLOSED: service unreachable → requiresReview', async () => {
    const r = await new HttpLivenessAnalyzer({ baseUrl: 'http://127.0.0.1:1', timeoutMs: 300 }).analyze({ faceImage: Buffer.from('f') });
    expect(r.requiresReview).toBe(true);
  });
});

describe('HttpDocumentAnalyzer (VERI)', () => {
  const cfg = () => ({ baseUrl });
  it('authentic when OCR gives a valid, non-expired MRZ + portrait', async () => {
    const { l1, l2 } = validTD3L2('301231'); // expires 2030
    status = 200; document = { mrz: [l1, l2], portraitPresent: true, tamperScore: 0.05, ocrConfidence: 0.95 };
    const r = await new HttpDocumentAnalyzer(cfg()).analyze({ docImage: Buffer.from('img') });
    expect(r.authentic).toBe(true);
    expect(r.extracted?.docNumber).toBe('X1234567');
    expect(r.extracted?.nationality).toBe('GBR');
  });
  it('REJECT (hard): an expired document', async () => {
    const { l1, l2 } = validTD3L2('100101'); // expired 2010
    status = 200; document = { mrz: [l1, l2], portraitPresent: true, tamperScore: 0.05, ocrConfidence: 0.95 };
    const r = await new HttpDocumentAnalyzer(cfg()).analyze({ docImage: Buffer.from('img') });
    expect(r.authentic).toBe(false);
    expect(r.requiresReview).toBe(false); // expired is a clean reject
  });
  it('REVIEW: unreadable / unparseable MRZ', async () => {
    status = 200; document = { mrz: ['garbage'], portraitPresent: true, ocrConfidence: 0.4 };
    const r = await new HttpDocumentAnalyzer(cfg()).analyze({ docImage: Buffer.from('img') });
    expect(r.authentic).toBe(false);
    expect(r.requiresReview).toBe(true);
  });
  it('FAIL-CLOSED: service unreachable → requiresReview', async () => {
    const r = await new HttpDocumentAnalyzer({ baseUrl: 'http://127.0.0.1:1', timeoutMs: 300 }).analyze({ docImage: Buffer.from('img') });
    expect(r.requiresReview).toBe(true);
  });
});

describe('inferenceAnalyzersFromEnv', () => {
  it('returns analyzers when KYC_INFERENCE_URL is set, none when unset (engine fails closed)', () => {
    expect(inferenceAnalyzersFromEnv({} as NodeJS.ProcessEnv)).toEqual({});
    const a = inferenceAnalyzersFromEnv({ KYC_INFERENCE_URL: 'https://infer.internal' } as NodeJS.ProcessEnv);
    expect(a.liveness).toBeInstanceOf(HttpLivenessAnalyzer);
    expect(a.document).toBeInstanceOf(HttpDocumentAnalyzer);
  });
});

describe('buildVerificationEngine — THE WIRING (provider → engine → inference service)', () => {
  const master = randomBytes(32);
  async function provider(): Promise<{ p: InhouseKycProvider; caseId: string }> {
    const db = newDb();
    const store = new KycCaseStore(new (db.adapters.createPg().Pool)());
    await store.ensureSchema();
    const p = new InhouseKycProvider({ mode: 'sandbox', store, masterKey: master, sessionSecret: 's', webhookSecret: 'wh', captureBaseUrl: 'https://x/verify' });
    const { applicantId } = await p.createApplicant({ externalUserId: 'sub-wire', levelHint: 'basic-individual' });
    const dek = (await p.getCaseDek(applicantId))!;
    await store.setIdentityCiphertext(applicantId, sealField(JSON.stringify({ name: 'Jane Smith', dob: '1990-01-01', nationality: 'GBR' }), dek));
    await store.addEvidence({ caseId: applicantId, kind: 'document', tier: 3, ciphertext: sealBytes(Buffer.from('DOC'), dek) });
    await store.addEvidence({ caseId: applicantId, kind: 'liveness', tier: 2, ciphertext: sealBytes(Buffer.from('FACE'), dek), destroyAfter: Date.now() + 864e5 });
    return { p, caseId: applicantId };
  }

  it('VERIFIED end-to-end when the inference service passes both models', async () => {
    const { l1, l2 } = validTD3L2('301231');
    status = 200; liveness = { pass: true, confidence: 0.98 }; document = { mrz: [l1, l2], portraitPresent: true, tamperScore: 0.05, ocrConfidence: 0.95 };
    const { p, caseId } = await provider();
    const engine = buildVerificationEngine({ provider: p, screener: loadSanctionsList([], 'v0'), webhookSecret: 'wh', env: { KYC_INFERENCE_URL: baseUrl } as NodeJS.ProcessEnv });
    const res = (await engine.runCase(caseId))!;
    expect(res.decision).toBe('verified');
    expect(res.biometricsDestroyed).toBe(1);
  });

  it('FAIL-CLOSED end-to-end: no KYC_INFERENCE_URL → needs-review', async () => {
    const { p, caseId } = await provider();
    const engine = buildVerificationEngine({ provider: p, screener: loadSanctionsList([], 'v0'), webhookSecret: 'wh', env: {} as NodeJS.ProcessEnv });
    const res = (await engine.runCase(caseId))!;
    expect(res.decision).toBe('needs-review');
  });
});
