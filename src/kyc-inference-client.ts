/**
 * VERI inference-service client — the model backends the S3 engine calls (D5).
 *
 * The ISO-30107-3 PAD + 1:1 face-match and OCR models are **self-hosted on US
 * infrastructure** (heavy ONNX inference does not belong inline in the koa
 * authority). This module is the HTTP client that implements the engine's
 * `LivenessAnalyzer` / `DocumentAnalyzer` interfaces by POSTing the (already
 * DEK-decrypted) images to that service and interpreting the result. The service
 * contract lives in `.agentile/compliance/VERI-inference-service.md`.
 *
 * FAIL-CLOSED (Rule 1): if the inference service is unreachable, times out, errors,
 * or returns an unparseable body, the analyzer returns `requiresReview: true` — the
 * engine then routes the case to needs-review (human adjudication). It NEVER
 * fabricates a pass. A clear model verdict (`pass:false` / not-authentic) is a real
 * reject; a service failure is a review — the two are distinguished.
 *
 * The deterministic MRZ check-digit validation runs HERE (see `kyc-mrz.ts`), on the
 * OCR text the service returns, so a misread/tampered document is caught locally.
 */

import { parseMrz } from './kyc-mrz.js';
import { VerificationEngine } from './kyc-engine.js';
import type { DocumentAnalyzer, DocumentResult, LivenessAnalyzer, LivenessResult } from './kyc-engine.js';
import type { InhouseKycProvider } from './kyc-providers/inhouse.js';
import type { SanctionsScreener } from './kyc-screening.js';

export interface InferenceConfig {
  baseUrl: string;
  /** Bearer token shared with the inference service. */
  authToken?: string;
  timeoutMs?: number;
  /** Tamper-score threshold above which a document is not authentic (0..1). */
  tamperThreshold?: number;
}

/** Shape the inference service returns for /v1/liveness. */
interface LivenessResponse {
  pass: boolean;
  confidence: number;
  /** ISO-30107-3 PAD score + face-match cosine similarity, for audit/tuning. */
  padScore?: number;
  matchScore?: number;
  reason?: string;
}
/** Shape the inference service returns for /v1/document. */
interface DocumentResponse {
  mrz?: string[]; // OCR'd MRZ lines
  portraitPresent?: boolean;
  tamperScore?: number; // 0..1
  ocrConfidence?: number; // 0..1
  reason?: string;
}

async function postJson<T>(cfg: InferenceConfig, path: string, body: unknown): Promise<T> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), cfg.timeoutMs ?? 8000);
  try {
    const r = await fetch(`${cfg.baseUrl.replace(/\/+$/, '')}${path}`, {
      method: 'POST',
      signal: ctrl.signal,
      headers: {
        'content-type': 'application/json',
        ...(cfg.authToken ? { authorization: `Bearer ${cfg.authToken}` } : {}),
      },
      body: JSON.stringify(body),
    });
    if (!r.ok) throw new Error(`inference ${path} HTTP ${r.status}`);
    return (await r.json()) as T;
  } finally {
    clearTimeout(t);
  }
}

export class HttpLivenessAnalyzer implements LivenessAnalyzer {
  constructor(private readonly cfg: InferenceConfig) {}
  async analyze(input: { faceImage: Buffer; idPortrait?: Buffer }): Promise<LivenessResult> {
    try {
      const res = await postJson<LivenessResponse>(this.cfg, '/v1/liveness', {
        face: input.faceImage.toString('base64'),
        idPortrait: input.idPortrait ? input.idPortrait.toString('base64') : undefined,
      });
      return {
        pass: res.pass === true,
        confidence: typeof res.confidence === 'number' ? res.confidence : 0,
        reason: res.reason,
      };
    } catch (err) {
      // Service failure → review, never a fabricated pass.
      return { pass: false, confidence: 0, requiresReview: true, reason: `liveness backend unavailable: ${(err as Error).message}` };
    }
  }
}

export class HttpDocumentAnalyzer implements DocumentAnalyzer {
  constructor(private readonly cfg: InferenceConfig) {}
  async analyze(input: { docImage: Buffer }): Promise<DocumentResult> {
    let res: DocumentResponse;
    try {
      res = await postJson<DocumentResponse>(this.cfg, '/v1/document', { image: input.docImage.toString('base64') });
    } catch (err) {
      return { authentic: false, requiresReview: true, reason: `document backend unavailable: ${(err as Error).message}` };
    }
    // OCR gave us MRZ text → validate check digits + expiry LOCALLY (deterministic).
    const mrz = res.mrz && res.mrz.length ? parseMrz(res.mrz) : null;
    if (!mrz) {
      return { authentic: false, requiresReview: true, reason: 'MRZ not read / unparseable' };
    }
    const tamperThreshold = this.cfg.tamperThreshold ?? 0.5;
    const tamperOk = (res.tamperScore ?? 0) < tamperThreshold;
    const portraitOk = res.portraitPresent !== false;
    const lowOcr = (res.ocrConfidence ?? 1) < 0.6;

    const authentic = mrz.valid && mrz.notExpired && tamperOk && portraitOk;
    // HARD fail (unambiguous → engine rejects): expired, or a confident tamper score.
    const hardFail = !mrz.notExpired || !tamperOk;
    // Otherwise, any failure is ambiguous (OCR misread, missing portrait) → review.
    const requiresReview = !authentic && !hardFail;

    const reasons: string[] = [];
    if (!mrz.valid) reasons.push('MRZ check digits failed');
    if (!mrz.notExpired) reasons.push('document expired');
    if (!tamperOk) reasons.push(`tamper score ${res.tamperScore}`);
    if (!portraitOk) reasons.push('no portrait detected');

    return {
      authentic,
      requiresReview,
      reason: reasons.join('; ') || undefined,
      extracted: {
        name: [mrz.givenNames, mrz.surname].filter(Boolean).join(' ').trim() || undefined,
        dob: mrz.birthDate,
        docNumber: mrz.documentNumber,
        nationality: mrz.nationality,
      },
    };
  }
}

/**
 * Build the engine's model analyzers from env. When `KYC_INFERENCE_URL` is set the
 * engine gets the real HTTP-backed analyzers; when it is unset the engine gets none
 * and fails closed to needs-review (no fake pass — Rule 1).
 */
export function inferenceAnalyzersFromEnv(
  env: NodeJS.ProcessEnv = process.env,
): { liveness?: LivenessAnalyzer; document?: DocumentAnalyzer } {
  const baseUrl = env.KYC_INFERENCE_URL?.trim();
  if (!baseUrl) return {};
  const cfg: InferenceConfig = {
    baseUrl,
    authToken: env.KYC_INFERENCE_TOKEN?.trim(),
    timeoutMs: env.KYC_INFERENCE_TIMEOUT_MS ? Number(env.KYC_INFERENCE_TIMEOUT_MS) : undefined,
  };
  return { liveness: new HttpLivenessAnalyzer(cfg), document: new HttpDocumentAnalyzer(cfg) };
}

/**
 * Assemble the verification engine with the real model backends (THE WIRING).
 * `KYC_INFERENCE_URL` set → the engine runs against the self-hosted ONNX inference
 * service; unset → the engine gets no analyzers and fails closed to needs-review
 * (Rule 1). The store + DEK access come from the in-house provider (least privilege).
 */
export function buildVerificationEngine(args: {
  provider: InhouseKycProvider;
  screener: SanctionsScreener;
  webhookSecret: string;
  env?: NodeJS.ProcessEnv;
}): VerificationEngine {
  const { liveness, document } = inferenceAnalyzersFromEnv(args.env);
  return new VerificationEngine({
    store: args.provider.caseStore,
    getDek: (id) => args.provider.getCaseDek(id),
    screener: args.screener,
    webhookSecret: args.webhookSecret,
    liveness,
    document,
  });
}
