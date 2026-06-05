/**
 * SumsubKycProvider — focused unit tests for the parts the contract
 * suite can't exercise:
 *   - HMAC algorithm coverage (SHA-256 default, SHA-512, SHA-1 legacy).
 *   - Algorithm header rejection (unsupported alg → false, no throw).
 *   - mapSumsubKind() lifecycle decoder.
 *   - resolveLevelName errors for unconfigured levels.
 *   - signed REST call shape (auth headers present + correct signature).
 */

import { describe, expect, it } from 'vitest';
import { createHmac } from 'node:crypto';

import {
  SumsubKycProvider,
  mapSumsubKind,
} from '../../src/kyc-providers/sumsub.js';
import { KYC_LEVELS } from '../../src/kyc-providers/index.js';

const APP_TOKEN = 'sbx:test-token';
const SECRET_KEY = 'test-secret';
const WEBHOOK_SECRET = 'test-webhook-secret';
const BASIC_LEVEL = 'basic-kyc-level';

function build(provider?: Partial<ConstructorParameters<typeof SumsubKycProvider>[0]>) {
  return new SumsubKycProvider({
    mode: 'sandbox',
    appToken: APP_TOKEN,
    secretKey: SECRET_KEY,
    webhookSecret: WEBHOOK_SECRET,
    basicLevelName: BASIC_LEVEL,
    baseUrl: 'http://localhost:1',
    ...provider,
  });
}

describe('SumsubKycProvider.verifyWebhook', () => {
  it('accepts HMAC_SHA256_HEX (default) digests', () => {
    const p = build();
    const body = Buffer.from('{"hello":"world"}');
    const digest = createHmac('sha256', WEBHOOK_SECRET).update(body).digest('hex');
    expect(
      p.verifyWebhook(
        { 'x-payload-digest': digest, 'x-payload-digest-alg': 'HMAC_SHA256_HEX' },
        body,
      ),
    ).toBe(true);
  });

  it('uses HMAC_SHA256_HEX when the alg header is missing (Sumsub default)', () => {
    const p = build();
    const body = Buffer.from('{"hello":"world"}');
    const digest = createHmac('sha256', WEBHOOK_SECRET).update(body).digest('hex');
    expect(p.verifyWebhook({ 'x-payload-digest': digest }, body)).toBe(true);
  });

  it('accepts HMAC_SHA512_HEX digests', () => {
    const p = build();
    const body = Buffer.from('{"hello":"world"}');
    const digest = createHmac('sha512', WEBHOOK_SECRET).update(body).digest('hex');
    expect(
      p.verifyWebhook(
        { 'x-payload-digest': digest, 'x-payload-digest-alg': 'HMAC_SHA512_HEX' },
        body,
      ),
    ).toBe(true);
  });

  it('accepts HMAC_SHA1_HEX (legacy) digests', () => {
    const p = build();
    const body = Buffer.from('{"hello":"world"}');
    const digest = createHmac('sha1', WEBHOOK_SECRET).update(body).digest('hex');
    expect(
      p.verifyWebhook(
        { 'x-payload-digest': digest, 'x-payload-digest-alg': 'HMAC_SHA1_HEX' },
        body,
      ),
    ).toBe(true);
  });

  it('rejects unsupported algorithms without throwing', () => {
    const p = build();
    const body = Buffer.from('{"hello":"world"}');
    const digest = createHmac('sha256', WEBHOOK_SECRET).update(body).digest('hex');
    expect(
      p.verifyWebhook(
        { 'x-payload-digest': digest, 'x-payload-digest-alg': 'HMAC_MD5_HEX' },
        body,
      ),
    ).toBe(false);
  });

  it('returns false on a digest computed with the wrong secret', () => {
    const p = build();
    const body = Buffer.from('{"hello":"world"}');
    const digest = createHmac('sha256', 'wrong-secret').update(body).digest('hex');
    expect(p.verifyWebhook({ 'x-payload-digest': digest }, body)).toBe(false);
  });

  it('returns false when the body is tampered after signing', () => {
    const p = build();
    const original = Buffer.from('{"a":1}');
    const digest = createHmac('sha256', WEBHOOK_SECRET).update(original).digest('hex');
    const tampered = Buffer.from('{"a":2}');
    expect(p.verifyWebhook({ 'x-payload-digest': digest }, tampered)).toBe(false);
  });

  it('returns false when x-payload-digest is missing', () => {
    const p = build();
    expect(p.verifyWebhook({}, Buffer.from('{}'))).toBe(false);
  });
});

describe('SumsubKycProvider — mapSumsubKind lifecycle decoder', () => {
  it('applicantReviewed + completed + GREEN → verified', () => {
    expect(mapSumsubKind('applicantReviewed', 'completed', 'GREEN')).toBe('verified');
  });
  it('applicantReviewed + completed + RED → rejected', () => {
    expect(mapSumsubKind('applicantReviewed', 'completed', 'RED')).toBe('rejected');
  });
  it('applicantReviewed without reviewStatus → pending', () => {
    expect(mapSumsubKind('applicantReviewed', undefined, undefined)).toBe('pending');
  });
  it('applicantReset → reset', () => {
    expect(mapSumsubKind('applicantReset', undefined, undefined)).toBe('reset');
  });
  it('applicantPersonalDataDeleted → reset', () => {
    expect(mapSumsubKind('applicantPersonalDataDeleted', undefined, undefined)).toBe('reset');
  });
  it('applicantPending → pending', () => {
    expect(mapSumsubKind('applicantPending', undefined, undefined)).toBe('pending');
  });
  it('applicantOnHold → pending', () => {
    expect(mapSumsubKind('applicantOnHold', undefined, undefined)).toBe('pending');
  });
  it('unknown event types → pending (fail-safe)', () => {
    expect(mapSumsubKind('applicantNeverSeenBefore', undefined, undefined)).toBe('pending');
  });
});

describe('SumsubKycProvider — level hint resolution', () => {
  it('createApplicant for BASIC_INDIVIDUAL uses the configured level name', async () => {
    let capturedUrl = '';
    const fakeFetch: typeof fetch = (async (url: string | URL | Request, init?: RequestInit) => {
      capturedUrl = String(url);
      // First call is the GET-by-externalUserId (returns 404). Second call is the POST.
      if ((init?.method ?? 'GET') === 'GET') {
        return new Response('{"description":"not found"}', { status: 404 });
      }
      return new Response('{"id":"app_xyz"}', { status: 200 });
    }) as unknown as typeof fetch;

    const p = build({ fetchImpl: fakeFetch });
    const { applicantId } = await p.createApplicant({
      externalUserId: 'u',
      levelHint: KYC_LEVELS.BASIC_INDIVIDUAL,
    });
    expect(applicantId).toBe('app_xyz');
    expect(capturedUrl).toContain(`levelName=${encodeURIComponent(BASIC_LEVEL)}`);
  });

  it('createApplicant for ENHANCED_INDIVIDUAL fails with a clear COMP-S4 error', async () => {
    const p = build();
    await expect(
      p.createApplicant({
        externalUserId: 'u',
        levelHint: KYC_LEVELS.ENHANCED_INDIVIDUAL,
      }),
    ).rejects.toThrow(/COMP-S4/);
  });

  it('createApplicant for KYB_ENTITY fails with a clear COMP-S4 error', async () => {
    const p = build();
    await expect(
      p.createApplicant({
        externalUserId: 'u',
        levelHint: KYC_LEVELS.KYB_ENTITY,
      }),
    ).rejects.toThrow(/COMP-S4/);
  });

  it('createApplicant for an unknown hint fails clearly', async () => {
    const p = build();
    await expect(
      p.createApplicant({ externalUserId: 'u', levelHint: 'not-a-real-level' }),
    ).rejects.toThrow(/unknown levelHint/);
  });
});

describe('SumsubKycProvider — signed REST headers', () => {
  it('includes X-App-Token, X-App-Access-Ts, X-App-Access-Sig and signs over the right input', async () => {
    let captured: { url: string; init: RequestInit } | undefined;
    const fakeFetch: typeof fetch = (async (url: string | URL | Request, init?: RequestInit) => {
      captured = { url: String(url), init: init ?? {} };
      // GET-by-externalUserId 404 → triggers the create
      if ((init?.method ?? 'GET') === 'GET') {
        return new Response('{"description":"not found"}', { status: 404 });
      }
      return new Response('{"id":"app_signed"}', { status: 200 });
    }) as unknown as typeof fetch;

    const p = build({ fetchImpl: fakeFetch });
    await p.createApplicant({
      externalUserId: 'sig-user',
      levelHint: KYC_LEVELS.BASIC_INDIVIDUAL,
    });

    expect(captured).toBeDefined();
    const h = captured!.init.headers as Record<string, string>;
    expect(h['X-App-Token']).toBe(APP_TOKEN);
    expect(h['X-App-Access-Ts']).toMatch(/^\d+$/);
    expect(h['X-App-Access-Sig']).toMatch(/^[a-f0-9]+$/);

    const ts = h['X-App-Access-Ts'];
    const path = `/resources/applicants?levelName=${encodeURIComponent(BASIC_LEVEL)}`;
    const body = captured!.init.body as string;
    const expectedSig = createHmac('sha256', SECRET_KEY)
      .update(ts + 'POST' + path + body, 'utf8')
      .digest('hex');
    expect(h['X-App-Access-Sig']).toBe(expectedSig);
  });
});

describe('SumsubKycProvider — construction', () => {
  it('requires appToken / secretKey / webhookSecret', () => {
    expect(
      () =>
        new SumsubKycProvider({
          mode: 'sandbox',
          appToken: '',
          secretKey: 's',
          webhookSecret: 'w',
          basicLevelName: 'l',
        }),
    ).toThrow(/required/);
  });

  it('requires basicLevelName', () => {
    expect(
      () =>
        new SumsubKycProvider({
          mode: 'sandbox',
          appToken: 't',
          secretKey: 's',
          webhookSecret: 'w',
          basicLevelName: '',
        }),
    ).toThrow(/basicLevelName/);
  });
});
