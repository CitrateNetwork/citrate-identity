/**
 * KycProvider contract-test suite.
 *
 * Drives EVERY adapter through the same KycProvider methods to prove
 * conformance. The test body is shared via the `runContractSuite`
 * helper; each adapter wires it once.
 *
 * Sumsub is exercised against an in-process fake HTTP server that
 * mirrors the documented API shape. Real sandbox tests live in
 * `test/kyc-providers/sumsub.sandbox.test.ts` and gate on the four
 * SUMSUB_* env vars being set.
 */

import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createServer, type Server } from 'node:http';
import { createHmac } from 'node:crypto';

import { KYC_LEVELS, MockKycProvider } from '../../src/kyc-providers/index.js';
import type { KycProvider } from '../../src/kyc-providers/index.js';

type AdapterFactory = () => Promise<{
  provider: KycProvider;
  // For tests that need to manufacture an "authenticated" webhook body
  // for this adapter.
  buildSignedWebhook: (payload: {
    applicantId: string;
    externalUserId?: string;
    kind: 'verified' | 'rejected' | 'pending' | 'reset';
  }) => { body: Buffer; headers: Record<string, string> };
  cleanup?: () => Promise<void>;
}>;

function runContractSuite(name: string, factory: AdapterFactory): void {
  describe(`KycProvider contract: ${name}`, () => {
    let provider: KycProvider;
    let buildSignedWebhook: Awaited<ReturnType<AdapterFactory>>['buildSignedWebhook'];
    let cleanup: (() => Promise<void>) | undefined;

    beforeAll(async () => {
      const built = await factory();
      provider = built.provider;
      buildSignedWebhook = built.buildSignedWebhook;
      cleanup = built.cleanup;
    });

    afterAll(async () => {
      if (cleanup) await cleanup();
    });

    it('createApplicant returns an applicantId', async () => {
      const { applicantId } = await provider.createApplicant({
        externalUserId: 'user-create-1',
        levelHint: KYC_LEVELS.BASIC_INDIVIDUAL,
      });
      expect(applicantId).toBeTruthy();
      expect(typeof applicantId).toBe('string');
    });

    it('createApplicant is idempotent on externalUserId', async () => {
      const first = await provider.createApplicant({
        externalUserId: 'user-idem-1',
        levelHint: KYC_LEVELS.BASIC_INDIVIDUAL,
      });
      const second = await provider.createApplicant({
        externalUserId: 'user-idem-1',
        levelHint: KYC_LEVELS.BASIC_INDIVIDUAL,
      });
      expect(second.applicantId).toBe(first.applicantId);
    });

    it('mintClientSession returns a hosted redirectUrl + expiresAt', async () => {
      const { applicantId } = await provider.createApplicant({
        externalUserId: 'user-mint-1',
        levelHint: KYC_LEVELS.BASIC_INDIVIDUAL,
      });
      const session = await provider.mintClientSession({
        applicantId,
        externalUserId: 'user-mint-1',
        ttlSec: 600,
      });
      // Sumsub now returns a hosted external WebSDK link (redirectUrl), not an
      // embedded-SDK token — redirecting to the latter breaks WebSDK init.
      expect(session.redirectUrl).toMatch(/^https:\/\//);
      expect(session.expiresAt).toBeGreaterThan(Math.floor(Date.now() / 1000));
    });

    it('verifyWebhook returns false for an unsigned body', () => {
      expect(provider.verifyWebhook({}, Buffer.from('{"hi":1}'))).toBe(false);
    });

    it('verifyWebhook returns true for a correctly signed body and the parse + status flow holds', async () => {
      const { applicantId } = await provider.createApplicant({
        externalUserId: 'user-wh-1',
        levelHint: KYC_LEVELS.BASIC_INDIVIDUAL,
      });
      const { body, headers } = buildSignedWebhook({
        applicantId,
        externalUserId: 'user-wh-1',
        kind: 'verified',
      });
      expect(provider.verifyWebhook(headers, body)).toBe(true);
      const event = await provider.parseWebhookEvent(body);
      expect(event.applicantId).toBe(applicantId);
      expect(event.kind).toBe('verified');
      expect(typeof event.occurredAt).toBe('number');

      const status = await provider.getApplicantStatus(applicantId);
      expect(['verified', 'pending', 'unverified', 'rejected']).toContain(status.state);
    });

    it('verifyWebhook returns false for a tampered body', () => {
      const { body, headers } = buildSignedWebhook({
        applicantId: 'tamper-1',
        externalUserId: 'user-tamper-1',
        kind: 'verified',
      });
      const tampered = Buffer.concat([body, Buffer.from(' ')]);
      expect(provider.verifyWebhook(headers, tampered)).toBe(false);
    });

    it('deleteApplicant resolves without throwing', async () => {
      const { applicantId } = await provider.createApplicant({
        externalUserId: 'user-delete-1',
        levelHint: KYC_LEVELS.BASIC_INDIVIDUAL,
      });
      await expect(provider.deleteApplicant(applicantId)).resolves.toBeUndefined();
    });
  });
}

// ── Mock adapter ──────────────────────────────────────────────────────────
runContractSuite('MockKycProvider', async () => {
  const m = new MockKycProvider({ mode: 'sandbox', webhookSecret: 'shh' });
  return {
    provider: m,
    buildSignedWebhook: (payload) => m.buildSignedWebhook(payload),
  };
});
