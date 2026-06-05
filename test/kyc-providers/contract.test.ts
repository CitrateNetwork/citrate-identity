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

import { KYC_LEVELS, MockKycProvider, SumsubKycProvider } from '../../src/kyc-providers/index.js';
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

    it('mintClientSession returns a token + expiresAt', async () => {
      const { applicantId } = await provider.createApplicant({
        externalUserId: 'user-mint-1',
        levelHint: KYC_LEVELS.BASIC_INDIVIDUAL,
      });
      const session = await provider.mintClientSession({
        applicantId,
        externalUserId: 'user-mint-1',
        ttlSec: 600,
      });
      expect(session.token).toBeTruthy();
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

// ── Sumsub adapter (against an in-process fake API server) ────────────────
runContractSuite('SumsubKycProvider', async () => {
  const APP_TOKEN = 'sbx:test-token';
  const SECRET_KEY = 'test-secret';
  const WEBHOOK_SECRET = 'test-webhook-secret';
  const LEVEL_NAME = 'basic-kyc-level';

  // In-process fake of the documented Sumsub REST surface.
  const applicants = new Map<string, { id: string; externalUserId: string; review?: { reviewStatus?: string; reviewResult?: { reviewAnswer?: string } } }>();
  const externalIndex = new Map<string, string>();

  const server: Server = createServer((req, res) => {
    const url = new URL(req.url ?? '', 'http://localhost');
    const path = url.pathname;

    // (Auth is not enforced by the fake; the adapter still computes
    // headers, so we exercise the signing code path without asserting
    // server-side. The real sandbox tests prove auth end-to-end.)

    if (req.method === 'POST' && path === '/resources/applicants') {
      const chunks: Buffer[] = [];
      req.on('data', (c) => chunks.push(c));
      req.on('end', () => {
        const body = JSON.parse(Buffer.concat(chunks).toString('utf8')) as { externalUserId: string };
        if (externalIndex.has(body.externalUserId)) {
          const id = externalIndex.get(body.externalUserId)!;
          res.writeHead(200, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ id }));
          return;
        }
        const id = `app_${applicants.size + 1}`;
        applicants.set(id, { id, externalUserId: body.externalUserId, review: { reviewStatus: 'init' } });
        externalIndex.set(body.externalUserId, id);
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ id }));
      });
      return;
    }

    if (req.method === 'GET' && path.startsWith('/resources/applicants/-;externalUserId=')) {
      const eid = decodeURIComponent(path.replace('/resources/applicants/-;externalUserId=', '').replace('/one', ''));
      const id = externalIndex.get(eid);
      if (!id) {
        res.writeHead(404, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ description: 'not found' }));
        return;
      }
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ id }));
      return;
    }

    if (req.method === 'POST' && path === '/resources/accessTokens/sdk') {
      const chunks: Buffer[] = [];
      req.on('data', (c) => chunks.push(c));
      req.on('end', () => {
        const body = JSON.parse(Buffer.concat(chunks).toString('utf8')) as { userId: string };
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ token: `tok_${body.userId}_${Date.now()}`, userId: body.userId }));
      });
      return;
    }

    if (req.method === 'GET' && /^\/resources\/applicants\/[^/]+\/one$/.test(path)) {
      const id = path.split('/')[3];
      const a = applicants.get(id);
      if (!a) {
        res.writeHead(404, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ description: 'not found' }));
        return;
      }
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ id, review: a.review ?? {} }));
      return;
    }

    if (req.method === 'POST' && /^\/resources\/applicants\/[^/]+\/erase$/.test(path)) {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ok: true }));
      return;
    }

    res.writeHead(404, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ description: 'not found', path }));
  });

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
  const addr = server.address();
  if (!addr || typeof addr === 'string') throw new Error('failed to start fake server');
  const baseUrl = `http://127.0.0.1:${addr.port}`;

  const provider = new SumsubKycProvider({
    mode: 'sandbox',
    appToken: APP_TOKEN,
    secretKey: SECRET_KEY,
    webhookSecret: WEBHOOK_SECRET,
    basicLevelName: LEVEL_NAME,
    baseUrl,
  });

  // For verifyWebhook contract tests we craft a Sumsub-shaped body +
  // x-payload-digest header signed with the WEBHOOK_SECRET. parse needs
  // to map our four-state kind onto Sumsub's type + reviewStatus +
  // reviewAnswer fields.
  function buildSignedWebhook(payload: {
    applicantId: string;
    externalUserId?: string;
    kind: 'verified' | 'rejected' | 'pending' | 'reset';
  }): { body: Buffer; headers: Record<string, string> } {
    const sumsubShape =
      payload.kind === 'verified'
        ? {
            applicantId: payload.applicantId,
            externalUserId: payload.externalUserId,
            type: 'applicantReviewed',
            reviewStatus: 'completed',
            reviewResult: { reviewAnswer: 'GREEN' },
            createdAtMs: Date.now(),
          }
        : payload.kind === 'rejected'
          ? {
              applicantId: payload.applicantId,
              externalUserId: payload.externalUserId,
              type: 'applicantReviewed',
              reviewStatus: 'completed',
              reviewResult: { reviewAnswer: 'RED', reviewRejectType: 'FINAL' },
              createdAtMs: Date.now(),
            }
          : payload.kind === 'reset'
            ? {
                applicantId: payload.applicantId,
                externalUserId: payload.externalUserId,
                type: 'applicantReset',
                createdAtMs: Date.now(),
              }
            : {
                applicantId: payload.applicantId,
                externalUserId: payload.externalUserId,
                type: 'applicantPending',
                reviewStatus: 'pending',
                createdAtMs: Date.now(),
              };
    const body = Buffer.from(JSON.stringify(sumsubShape), 'utf8');
    const digest = createHmac('sha256', WEBHOOK_SECRET).update(body).digest('hex');
    return {
      body,
      headers: {
        'x-payload-digest': digest,
        'x-payload-digest-alg': 'HMAC_SHA256_HEX',
      },
    };
  }

  return {
    provider,
    buildSignedWebhook,
    cleanup: async () =>
      new Promise<void>((resolve) => {
        server.close(() => resolve());
      }),
  };
});
