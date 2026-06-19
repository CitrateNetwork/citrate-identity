/**
 * COMP-S1 — the REAL vendor webhook: POST /kyc/webhook.
 *
 * Unlike /kyc/_set (bearer stand-in), this route verifies the vendor's HMAC over
 * the RAW body via the active KycProvider, decodes the event, and writes the live
 * KycClaim keyed on `externalUserId` (= the OIDC accountId we hand Sumsub at
 * /kyc/start). We drive a real SumsubKycProvider so the HMAC path is exercised.
 */
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { createHmac } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createProvider } from '../src/server.js';
import { getKycStore, setKycStore, InMemoryKycStore, effectiveVerified } from '../src/kyc.js';
import { setKycProvider, SumsubKycProvider } from '../src/kyc-providers/index.js';

const WEBHOOK_SECRET = 'whsec_test_0xfeedface';
const ACCOUNT = '0d1f02f1-1f5a-4f5e-9c2e-7b8d1a2b3c4d'; // a UUID-keyed accountId

let server: Server;
let baseUrl: string;

function sign(body: string): string {
  return createHmac('sha256', WEBHOOK_SECRET).update(Buffer.from(body, 'utf8')).digest('hex');
}

async function postWebhook(body: string, headers: Record<string, string>) {
  return fetch(`${baseUrl}/kyc/webhook`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body,
    redirect: 'manual',
  });
}

beforeAll(async () => {
  setKycStore(new InMemoryKycStore());
  setKycProvider(
    new SumsubKycProvider({
      mode: 'sandbox',
      appToken: 'sbx:test',
      secretKey: 'test-secret',
      webhookSecret: WEBHOOK_SECRET,
      basicLevelName: 'basic-kyc-level',
    }),
  );
  process.env.KYC_PROVIDER = 'sumsub';

  const probe = createServer();
  await new Promise<void>((res) => probe.listen(0, '127.0.0.1', res));
  const { port } = probe.address() as AddressInfo;
  probe.close();
  baseUrl = `http://127.0.0.1:${port}`;
  const provider = await createProvider(baseUrl, { googleEnabled: false });
  server = createServer(provider.callback());
  await new Promise<void>((res) => server.listen(port, '127.0.0.1', res));
});

afterAll(async () => {
  delete process.env.KYC_PROVIDER;
  setKycProvider(undefined);
  await new Promise<void>((res, rej) => server.close((e) => (e ? rej(e) : res())));
});

describe('POST /kyc/webhook (real Sumsub HMAC path)', () => {
  it('writes a verified claim, keyed on externalUserId, on a GREEN applicantReviewed', async () => {
    const body = JSON.stringify({
      applicantId: 'app_123',
      externalUserId: ACCOUNT,
      type: 'applicantReviewed',
      reviewStatus: 'completed',
      reviewResult: { reviewAnswer: 'GREEN' },
      createdAtMs: Date.parse('2026-06-17T00:00:00.000Z'),
    });
    const res = await postWebhook(body, {
      'x-payload-digest': sign(body),
      'x-payload-digest-alg': 'HMAC_SHA256_HEX',
    });
    expect(res.status).toBe(200);
    const claim = await getKycStore().get(ACCOUNT);
    expect(claim?.status).toBe('verified');
    expect(claim?.vendor_ref).toBe('app_123');
    expect(effectiveVerified(claim)).toBe(true);
  });

  it('writes a real ~1y TTL when createdAtMs is a Sumsub DATETIME STRING (regression: 0-TTL bug)', async () => {
    const STR_ACCT = 'acct-string-createdat';
    const body = JSON.stringify({
      applicantId: 'app_str',
      externalUserId: STR_ACCT,
      type: 'applicantReviewed',
      reviewStatus: 'completed',
      reviewResult: { reviewAnswer: 'GREEN' },
      // Sumsub's real shape: a datetime STRING, not epoch ms. Adding the TTL to
      // this used to string-concat and collapse expires_at == verified_at.
      createdAtMs: '2026-06-19 01:32:25.123',
    });
    const res = await postWebhook(body, {
      'x-payload-digest': sign(body),
      'x-payload-digest-alg': 'HMAC_SHA256_HEX',
    });
    expect(res.status).toBe(200);
    const claim = await getKycStore().get(STR_ACCT);
    expect(claim?.status).toBe('verified');
    expect(effectiveVerified(claim)).toBe(true);
    const ttl = Date.parse(claim!.expires_at!) - Date.parse(claim!.verified_at!);
    // ~365 days, NOT 0. Allow a small parse/clock delta.
    expect(ttl).toBeGreaterThan(360 * 24 * 60 * 60 * 1000);
  });

  it('rejects a forged signature with 401 and does not touch the store', async () => {
    const body = JSON.stringify({
      applicantId: 'app_evil',
      externalUserId: 'attacker',
      type: 'applicantReviewed',
      reviewStatus: 'completed',
      reviewResult: { reviewAnswer: 'GREEN' },
    });
    const res = await postWebhook(body, {
      'x-payload-digest': 'deadbeef'.repeat(8),
      'x-payload-digest-alg': 'HMAC_SHA256_HEX',
    });
    expect(res.status).toBe(401);
    expect(await getKycStore().get('attacker')).toBeUndefined();
  });

  it('revokes on a RED review (fail-closed: not verified)', async () => {
    const body = JSON.stringify({
      applicantId: 'app_123',
      externalUserId: ACCOUNT,
      type: 'applicantReviewed',
      reviewStatus: 'completed',
      reviewResult: { reviewAnswer: 'RED' },
    });
    const res = await postWebhook(body, { 'x-payload-digest': sign(body) });
    expect(res.status).toBe(200);
    const claim = await getKycStore().get(ACCOUNT);
    expect(claim?.status).toBe('revoked');
    expect(effectiveVerified(claim)).toBe(false);
  });
});
