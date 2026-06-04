import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { privateKeyToAccount } from 'viem/accounts';
import { getAddress, parseSignature, serializeSignature, type Hex } from 'viem';
import { SiweMessage } from 'siwe';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import { createProvider } from '../src/server.js';
import {
  CITRATE_CHAIN_ID,
  InMemoryNonceStore,
  SiweVerificationError,
  verifySiweLogin,
} from '../src/siwe.js';

/**
 * IDP-S1.5 — SIWE (EIP-4361) login.
 *   gtm-spine/features/IDP-S1.5-siwe-login.feature
 *
 * A test EOA is generated with viem; it signs a real EIP-4361 message. The
 * authority is mounted on an ephemeral port so `/siwe/challenge` + `/siwe/verify`
 * and discovery are exercised over real HTTP.
 */

let server: Server;
let baseUrl: string;
let host: string;
const account = privateKeyToAccount(`0x${'a1'.repeat(32)}` as Hex);

beforeAll(async () => {
  const probe = createServer();
  await new Promise<void>((res) => probe.listen(0, '127.0.0.1', res));
  const { port } = probe.address() as AddressInfo;
  probe.close();

  baseUrl = `http://127.0.0.1:${port}`;
  host = `127.0.0.1:${port}`;
  const provider = await createProvider(baseUrl);
  server = createServer(provider.callback());
  await new Promise<void>((res) => server.listen(port, '127.0.0.1', res));
});

afterAll(async () => {
  await new Promise<void>((res, rej) =>
    server.close((err) => (err ? rej(err) : res())),
  );
});

async function getChallenge(): Promise<string> {
  const res = await fetch(`${baseUrl}/siwe/challenge`);
  expect(res.status).toBe(200);
  const body = (await res.json()) as { nonce: string };
  expect(typeof body.nonce).toBe('string');
  expect(body.nonce.length).toBeGreaterThanOrEqual(8);
  return body.nonce;
}

function buildMessage(opts: {
  nonce: string;
  domain?: string;
  chainId?: number;
  expirationTime?: string;
}): SiweMessage {
  return new SiweMessage({
    domain: opts.domain ?? host,
    address: account.address,
    statement: 'Sign in to Citrate',
    uri: baseUrl,
    version: '1',
    chainId: opts.chainId ?? CITRATE_CHAIN_ID,
    nonce: opts.nonce,
    issuedAt: new Date().toISOString(),
    expirationTime: opts.expirationTime,
  });
}

async function signMessage(siwe: SiweMessage): Promise<{ message: string; signature: string }> {
  const message = siwe.prepareMessage();
  const signature = await account.signMessage({ message });
  return { message, signature };
}

async function postVerify(body: {
  message: string;
  signature: string;
}): Promise<{ status: number; json: any }> {
  const res = await fetch(`${baseUrl}/siwe/verify`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  return { status: res.status, json: await res.json() };
}

describe('SIWE login (IDP-S1.5)', () => {
  it('a fresh nonce challenge then a verified signature issues a token with wallet_address', async () => {
    const nonce = await getChallenge();
    const { message, signature } = await signMessage(buildMessage({ nonce }));

    const { status, json } = await postVerify({ message, signature });
    expect(status).toBe(200);
    // Signature recovers the claimed address (EIP-55 checksummed).
    expect(json.address).toBe(account.address);
    expect(json.method).toBe('eoa');
    expect(json.wallet_address).toBe(account.address);

    // A real OIDC ID token signed by the authority JWKS is returned and
    // verifies against the published /jwks with iss + wallet_address claim.
    expect(typeof json.id_token).toBe('string');
    const jwks = createRemoteJWKSet(new URL(`${baseUrl}/jwks`));
    const { payload } = await jwtVerify(json.id_token, jwks, {
      issuer: baseUrl,
      audience: 'citrate-explorer',
    });
    expect(payload.sub).toBe(account.address);
    expect(payload.wallet_address).toBe(account.address);
  });

  it('rejects replay of a used nonce', async () => {
    const nonce = await getChallenge();
    const { message, signature } = await signMessage(buildMessage({ nonce }));

    const first = await postVerify({ message, signature });
    expect(first.status).toBe(200);

    // Same message + signature again → nonce already consumed.
    const replay = await postVerify({ message, signature });
    expect(replay.status).toBe(401);
    expect(replay.json.reason).toBe('unknown_nonce');
  });

  it('rejects an unknown / never-issued nonce', async () => {
    // Valid-looking nonce that the authority never issued.
    const { message, signature } = await signMessage(
      buildMessage({ nonce: 'deadbeefdeadbeef0000' }),
    );
    const { status, json } = await postVerify({ message, signature });
    expect(status).toBe(401);
    expect(json.reason).toBe('unknown_nonce');
  });

  it('rejects a message whose domain is not the authority (anti-phishing)', async () => {
    const nonce = await getChallenge();
    const { message, signature } = await signMessage(
      buildMessage({ nonce, domain: 'evil-phisher.example' }),
    );
    const { status, json } = await postVerify({ message, signature });
    expect(status).toBe(401);
    expect(json.reason).toBe('domain_mismatch');
  });

  it('rejects an expired message', async () => {
    const nonce = await getChallenge();
    const { message, signature } = await signMessage(
      buildMessage({
        nonce,
        expirationTime: new Date(Date.now() - 60_000).toISOString(),
      }),
    );
    const { status, json } = await postVerify({ message, signature });
    expect(status).toBe(401);
    expect(json.reason).toBe('expired');
  });

  it('rejects a message bound to the wrong chain', async () => {
    const nonce = await getChallenge();
    const { message, signature } = await signMessage(
      buildMessage({ nonce, chainId: 1 }), // Ethereum mainnet, not Citrate
    );
    const { status, json } = await postVerify({ message, signature });
    expect(status).toBe(401);
    expect(json.reason).toBe('wrong_chain');
  });
});

describe('SIWE verification core (unit)', () => {
  it('rejects a high-S (malleable) signature', async () => {
    const store = new InMemoryNonceStore();
    const nonce = store.issue();
    const siwe = new SiweMessage({
      domain: 'auth.citrate.ai',
      address: account.address,
      uri: 'https://auth.citrate.ai',
      version: '1',
      chainId: CITRATE_CHAIN_ID,
      nonce,
    });
    const message = siwe.prepareMessage();
    const lowS = await account.signMessage({ message });

    // Flip to the high-S twin: s' = N - s, v flipped.
    const { r, s, v } = parseSignature(lowS);
    const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
    const highSValue = N - BigInt(s);
    const highS = serializeSignature({
      r,
      s: `0x${highSValue.toString(16).padStart(64, '0')}` as Hex,
      v: v === 27n ? 28n : 27n,
    });

    await expect(
      verifySiweLogin({
        message,
        signature: highS,
        expectedDomain: 'auth.citrate.ai',
        nonceStore: store,
      }),
    ).rejects.toMatchObject({ reason: 'malleable_signature' });
  });

  it('consumes a nonce exactly once', () => {
    const store = new InMemoryNonceStore();
    const nonce = store.issue();
    expect(store.consume(nonce)).toBe(true);
    expect(store.consume(nonce)).toBe(false);
  });

  it('treats an expired nonce as unusable', () => {
    const store = new InMemoryNonceStore(-1); // already expired on issue
    const nonce = store.issue();
    expect(store.consume(nonce)).toBe(false);
  });

  it('EIP-1271: verifies a smart-contract wallet via on-chain isValidSignature', async () => {
    // EIP-1271 magic value 0x1626ba7e (bytes4) padded to a 32-byte word.
    const MAGIC =
      '0x1626ba7e00000000000000000000000000000000000000000000000000000000';
    const contractWallet = getAddress(
      '0x000000000000000000000000000000000000c0de',
    );

    // A mock viem public client whose `call` answers isValidSignature with the
    // EIP-1271 magic value — i.e. the contract approves the signature on-chain.
    // This exercises the exact code path siwe takes for contract accounts
    // (provider.call → isValidSignature) without needing a live RPC; a live-RPC
    // run against a deployed Safe is the integration variant.
    let calledWith: { to?: string; data?: string } = {};
    const mockClient = {
      call: async (tx: { to?: string; data?: string }) => {
        calledWith = tx;
        return { data: MAGIC };
      },
    } as unknown as Parameters<typeof verifySiweLogin>[0]['publicClient'];

    const store = new InMemoryNonceStore();
    const nonce = store.issue();
    const siwe = new SiweMessage({
      domain: 'auth.citrate.ai',
      address: contractWallet,
      uri: 'https://auth.citrate.ai',
      version: '1',
      chainId: CITRATE_CHAIN_ID,
      nonce,
    });
    const message = siwe.prepareMessage();
    // Any non-recoverable signature blob; the contract (mock) is authoritative.
    const contractSignature = '0xdeadbeef';

    const result = await verifySiweLogin({
      message,
      signature: contractSignature,
      expectedDomain: 'auth.citrate.ai',
      nonceStore: store,
      publicClient: mockClient,
    });

    expect(result.method).toBe('eip1271');
    expect(result.address.toLowerCase()).toBe(contractWallet.toLowerCase());
    // Confirm the on-chain call was actually made to the wallet contract.
    expect(calledWith.to?.toLowerCase()).toBe(contractWallet.toLowerCase());
    expect(calledWith.data).toMatch(/^0x1626ba7e/); // isValidSignature selector
  });

  it('throws a typed SiweVerificationError for an unknown nonce', async () => {
    const store = new InMemoryNonceStore();
    const siwe = new SiweMessage({
      domain: 'auth.citrate.ai',
      address: account.address,
      uri: 'https://auth.citrate.ai',
      version: '1',
      chainId: CITRATE_CHAIN_ID,
      nonce: 'neverissuednonce1234',
    });
    const message = siwe.prepareMessage();
    const signature = await account.signMessage({ message });
    await expect(
      verifySiweLogin({
        message,
        signature,
        expectedDomain: 'auth.citrate.ai',
        nonceStore: store,
      }),
    ).rejects.toBeInstanceOf(SiweVerificationError);
  });
});
