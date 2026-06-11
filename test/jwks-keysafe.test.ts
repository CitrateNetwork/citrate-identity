import { mkdtempSync, statSync, chmodSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  SignJWT,
  importJWK,
  createLocalJWKSet,
  jwtVerify,
  decodeProtectedHeader,
  type JWK,
} from 'jose';
import { loadOrCreateJwks, rotateJwks } from '../src/config.js';
import { createProvider } from '../src/server.js';

/**
 * SECREM-02 KEYSAFE K2 — FUA-IDENTITY-06.
 *
 * 1. The persisted JWKS (private RS256 signing key) must be written 0600 and
 *    have its mode asserted/repaired on every load (fail closed if it cannot
 *    be restricted).
 * 2. Key rotation must support a published-but-retiring second JWK so there is
 *    an overlap window: tokens signed by the retiring key still verify against
 *    the published JWKS while new tokens carry the new `kid`.
 */

const isPosix = process.platform !== 'win32';

function tmpJwksPath(): string {
  return join(mkdtempSync(join(tmpdir(), 'citrate-jwks-')), 'jwks.json');
}

function fileMode(path: string): number {
  return statSync(path).mode & 0o777;
}

/** Public (verify-only) projection of a private JWKS — what `/jwks` serves. */
function publicProjection(keys: JWK[]): { keys: JWK[] } {
  return {
    keys: keys.map((k) => {
      const { d, p, q, dp, dq, qi, ...pub } = k;
      void d, void p, void q, void dp, void dq, void qi;
      return pub;
    }),
  };
}

async function signWith(jwk: JWK, issuer: string): Promise<string> {
  const key = await importJWK(jwk, 'RS256');
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({ sub: '0xabc' })
    .setProtectedHeader({ alg: 'RS256', kid: jwk.kid, typ: 'JWT' })
    .setIssuer(issuer)
    .setAudience('citrate-explorer')
    .setIssuedAt(now)
    .setExpirationTime(now + 300)
    .sign(key);
}

describe('JWKS file permissions (FUA-IDENTITY-06)', () => {
  it.skipIf(!isPosix)('creates the JWKS file with mode 0600', async () => {
    const path = tmpJwksPath();
    await loadOrCreateJwks(path);
    expect(fileMode(path).toString(8)).toBe((0o600).toString(8));
  });

  it.skipIf(!isPosix)('repairs a loosely-permissioned JWKS file on load', async () => {
    const path = tmpJwksPath();
    await loadOrCreateJwks(path);
    chmodSync(path, 0o644); // simulate the pre-fix on-disk state
    await loadOrCreateJwks(path);
    expect(fileMode(path).toString(8)).toBe((0o600).toString(8));
  });

  it.skipIf(!isPosix)('keeps 0600 after a rotation rewrite', async () => {
    const path = tmpJwksPath();
    await loadOrCreateJwks(path);
    await rotateJwks(path);
    expect(fileMode(path).toString(8)).toBe((0o600).toString(8));
  });
});

describe('signing-key rotation overlap (FUA-IDENTITY-06)', () => {
  it('rotation keeps the retiring key published while the new key signs', async () => {
    const path = tmpJwksPath();
    const issuer = 'http://localhost:3000';

    const before = await loadOrCreateJwks(path);
    expect(before.keys.length).toBe(1);
    const retiringKid = before.keys[0].kid;
    expect(retiringKid).toBeTruthy();

    // Token minted by the (about-to-retire) signing key.
    const oldToken = await signWith(before.keys[0], issuer);

    const after = await rotateJwks(path);
    expect(after.keys.length).toBe(2);
    const newKid = after.keys[0].kid;
    expect(newKid).toBeTruthy();
    expect(newKid).not.toBe(retiringKid);
    // keys[0] is the active signer; the retiring key stays published.
    expect(after.keys[1].kid).toBe(retiringKid);

    const published = createLocalJWKSet(publicProjection(after.keys));

    // Overlap window: the retiring key's token still verifies.
    const oldVerified = await jwtVerify(oldToken, published, { issuer });
    expect(oldVerified.protectedHeader.kid).toBe(retiringKid);

    // New tokens are signed by — and carry the kid of — the new key.
    const newToken = await signWith(after.keys[0], issuer);
    expect(decodeProtectedHeader(newToken).kid).toBe(newKid);
    const newVerified = await jwtVerify(newToken, published, { issuer });
    expect(newVerified.protectedHeader.kid).toBe(newKid);
  });

  it('a second rotation drops the oldest key (publish window of two)', async () => {
    const path = tmpJwksPath();
    const first = await loadOrCreateJwks(path);
    const kidA = first.keys[0].kid;
    const second = await rotateJwks(path);
    const kidB = second.keys[0].kid;
    const third = await rotateJwks(path);
    expect(third.keys.length).toBe(2);
    expect(third.keys.map((k) => k.kid)).not.toContain(kidA);
    expect(third.keys[1].kid).toBe(kidB);
    // Persisted state matches the returned state.
    const onDisk = JSON.parse(readFileSync(path, 'utf8')) as { keys: JWK[] };
    expect(onDisk.keys.map((k) => k.kid)).toEqual(third.keys.map((k) => k.kid));
  });
});

describe('/jwks endpoint serves both keys during overlap', () => {
  let server: Server;
  let baseUrl: string;
  let kids: (string | undefined)[];
  const prevEnv = process.env.JWKS_PATH;

  beforeAll(async () => {
    // Point the authority at a rotated (two-key) JWKS file.
    const path = tmpJwksPath();
    process.env.JWKS_PATH = path;
    await loadOrCreateJwks(path);
    const rotated = await rotateJwks(path);
    kids = rotated.keys.map((k) => k.kid);

    const probe = createServer();
    await new Promise<void>((res) => probe.listen(0, '127.0.0.1', res));
    const { port } = probe.address() as AddressInfo;
    probe.close();
    baseUrl = `http://127.0.0.1:${port}`;
    const provider = await createProvider(baseUrl);
    server = createServer(provider.callback());
    await new Promise<void>((res) => server.listen(port, '127.0.0.1', res));
  });

  afterAll(async () => {
    if (prevEnv === undefined) delete process.env.JWKS_PATH;
    else process.env.JWKS_PATH = prevEnv;
    await new Promise<void>((res, rej) =>
      server.close((err) => (err ? rej(err) : res())),
    );
  });

  it('publishes both kids and never the private members', async () => {
    const res = await fetch(`${baseUrl}/jwks`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { keys: JWK[] };
    const served = body.keys.map((k) => k.kid);
    for (const kid of kids) expect(served).toContain(kid);
    for (const k of body.keys) {
      expect(k).not.toHaveProperty('d');
      expect(k).not.toHaveProperty('p');
      expect(k).not.toHaveProperty('q');
    }
  });
});
