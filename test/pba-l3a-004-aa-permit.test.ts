/**
 * PBA-L3a-004 (MEDIUM) — POST /aa/enroll-validator signed a factory deploy
 * permit with no maximum lifetime, over ANY initData, for an access token from
 * ANY client. The wallet address depends only on the userId, so a leaked token
 * could mint a long-lived permit that deploys the victim's future wallet with an
 * attacker-chosen validator.
 *
 * Fix under test: expiry capped, first-party permit clients only, initData must
 * be a Kernel initialize() whose root validator is the caller's own (ECDSA owner
 * = the caller's proven wallet; WebAuthn credential = the caller's passkey), and
 * a per-user issuance budget.
 */
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { privateKeyToAccount } from 'viem/accounts';
import { keccak256, recoverMessageAddress, type Address, type Hex } from 'viem';
import type Provider from 'oidc-provider';
import { createProvider } from '../src/server.js';
import * as aaRoutes from '../src/aa/aa-routes.js';
const { mountAaRoutes, accountIdToUserId } = aaRoutes;
const MAX_PERMIT_TTL_SEC = (aaRoutes as { MAX_PERMIT_TTL_SEC?: number }).MAX_PERMIT_TTL_SEC ?? 3600;
const AA_PERMIT_CLIENT_IDS = (aaRoutes as { AA_PERMIT_CLIENT_IDS?: ReadonlySet<string> }).AA_PERMIT_CLIENT_IDS ?? new Set<string>();
import { ecdsaInstallData, EcdsaValidatorSource, guardianInstallModuleCall, kernelInitializeCalldata, webauthnInstallData } from '../src/aa/install-data.js';
import { InMemoryWalletRegistry, setWalletRegistry, getWalletRegistry } from '../src/identity-registry.js';
import { setWebAuthnStore, InMemoryWebAuthnCredentialStore, getWebAuthnStore } from '../src/auth/stores.js';

const signer = privateKeyToAccount(`0x${'5a'.repeat(32)}` as Hex);
const victimEoa = privateKeyToAccount(`0x${'11'.repeat(32)}` as Hex).address;
const attackerEoa = privateKeyToAccount(`0x${'22'.repeat(32)}` as Hex).address;
const ecdsaValidator = '0x00000000000000000000000000000000000000e1' as Address;
const webauthnValidator = '0x00000000000000000000000000000000000000e2' as Address;
const config = {
  factory: '0x00000000000000000000000000000000000000f1' as Address,
  kernelImpl: '0x00000000000000000000000000000000000000f2' as Address,
  chainId: 40204n,
  identitySignerKey: `0x${'5a'.repeat(32)}` as Hex,
  ecdsaValidator,
  webauthnValidator,
};

let server: Server;
let baseUrl: string;
let provider: Provider;

beforeAll(async () => {
  const probe = createServer();
  await new Promise<void>((r) => probe.listen(0, '127.0.0.1', r));
  const { port } = probe.address() as AddressInfo;
  probe.close();
  baseUrl = `http://127.0.0.1:${port}`;
  provider = await createProvider(baseUrl, { googleEnabled: false });
  mountAaRoutes(provider, { config, rpcUrl: 'http://127.0.0.1:9' });
  server = createServer(provider.callback());
  await new Promise<void>((r) => server.listen(port, '127.0.0.1', r));
});
afterAll(async () => { await new Promise<void>((r) => server.close(() => r())); });
beforeEach(() => {
  setWalletRegistry(new InMemoryWalletRegistry());
  setWebAuthnStore(new InMemoryWebAuthnCredentialStore());
});

async function token(accountId: string, clientId: string): Promise<string> {
  const client = await provider.Client.find(clientId);
  const at = new provider.AccessToken({ accountId, client: client!, scope: 'openid wallet' } as never);
  return at.save();
}
const userIdForEoa = (eoa: Address): Hex => accountIdToUserId(eoa)!;
const ecdsaInit = (owner: Address): Hex =>
  kernelInitializeCalldata({ rootValidator: ecdsaValidator, validatorData: ecdsaInstallData({ owner, source: EcdsaValidatorSource.WalletExtension }) });
const now = () => Math.floor(Date.now() / 1000);

async function enroll(tok: string, body: Record<string, unknown>): Promise<Response> {
  return fetch(`${baseUrl}/aa/enroll-validator`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${tok}` },
    body: JSON.stringify(body),
  });
}

describe('PBA-L3a-004 wallet deploy permit', () => {
  it('a token from a client that is not a permit client is refused', async () => {
    expect(AA_PERMIT_CLIENT_IDS.has('citrate-explorer')).toBe(false);
    const tok = await token(victimEoa, 'citrate-explorer');
    const r = await enroll(tok, { userId: userIdForEoa(victimEoa), initData: ecdsaInit(victimEoa), expiresAt: now() + 600 });
    expect(r.status).toBe(403);
    expect(((await r.json()) as { error: string }).error).toBe('client_not_permitted');
  });

  it('the permit client set is exactly the Citrate-owned permit callers', () => {
    expect([...AA_PERMIT_CLIENT_IDS].sort()).toEqual(['citrate-core', 'citrate-gui-native', 'citrate-radar', 'citrate-wallet-extension']);
  });

  it('what the shipped wallet extension sends (now + 3600) is accepted', async () => {
    const tok = await token(victimEoa, 'citrate-radar');
    const r = await enroll(tok, { userId: userIdForEoa(victimEoa), initData: ecdsaInit(victimEoa), expiresAt: now() + 3600 });
    expect(r.status).toBe(200);
  });

  it('an expiry in the past is refused', async () => {
    const tok = await token(victimEoa, 'citrate-radar');
    expect((await enroll(tok, { userId: userIdForEoa(victimEoa), initData: ecdsaInit(victimEoa), expiresAt: now() - 10 })).status).toBe(400);
  });

  it('missing / non-Bearer / unknown tokens are 401', async () => {
    const body = JSON.stringify({ userId: userIdForEoa(victimEoa), initData: ecdsaInit(victimEoa), expiresAt: now() + 600 });
    for (const authorization of [undefined, 'Basic abc', 'Bearer not-a-real-token', 'Bearer']) {
      const r = await fetch(`${baseUrl}/aa/enroll-validator`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', ...(authorization ? { authorization } : {}) },
        body,
      });
      expect(r.status).toBe(401);
    }
  });

  it('a far-future (effectively permanent) expiry is refused', async () => {
    const tok = await token(victimEoa, 'citrate-radar');
    const r = await enroll(tok, { userId: userIdForEoa(victimEoa), initData: ecdsaInit(victimEoa), expiresAt: now() + 10 * 365 * 86400 });
    expect(r.status).toBe(400);
    expect(((await r.json()) as { reason: string }).reason).toMatch(/expiresAt/);
  });

  it('expiry just past the cap is refused; exactly at the cap is accepted', async () => {
    const tok = await token(victimEoa, 'citrate-radar');
    const over = await enroll(tok, { userId: userIdForEoa(victimEoa), initData: ecdsaInit(victimEoa), expiresAt: now() + MAX_PERMIT_TTL_SEC + 5 });
    expect(over.status).toBe(400);
    const at = await enroll(tok, { userId: userIdForEoa(victimEoa), initData: ecdsaInit(victimEoa), expiresAt: now() + MAX_PERMIT_TTL_SEC - 5 });
    expect(at.status).toBe(200);
  });

  it('arbitrary initData (not a Kernel initialize) is refused', async () => {
    const tok = await token(victimEoa, 'citrate-radar');
    const r = await enroll(tok, { userId: userIdForEoa(victimEoa), initData: '0xdeadbeef', expiresAt: now() + 600 });
    expect(r.status).toBe(400);
  });

  it('an ECDSA root validator owned by someone else is refused (the leaked-token takeover)', async () => {
    const tok = await token(victimEoa, 'citrate-radar');
    const r = await enroll(tok, { userId: userIdForEoa(victimEoa), initData: ecdsaInit(attackerEoa), expiresAt: now() + 600 });
    expect(r.status).toBe(403);
    expect(((await r.json()) as { error: string }).error).toBe('validator_not_owned');
  });

  it('the caller\'s own ECDSA owner gets a valid signed permit', async () => {
    const tok = await token(victimEoa, 'citrate-radar');
    const r = await enroll(tok, { userId: userIdForEoa(victimEoa), initData: ecdsaInit(victimEoa), expiresAt: now() + 600 });
    expect(r.status).toBe(200);
    const j = (await r.json()) as { permitDigest: Hex; signature: Hex };
    expect(await recoverMessageAddress({ message: { raw: j.permitDigest }, signature: j.signature })).toBe(signer.address);
  });

  it('a UUID account may use a registry-proven wallet as owner, not an unproven one', async () => {
    const uuid = '6f1c1b1e-1111-4222-8333-944444444444';
    await getWalletRegistry().link(uuid, victimEoa);
    const tok = await token(uuid, 'citrate-radar');
    const userId = accountIdToUserId(uuid)!;
    expect((await enroll(tok, { userId, initData: ecdsaInit(victimEoa), expiresAt: now() + 600 })).status).toBe(200);
    expect((await enroll(tok, { userId, initData: ecdsaInit(attackerEoa), expiresAt: now() + 600 })).status).toBe(403);
  });

  it('a WebAuthn root validator must be one of the caller\'s own passkeys', async () => {
    const uuid = '6f1c1b1e-2222-4222-8333-944444444444';
    const credentialId = Buffer.from('cred-of-user');
    await getWebAuthnStore().insertCredential({ userId: uuid, credentialId, publicKeyCose: Buffer.from('k') });
    const tok = await token(uuid, 'citrate-radar');
    const userId = accountIdToUserId(uuid)!;
    const init = (credHash: Hex) =>
      kernelInitializeCalldata({
        rootValidator: webauthnValidator,
        validatorData: webauthnInstallData({ credentialIdHash: credHash, x: `0x${'01'.repeat(32)}`, y: `0x${'02'.repeat(32)}`, requireUserVerification: true }),
      });
    await getWebAuthnStore().insertCredential({ userId: uuid, credentialId: Buffer.from('second-passkey'), publicKeyCose: Buffer.from('k2') });
    expect((await enroll(tok, { userId, initData: init(keccak256(credentialId)), expiresAt: now() + 600 })).status).toBe(200);
    expect((await enroll(tok, { userId, initData: init(keccak256(Buffer.from('second-passkey'))), expiresAt: now() + 600 })).status).toBe(200);
    expect((await enroll(tok, { userId, initData: init(keccak256(Buffer.from('someone-else'))), expiresAt: now() + 600 })).status).toBe(403);
  });

  it('permits are rationed per user (a leaked token cannot mint an unbounded supply)', async () => {
    const eoa = privateKeyToAccount(`0x${'33'.repeat(32)}` as Hex).address;
    const tok = await token(eoa, 'citrate-radar');
    const statuses: number[] = [];
    for (let i = 0; i < 8; i++) statuses.push((await enroll(tok, { userId: userIdForEoa(eoa), initData: ecdsaInit(eoa), expiresAt: now() + 600 })).status);
    expect(statuses.slice(0, 5).every((s) => s === 200)).toBe(true);
    expect(statuses.slice(5).every((s) => s === 429)).toBe(true);
  });
});

describe('PBA-L3a-004 initData ownership rules (unit)', () => {
  const parse = (aaRoutes as { parseKernelInitData?: (h: Hex) => unknown }).parseKernelInitData!;
  const check = (aaRoutes as { checkRootValidatorOwnership?: (...a: unknown[]) => Promise<true | string> }).checkRootValidatorOwnership!;
  const recoveryModule = '0x00000000000000000000000000000000000000e3' as Address;
  const g1 = privateKeyToAccount(`0x${'44'.repeat(32)}` as Hex).address;
  const g2 = privateKeyToAccount(`0x${'55'.repeat(32)}` as Hex).address;

  it('rejects a non-validator root type, a hook, hook data, and unknown validator-data lengths', () => {
    const vd = ecdsaInstallData({ owner: victimEoa, source: EcdsaValidatorSource.WalletExtension });
    expect(parse(kernelInitializeCalldata({ rootValidator: ecdsaValidator, validatorData: vd }))).not.toBeNull();
    expect(parse(kernelInitializeCalldata({ rootValidator: ecdsaValidator, validationType: 2, validatorData: vd }))).toBeNull();
    expect(parse(kernelInitializeCalldata({ rootValidator: ecdsaValidator, hook: attackerEoa, validatorData: vd }))).toBeNull();
    expect(parse(kernelInitializeCalldata({ rootValidator: ecdsaValidator, hookData: '0x01', validatorData: vd }))).toBeNull();
    expect(parse(kernelInitializeCalldata({ rootValidator: ecdsaValidator, validatorData: `${vd}00` as Hex }))).toBeNull();
    expect(parse('0x')).toBeNull();
  });

  it('extracts the ECDSA owner and the WebAuthn credential hash', () => {
    const e = parse(ecdsaInit(victimEoa)) as { kind: string; owner: Address; validator: Address };
    expect(e.kind).toBe('ecdsa');
    expect(e.owner).toBe(victimEoa);
    expect(e.validator.toLowerCase()).toBe(ecdsaValidator.toLowerCase());
    const h = keccak256(Buffer.from('x'));
    const w = parse(kernelInitializeCalldata({ rootValidator: webauthnValidator, validatorData: webauthnInstallData({ credentialIdHash: h, x: `0x${'01'.repeat(32)}`, y: `0x${'02'.repeat(32)}`, requireUserVerification: false }) })) as { kind: string; credentialIdHash: Hex };
    expect(w).toMatchObject({ kind: 'webauthn', credentialIdHash: h });
  });

  it('refuses a non-canonical validator module even with the caller\'s own owner', async () => {
    const root = parse(kernelInitializeCalldata({ rootValidator: attackerEoa, validatorData: ecdsaInstallData({ owner: victimEoa, source: EcdsaValidatorSource.WalletExtension }) }));
    expect(await check(root, victimEoa, config)).toMatch(/canonical/);
    expect(await check(parse(ecdsaInit(victimEoa)), victimEoa, { ...config, ecdsaValidator: undefined })).toMatch(/canonical/);
  });

  it('a bound primary wallet counts as the caller\'s own owner', async () => {
    const { InMemoryUserStore, setUserStore, getUserStore } = await import('../src/auth/stores.js');
    setUserStore(new InMemoryUserStore());
    const u = await getUserStore().createWithPasskey();
    expect(await check(parse(ecdsaInit(victimEoa)), u.id, config)).toMatch(/proven/);
    await getUserStore().setPrimaryWallet(u.id, victimEoa);
    expect(await check(parse(ecdsaInit(victimEoa)), u.id, config)).toBe(true);
  });

  it('accepts sha256(credentialId) as well as keccak256', async () => {
    const credentialId = Buffer.from('cred-sha');
    await getWebAuthnStore().insertCredential({ userId: 'u-sha', credentialId, publicKeyCose: Buffer.from('k') });
    const { sha256 } = await import('viem');
    const root = parse(kernelInitializeCalldata({ rootValidator: webauthnValidator, validatorData: webauthnInstallData({ credentialIdHash: sha256(new Uint8Array(credentialId)), x: `0x${'01'.repeat(32)}`, y: `0x${'02'.repeat(32)}`, requireUserVerification: true }) }));
    expect(await check(root, 'u-sha', config)).toBe(true);
  });

  it('initConfig: only the guardian module with the caller\'s own nomination', async () => {
    const { getGuardianStore } = await import('../src/aa/guardians.js');
    await getGuardianStore().set({ sub: victimEoa, guardians: [g1.toLowerCase(), g2.toLowerCase()], threshold: 2, updatedAt: new Date() });
    const vd = ecdsaInstallData({ owner: victimEoa, source: EcdsaValidatorSource.WalletExtension });
    const mine = guardianInstallModuleCall({ recoveryModule, threshold: 2, guardians: [g1.toLowerCase() as Address, g2.toLowerCase() as Address] });
    const theirs = guardianInstallModuleCall({ recoveryModule, threshold: 1, guardians: [attackerEoa, g2] });
    const withCfg = (cfg: Hex[]) => parse(kernelInitializeCalldata({ rootValidator: ecdsaValidator, validatorData: vd, initConfig: cfg }));
    expect(await check(withCfg([mine]), victimEoa, config, recoveryModule)).toBe(true);
    expect(await check(withCfg([theirs]), victimEoa, config, recoveryModule)).toMatch(/initConfig/);
    expect(await check(withCfg([mine, mine]), victimEoa, config, recoveryModule)).toMatch(/initConfig/);
    expect(await check(withCfg([mine]), victimEoa, config)).toMatch(/initConfig/);
    // recovery module configured, but this account never nominated guardians
    expect(await check(parse(kernelInitializeCalldata({ rootValidator: ecdsaValidator, validatorData: ecdsaInstallData({ owner: g1, source: EcdsaValidatorSource.WalletExtension }), initConfig: [mine] })), g1, config, recoveryModule)).toMatch(/initConfig/);
  });

  it('with no canonical validators configured the route fails closed (503)', async () => {
    const probe = createServer();
    await new Promise<void>((r) => probe.listen(0, '127.0.0.1', r));
    const { port } = probe.address() as AddressInfo;
    probe.close();
    const url = `http://127.0.0.1:${port}`;
    const p2 = await createProvider(url, { googleEnabled: false });
    mountAaRoutes(p2, { config: { ...config, ecdsaValidator: undefined, webauthnValidator: undefined }, rpcUrl: 'http://127.0.0.1:9' });
    const s2 = createServer(p2.callback());
    await new Promise<void>((r) => s2.listen(port, '127.0.0.1', r));
    try {
      const client = await p2.Client.find('citrate-radar');
      const tok = await new p2.AccessToken({ accountId: victimEoa, client: client!, scope: 'openid wallet' } as never).save();
      const r = await fetch(`${url}/aa/enroll-validator`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', authorization: `Bearer ${tok}` },
        body: JSON.stringify({ userId: userIdForEoa(victimEoa), initData: ecdsaInit(victimEoa), expiresAt: now() + 600 }),
      });
      expect(r.status).toBe(503);
      expect(((await r.json()) as { error: string }).error).toBe('aa_validators_unconfigured');
    } finally {
      await new Promise<void>((r) => s2.close(() => r()));
    }
  });
});

describe('PBA-L3a-004 one configured validator kind is enough', () => {
  it('ECDSA-only config still signs ECDSA permits', async () => {
    const probe = createServer();
    await new Promise<void>((r) => probe.listen(0, '127.0.0.1', r));
    const { port } = probe.address() as AddressInfo;
    probe.close();
    const url = `http://127.0.0.1:${port}`;
    const p3 = await createProvider(url, { googleEnabled: false });
    mountAaRoutes(p3, { config: { ...config, webauthnValidator: undefined }, rpcUrl: 'http://127.0.0.1:9' });
    const s3 = createServer(p3.callback());
    await new Promise<void>((r) => s3.listen(port, '127.0.0.1', r));
    try {
      const client = await p3.Client.find('citrate-radar');
      const tok = await new p3.AccessToken({ accountId: victimEoa, client: client!, scope: 'openid wallet' } as never).save();
      const r = await fetch(`${url}/aa/enroll-validator`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', authorization: `Bearer ${tok}` },
        body: JSON.stringify({ userId: userIdForEoa(victimEoa), initData: ecdsaInit(victimEoa), expiresAt: now() + 600 }),
      });
      expect(r.status).toBe(200);
    } finally {
      await new Promise<void>((r) => s3.close(() => r()));
    }
  });
});

describe('PBA-L3a-004 AA config: canonical validators', () => {
  const base = {
    CITRATE_AA_FACTORY: config.factory,
    CITRATE_AA_KERNEL_IMPL: config.kernelImpl,
    CITRATE_AA_IDENTITY_SIGNER_KEY: config.identitySignerKey,
  };
  it('loads well-formed validator addresses', async () => {
    const { loadAaConfig } = await import('../src/aa/config.js');
    const c = loadAaConfig({ ...base, CITRATE_AA_ECDSA_VALIDATOR: ecdsaValidator, CITRATE_AA_WEBAUTHN_VALIDATOR: webauthnValidator });
    expect(c.ecdsaValidator).toBe(ecdsaValidator);
    expect(c.webauthnValidator).toBe(webauthnValidator);
    const none = loadAaConfig(base);
    expect(none.ecdsaValidator).toBeUndefined();
    expect(none.webauthnValidator).toBeUndefined();
  });
  it('a malformed validator address fails production boot and is ignored in dev', async () => {
    const { loadAaConfig } = await import('../src/aa/config.js');
    expect(() => loadAaConfig({ ...base, NODE_ENV: 'production', CITRATE_AA_ECDSA_VALIDATOR: '0x1234' })).toThrow(/CITRATE_AA_ECDSA_VALIDATOR/);
    expect(() => loadAaConfig({ ...base, NODE_ENV: 'production', CITRATE_AA_WEBAUTHN_VALIDATOR: 'nope' })).toThrow(/CITRATE_AA_WEBAUTHN_VALIDATOR/);
    expect(loadAaConfig({ ...base, CITRATE_AA_ECDSA_VALIDATOR: '0x1234' }).ecdsaValidator).toBeUndefined();
  });
});
