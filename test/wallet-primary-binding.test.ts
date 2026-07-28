/**
 * The canonical-wallet → `wallet_address` binding (2026-07-28).
 *
 * WHY THIS EXISTS. `findAccount` already preferred a user's bound
 * `primaryWallet` over the counterfactual CREATE2 prediction when minting the
 * `wallet_address` claim — but NOTHING ever called `setPrimaryWallet`, so the
 * claim was always the predicted smart-wallet address. No private key can spend
 * from that address, so anything that pays it (the 32,000 SALT validator bond)
 * sends funds the member cannot move. Meanwhile a full proof-of-control wallet
 * link already existed at `/identity/:sub/wallets`, unconnected to the claim.
 *
 * This pins the wire between them, and the two ways it could go wrong:
 *   1. a NON-canonical link must not repoint a member's pay-to address;
 *   2. clearing the binding must write NULL, not '' — `account-routes` and
 *      `kyc-routes` read it as `primaryWallet ?? predicted`, and '' is not
 *      nullish, so an empty string would suppress the fallback and yield a
 *      BLANK address rather than the predicted one.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { Wallet } from 'ethers';
import { getAddress } from 'viem';
import type Provider from 'oidc-provider';

import {
  InMemoryWalletRegistry,
  buildWalletLinkMessage,
  setWalletRegistry,
  getWalletRegistry,
  mountIdentityRegistryRoutes,
} from '../src/identity-registry.js';
import { InMemoryNonceStore } from '../src/siwe.js';
import { InMemoryUserStore } from '../src/auth/stores.js';

const SUB = '0d1f02f1-1f5a-4f5e-9c2e-7b8d1a2b3c4d';
const AUTHORITY = 'auth.citrate.ai';
const CHAIN_ID = 40204;
const TOKEN = 'tok_good';

const walletA = new Wallet(`0x${'a7'.repeat(32)}`);
const walletB = new Wallet(`0x${'b9'.repeat(32)}`);

/** Minimal ctx the registry middleware understands (readJson takes request.body). */
function makeCtx(method: string, path: string, body?: unknown) {
  return {
    method,
    path,
    headers: { authorization: `Bearer ${TOKEN}` },
    request: { body },
    req: null,
    status: 0,
    type: '',
    body: undefined as unknown,
  };
}

/** Mount the routes on a fake provider and return the single middleware. */
function mount(onCanonicalWalletChange?: (sub: string, addr: string | null) => Promise<void>) {
  let mw: ((ctx: unknown, next: () => Promise<void>) => Promise<void>) | null = null;
  const provider = {
    use: (fn: (ctx: unknown, next: () => Promise<void>) => Promise<void>) => {
      mw = fn;
    },
    AccessToken: {
      find: async (t: string) =>
        t === TOKEN ? { accountId: SUB, isExpired: false } : null,
    },
  } as unknown as Provider;

  mountIdentityRegistryRoutes(provider, {
    authority: AUTHORITY,
    chainId: CHAIN_ID,
    nonceStore: nonces,
    ...(onCanonicalWalletChange ? { onCanonicalWalletChange } : {}),
  });
  return mw!;
}

let nonces: InMemoryNonceStore;

beforeEach(() => {
  nonces = new InMemoryNonceStore();
  setWalletRegistry(new InMemoryWalletRegistry());
});

/** Drive a real proof-of-control link for `w`. */
async function link(mw: ReturnType<typeof mount>, w: Wallet) {
  const nonce = await nonces.issue();
  const message = buildWalletLinkMessage({
    authority: AUTHORITY,
    sub: SUB,
    address: w.address,
    nonce,
    chainId: CHAIN_ID,
  });
  const signature = await w.signMessage(message);
  const ctx = makeCtx('POST', `/identity/${SUB}/wallets`, {
    address: w.address,
    signature,
    nonce,
  });
  await mw(ctx, async () => {});
  return ctx;
}

describe('canonical link → the wallet_address binding', () => {
  it('the FIRST proven link becomes canonical and announces the bound address', async () => {
    const hook = vi.fn(async () => {});
    const mw = mount(hook);

    const ctx = await link(mw, walletA);
    expect(ctx.status).toBe(201);
    expect(hook).toHaveBeenCalledTimes(1);
    expect(hook).toHaveBeenCalledWith(SUB, getAddress(walletA.address));
  });

  it('a SECOND link does NOT repoint the pay-to address', async () => {
    const hook = vi.fn(async () => {});
    const mw = mount(hook);

    await link(mw, walletA);
    hook.mockClear();
    const ctx = await link(mw, walletB);

    expect(ctx.status).toBe(201);
    // Attributable, but the member's pay-to address must not move under them.
    expect(hook).not.toHaveBeenCalled();
  });

  it('unlinking the canonical promotes the next wallet and announces IT', async () => {
    const hook = vi.fn(async () => {});
    const mw = mount(hook);
    await link(mw, walletA);
    await link(mw, walletB);
    hook.mockClear();

    const ctx = makeCtx('DELETE', `/identity/${SUB}/wallets/${walletA.address}`);
    await mw(ctx, async () => {});

    expect(ctx.status).toBe(200);
    expect(hook).toHaveBeenCalledTimes(1);
    expect(hook).toHaveBeenCalledWith(SUB, getAddress(walletB.address));
  });

  it('unlinking the LAST wallet announces null — the prediction resumes', async () => {
    const hook = vi.fn(async () => {});
    const mw = mount(hook);
    await link(mw, walletA);
    hook.mockClear();

    const ctx = makeCtx('DELETE', `/identity/${SUB}/wallets/${walletA.address}`);
    await mw(ctx, async () => {});

    expect(hook).toHaveBeenCalledWith(SUB, null);
  });

  it('unlinking a NON-canonical wallet leaves the binding alone', async () => {
    const hook = vi.fn(async () => {});
    const mw = mount(hook);
    await link(mw, walletA);
    await link(mw, walletB);
    hook.mockClear();

    const ctx = makeCtx('DELETE', `/identity/${SUB}/wallets/${walletB.address}`);
    await mw(ctx, async () => {});

    expect(ctx.status).toBe(200);
    expect(hook).not.toHaveBeenCalled();
  });

  it('a hook failure does NOT fail the link — the link is already committed', async () => {
    const hook = vi.fn(async () => {
      throw new Error('store down');
    });
    const mw = mount(hook);

    const ctx = await link(mw, walletA);

    // Reporting failure for work that succeeded would be the worse lie.
    expect(ctx.status).toBe(201);
    expect(await getWalletRegistry().canonicalFor(SUB)).toBe(walletA.address.toLowerCase());
  });
});

describe('clearing the binding writes NULL, never an empty string', () => {
  it('binds, then clears back to the predicted-address fallback', async () => {
    const users = new InMemoryUserStore();
    const rec = await users.createWithPasskey();

    await users.setPrimaryWallet(rec.id, walletA.address);
    expect((await users.findById(rec.id))?.primaryWallet).toBe(
      walletA.address.toLowerCase(),
    );

    await users.setPrimaryWallet(rec.id, null);
    const cleared = await users.findById(rec.id);

    // The exact idiom account-routes.ts:183 and kyc-routes.ts:415 use. With ''
    // this yields '' — a BLANK wallet — instead of falling through.
    expect(cleared?.primaryWallet ?? 'PREDICTED').toBe('PREDICTED');
    expect(cleared?.primaryWallet).toBeUndefined();
  });
});
