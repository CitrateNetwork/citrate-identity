/**
 * IDP-S3 — identity ↔ wallet registry.
 *
 * One Citrate identity, N wallets, ONE canonical (the first linked —
 * `ADR` rule) that marketplace settlement attributes earnings to.
 *
 * HTTP surface (mounted by {@link mountIdentityRegistryRoutes}):
 *
 *   POST   /identity/:sub/wallets/challenge  → { nonce }   (Bearer, own sub)
 *   POST   /identity/:sub/wallets            → link with proof
 *          { address, signature }            (Bearer, own sub)
 *   GET    /identity/:sub/wallets            → list        (Bearer, own sub)
 *   DELETE /identity/:sub/wallets/:address   → unlink      (Bearer, own sub)
 *
 * The link PROOF is the WALLET's own EIP-191 signature over a canonical
 * message binding (authority, sub, address, one-time nonce, chainId) —
 * a stolen bearer token alone cannot attach an attacker's wallet to a
 * victim (the attacker's wallet would attribute earnings TO the victim's
 * identity, and a victim's wallet can't be attached without its key).
 * Nonces are one-time via the SAME store SIWE uses (Redis in prod).
 *
 * Marketplace settlement reads the canonical wallet through
 * {@link WalletRegistry.canonicalFor}; the HTTP surface stays same-sub
 * only until a service-credential client lands (follow-up noted in the
 * IDP planset).
 */

import type Provider from 'oidc-provider';
import { getAddress, isAddress, verifyMessage } from 'ethers';

import type { NonceStore } from './siwe.js';

type Ctx = Parameters<Parameters<Provider['use']>[0]>[0];
type Next = Parameters<Parameters<Provider['use']>[0]>[1];

const MAX_WALLETS_PER_SUB = 10;

export class WalletRegistryError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'WalletRegistryError';
  }
}

/** One linked wallet row. */
export interface LinkedWallet {
  address: string; // lowercase 0x
  canonical: boolean;
  linkedAt: Date;
}

/** Store shape — in-memory for dev/tests, Postgres in production. */
export interface WalletRegistry {
  link(sub: string, address: string): Promise<LinkedWallet>;
  unlink(sub: string, address: string): Promise<void>;
  list(sub: string): Promise<LinkedWallet[]>;
  /** The settlement-attribution wallet (first linked), if any. */
  canonicalFor(sub: string): Promise<string | null>;
}

// ── in-memory implementation (dev/test; Postgres impl mirrors it) ────

interface Row {
  sub: string;
  address: string;
  linkedAt: Date;
  seq: number;
}

export class InMemoryWalletRegistry implements WalletRegistry {
  private rows: Row[] = [];
  private seq = 0;

  async link(sub: string, address: string): Promise<LinkedWallet> {
    const addr = address.toLowerCase();
    const existing = this.rows.find((r) => r.address === addr);
    if (existing) {
      if (existing.sub !== sub) {
        throw new WalletRegistryError(
          'wallet is already linked to another identity',
        );
      }
      return this.toLinked(existing);
    }
    const mine = this.rows.filter((r) => r.sub === sub);
    if (mine.length >= MAX_WALLETS_PER_SUB) {
      throw new WalletRegistryError(
        `at most ${MAX_WALLETS_PER_SUB} wallets per identity`,
      );
    }
    const row: Row = { sub, address: addr, linkedAt: new Date(), seq: this.seq++ };
    this.rows.push(row);
    return this.toLinked(row);
  }

  async unlink(sub: string, address: string): Promise<void> {
    const addr = address.toLowerCase();
    this.rows = this.rows.filter((r) => !(r.sub === sub && r.address === addr));
  }

  async list(sub: string): Promise<LinkedWallet[]> {
    return this.rows
      .filter((r) => r.sub === sub)
      .sort((a, b) => a.seq - b.seq)
      .map((r, i) => ({ address: r.address, canonical: i === 0, linkedAt: r.linkedAt }));
  }

  async canonicalFor(sub: string): Promise<string | null> {
    const list = await this.list(sub);
    return list[0]?.address ?? null;
  }

  private toLinked(row: Row): LinkedWallet {
    const mine = this.rows.filter((r) => r.sub === row.sub).sort((a, b) => a.seq - b.seq);
    return {
      address: row.address,
      canonical: mine[0]?.address === row.address,
      linkedAt: row.linkedAt,
    };
  }
}

// ── process-wide singleton (mirrors the KYC/user-store pattern) ──────

let registry: WalletRegistry = new InMemoryWalletRegistry();

export function getWalletRegistry(): WalletRegistry {
  return registry;
}

export function setWalletRegistry(r: WalletRegistry): void {
  registry = r;
}

// ── proof message + verification ─────────────────────────────────────

/**
 * The canonical link-proof message the wallet signs (EIP-191
 * personal_sign). Versioned so future shapes can coexist.
 */
export function buildWalletLinkMessage(args: {
  authority: string;
  sub: string;
  address: string;
  nonce: string;
  chainId: number;
}): string {
  return [
    `${args.authority} wants to link a wallet to your Citrate identity.`,
    '',
    `Identity: ${args.sub}`,
    `Wallet: ${args.address.toLowerCase()}`,
    `Chain ID: ${args.chainId}`,
    `Nonce: ${args.nonce}`,
    'Version: citrate-wallet-link-1',
  ].join('\n');
}

/** EOA proof check (EIP-1271 smart-wallet proofs are a follow-up — the
 * Kernel wrapped-digest signing scheme is pinned in citrate-chain
 * test/aa/KernelEip1271.t.sol and needs the sdk-js 1271 signer first). */
export async function verifyWalletLinkProof(args: {
  message: string;
  signature: string;
  address: string;
}): Promise<boolean> {
  try {
    return (
      verifyMessage(args.message, args.signature).toLowerCase() ===
      args.address.toLowerCase()
    );
  } catch {
    return false;
  }
}

// ── HTTP routes ───────────────────────────────────────────────────────

export interface IdentityRegistryOptions {
  /** Authority hostname baked into the proof message (e.g. auth.citrate.ai). */
  authority: string;
  chainId: number;
  /** One-time nonce store — the SAME store SIWE uses (Redis in prod). */
  nonceStore: NonceStore;
}

export function mountIdentityRegistryRoutes(
  provider: Provider,
  options: IdentityRegistryOptions,
): void {
  const { authority, chainId, nonceStore } = options;

  provider.use(async (ctx: Ctx, next: Next) => {
    const match = /^\/identity\/([^/]+)\/wallets(?:\/(.+))?$/.exec(ctx.path);
    if (!match) return next();
    const sub = decodeURIComponent(match[1] ?? '');
    const tail = match[2] ? decodeURIComponent(match[2]) : undefined;

    // Every route requires a Bearer token for the SAME sub — fail closed.
    const caller = await resolveSub(provider, ctx);
    if (!caller) {
      respond(ctx, 401, { error: 'unauthorized', reason: 'access token required' });
      return;
    }
    if (caller !== sub) {
      respond(ctx, 403, { error: 'forbidden', reason: 'token subject does not match :sub' });
      return;
    }

    // POST /identity/:sub/wallets/challenge → one-time nonce
    if (ctx.method === 'POST' && tail === 'challenge') {
      const nonce = await nonceStore.issue();
      respond(ctx, 200, {
        nonce,
        message_template: buildWalletLinkMessage({
          authority,
          sub,
          address: '0x<wallet>',
          nonce,
          chainId,
        }),
      });
      return;
    }

    // POST /identity/:sub/wallets → link with proof
    if (ctx.method === 'POST' && tail === undefined) {
      const body = await readJson(ctx);
      const address = typeof body?.address === 'string' ? body.address : '';
      const signature = typeof body?.signature === 'string' ? body.signature : '';
      const nonce = typeof body?.nonce === 'string' ? body.nonce : '';
      if (!isAddress(address) || signature === '' || nonce === '') {
        respond(ctx, 400, {
          error: 'invalid_request',
          reason: 'address, signature, nonce are required (address must be a 20-byte 0x address)',
        });
        return;
      }
      // One-time nonce: consume BEFORE crypto (same posture as SIWE).
      const fresh = await nonceStore.consume(nonce);
      if (!fresh) {
        respond(ctx, 401, { error: 'invalid_grant', reason: 'unknown or replayed nonce' });
        return;
      }
      const message = buildWalletLinkMessage({ authority, sub, address, nonce, chainId });
      const ok = await verifyWalletLinkProof({ message, signature, address });
      if (!ok) {
        respond(ctx, 401, {
          error: 'invalid_grant',
          reason: 'signature does not prove control of the wallet',
        });
        return;
      }
      try {
        const linked = await getWalletRegistry().link(sub, address);
        respond(ctx, 201, { wallet: serialize(linked) });
      } catch (err) {
        if (err instanceof WalletRegistryError) {
          respond(ctx, 409, { error: 'conflict', reason: err.message });
          return;
        }
        throw err;
      }
      return;
    }

    // GET /identity/:sub/wallets → list
    if (ctx.method === 'GET' && tail === undefined) {
      const wallets = await getWalletRegistry().list(sub);
      respond(ctx, 200, { sub, wallets: wallets.map(serialize) });
      return;
    }

    // DELETE /identity/:sub/wallets/:address → unlink
    if (ctx.method === 'DELETE' && tail !== undefined) {
      if (!isAddress(tail)) {
        respond(ctx, 400, { error: 'invalid_request', reason: 'path address malformed' });
        return;
      }
      await getWalletRegistry().unlink(sub, tail);
      respond(ctx, 200, { ok: true });
      return;
    }

    respond(ctx, 405, { error: 'method_not_allowed' });
  });
}

// ── helpers ───────────────────────────────────────────────────────────

function serialize(w: LinkedWallet): Record<string, unknown> {
  return {
    address: getAddress(w.address),
    canonical: w.canonical,
    linked_at: w.linkedAt.toISOString(),
  };
}

function respond(ctx: Ctx, status: number, body: unknown): void {
  ctx.status = status;
  ctx.type = 'application/json';
  ctx.body = body;
}

async function readJson(ctx: Ctx): Promise<Record<string, unknown> | null> {
  const existing = (ctx.request as { body?: unknown }).body;
  if (existing && typeof existing === 'object' && !Array.isArray(existing)) {
    return existing as Record<string, unknown>;
  }
  const chunks: Buffer[] = [];
  await new Promise<void>((resolve, reject) => {
    const req = ctx.req as NodeJS.ReadableStream;
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => resolve());
    req.on('error', reject);
  });
  if (chunks.length === 0) return null;
  try {
    const parsed = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

/** Bearer token → accountId (sub), or null. Same shape as the aa routes. */
async function resolveSub(provider: Provider, ctx: Ctx): Promise<string | null> {
  const auth = ctx.headers.authorization;
  if (typeof auth !== 'string') return null;
  const m = /^Bearer\s+(.+)$/i.exec(auth.trim());
  if (!m || !m[1]) return null;
  try {
    const token = await provider.AccessToken.find(m[1].trim());
    if (!token || token.isExpired) return null;
    return typeof token.accountId === 'string' ? token.accountId : null;
  } catch {
    return null;
  }
}
