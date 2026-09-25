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
  /** The settlement-attribution wallet, if any. See {@link setCanonical}. */
  canonicalFor(sub: string): Promise<string | null>;
  /**
   * Make an ALREADY-LINKED wallet the canonical one for `sub`.
   *
   * Canonical defaults to FIRST-linked (the ADR rule) precisely so a restart or
   * a stray second link can never silently move a member's pay-to address. That
   * default is correct and stays. What it lacked was any deliberate way OUT: a
   * member whose device custody vault is replaced links a new wallet, the claim
   * stays pinned to the old one, and the desktop — which requires
   * `wallet_address == this device's custody address` — blocks forever with no
   * error anywhere. Observed live 2026-08-04 on sub a22d6f95.
   *
   * So rebinding is explicit, authenticated, and narrow: `address` MUST already
   * be a proven link for THIS `sub`. It cannot introduce an address, only choose
   * among ones already proven — the promotion can never outrun the proof.
   *
   * Throws {@link WalletRegistryError} if the wallet is not linked to `sub`.
   */
  setCanonical(sub: string, address: string): Promise<void>;
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
  /** sub → explicitly chosen canonical address (lowercase). Absent = first-linked. */
  private canonicalOverride = new Map<string, string>();

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

  async list(sub: string): Promise<LinkedWallet[]> {
    const mine = this.rows.filter((r) => r.sub === sub).sort((a, b) => a.seq - b.seq);
    const canonical = this.resolveCanonical(sub, mine);
    return mine.map((r) => ({
      address: r.address,
      canonical: r.address === canonical,
      linkedAt: r.linkedAt,
    }));
  }

  async canonicalFor(sub: string): Promise<string | null> {
    const mine = this.rows.filter((r) => r.sub === sub).sort((a, b) => a.seq - b.seq);
    return this.resolveCanonical(sub, mine);
  }

  async setCanonical(sub: string, address: string): Promise<void> {
    const addr = address.toLowerCase();
    const owned = this.rows.some((r) => r.sub === sub && r.address === addr);
    if (!owned) {
      throw new WalletRegistryError('wallet is not linked to this identity');
    }
    this.canonicalOverride.set(sub, addr);
  }

  async unlink(sub: string, address: string): Promise<void> {
    const addr = address.toLowerCase();
    this.rows = this.rows.filter((r) => !(r.sub === sub && r.address === addr));
    // Drop a dangling override so canonical falls back to first-linked rather
    // than pointing at a wallet that is no longer proven.
    if (this.canonicalOverride.get(sub) === addr) this.canonicalOverride.delete(sub);
  }

  /** Explicit choice wins; otherwise first-linked (the ADR default). */
  private resolveCanonical(sub: string, ordered: Row[]): string | null {
    const chosen = this.canonicalOverride.get(sub);
    if (chosen && ordered.some((r) => r.address === chosen)) return chosen;
    return ordered[0]?.address ?? null;
  }

  private toLinked(row: Row): LinkedWallet {
    const mine = this.rows.filter((r) => r.sub === row.sub).sort((a, b) => a.seq - b.seq);
    return {
      address: row.address,
      canonical: this.resolveCanonical(row.sub, mine) === row.address,
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
  /**
   * Called when a sub's CANONICAL wallet changes — on the first proven link,
   * and on an unlink that promotes a different wallet (or leaves none, `null`).
   *
   * WHY THIS HOOK EXISTS. `findAccount` already prefers a user's bound
   * `primaryWallet` over the counterfactual CREATE2 prediction when minting the
   * `wallet_address` claim — but nothing ever set `primaryWallet`, so the claim
   * was always the predicted smart-wallet address, which no private key can
   * spend from. Anything that pays that address (the validator bond) sends funds
   * the member cannot move. This hook is the missing wire between the
   * proof-of-control link that already exists here and the setter that already
   * exists on the user store.
   *
   * It is a CALLBACK rather than a direct user-store import so this module stays
   * store-agnostic and unit-testable, matching how {@link WalletRegistry} is
   * injected. A throw is swallowed by the caller: the link itself is already
   * durable and proven, and failing the request afterwards would tell the client
   * its wallet was not linked when it was.
   */
  onCanonicalWalletChange?: (sub: string, address: string | null) => Promise<void>;
}

export function mountIdentityRegistryRoutes(
  provider: Provider,
  options: IdentityRegistryOptions,
): void {
  const { authority, chainId, nonceStore, onCanonicalWalletChange } = options;

  /**
   * Report the current canonical wallet. Swallows a hook failure: the link/unlink
   * it follows is already committed, so surfacing the error would report failure
   * for work that succeeded. Logged, never thrown.
   */
  async function announceCanonical(sub: string): Promise<void> {
    if (!onCanonicalWalletChange) return;
    try {
      const canonical = await getWalletRegistry().canonicalFor(sub);
      await onCanonicalWalletChange(sub, canonical ? getAddress(canonical) : null);
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error(
        `[identity-registry] canonical-wallet hook failed for ${sub}: ${(err as Error).message}`,
      );
    }
  }

  provider.use(async (ctx: Ctx, next: Next) => {
    const match = /^\/identity\/([^/]+)\/wallets(?:\/(.+))?$/.exec(ctx.path);
    if (!match) return next();
    const sub = decodeURIComponent(match[1] ?? '');
    const tail = match[2] ? decodeURIComponent(match[2]) : undefined;

    // Every route requires a Bearer token for the SAME sub — fail closed.
    const token = await resolveToken(provider, ctx);
    if (!token) {
      respond(ctx, 401, { error: 'unauthorized', reason: 'access token required' });
      return;
    }
    const caller = token.accountId;
    if (caller !== sub) {
      respond(ctx, 403, { error: 'forbidden', reason: 'token subject does not match :sub' });
      return;
    }
    // PBA-L3a-005: changing which wallets speak for this identity (and which one
    // is the pay-to address) is a wallet-app action. Any other RP's token (a
    // leaked explorer/docs token) may still LIST, but never mutate.
    if (ctx.method !== 'GET') {
      if (!WALLET_LINK_CLIENT_IDS.has(token.clientId)) {
        respond(ctx, 403, { error: 'client_not_permitted', reason: 'only Citrate wallet apps may change linked wallets' });
        return;
      }
      if (!token.scopes.has('wallet')) {
        respond(ctx, 403, { error: 'insufficient_scope', reason: 'the wallet scope is required to change linked wallets' });
        return;
      }
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
        // Only a canonical link moves the `wallet_address` claim — a second
        // wallet is attributable but does not repoint the member's pay-to
        // address out from under them.
        if (linked.canonical) await announceCanonical(sub);
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

    // POST /identity/:sub/wallets/:address/canonical → make it the pay-to wallet
    //
    // Canonical defaults to FIRST-linked so a restart or a stray second link can
    // never silently move a member's pay-to address. That default is right and
    // stays; this is the deliberate way out of it. A member whose device custody
    // vault is replaced links a new wallet, and without this the claim stays
    // pinned to the old one while the desktop — which requires
    // `wallet_address == this device's custody address` — blocks forever with no
    // error anywhere (observed live 2026-08-04, sub a22d6f95).
    //
    // Narrow by construction: same-sub bearer is already enforced above, and
    // `setCanonical` refuses any address not already PROVEN for this sub. So the
    // promotion can never outrun the proof — it only re-orders wallets whose
    // ownership was established by the EIP-191 challenge.
    if (ctx.method === 'POST' && tail !== undefined && tail.endsWith('/canonical')) {
      const raw = tail.slice(0, -'/canonical'.length);
      if (!isAddress(raw)) {
        respond(ctx, 400, { error: 'invalid_request', reason: 'path address malformed' });
        return;
      }
      try {
        await getWalletRegistry().setCanonical(sub, raw);
      } catch (err) {
        if (err instanceof WalletRegistryError) {
          respond(ctx, 409, { error: 'conflict', reason: err.message });
          return;
        }
        throw err;
      }
      // Unlike the link path, a hook failure here is NOT cosmetic: the whole
      // point of the call is to move the claim, so a swallowed failure would
      // report success while leaving the member exactly as blocked. It is still
      // logged-not-thrown inside `announceCanonical` (the registry write is
      // already durable), so re-read and tell the caller what actually landed.
      await announceCanonical(sub);
      const canonical = await getWalletRegistry().canonicalFor(sub);
      respond(ctx, 200, {
        ok: true,
        canonical: canonical ? getAddress(canonical) : null,
      });
      return;
    }

    // DELETE /identity/:sub/wallets/:address → unlink
    if (ctx.method === 'DELETE' && tail !== undefined) {
      if (!isAddress(tail)) {
        respond(ctx, 400, { error: 'invalid_request', reason: 'path address malformed' });
        return;
      }
      const wasCanonical = (await getWalletRegistry().canonicalFor(sub))?.toLowerCase();
      await getWalletRegistry().unlink(sub, tail);
      // Unlinking the canonical wallet promotes another (or leaves none, which
      // returns the claim to the predicted address). Re-announce so a stale
      // pay-to address can never outlive the link that justified it.
      if (wasCanonical && wasCanonical === tail.toLowerCase()) await announceCanonical(sub);
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

/**
 * PBA-L3a-005: the Citrate wallet apps that may change a member's linked
 * wallets (the desktop app, the native wallet, the wallet extension).
 */
export const WALLET_LINK_CLIENT_IDS: ReadonlySet<string> = new Set([
  'citrate-core',
  'citrate-gui-native',
  'citrate-wallet-extension',
]);

/** Bearer token → { accountId, clientId, scopes }, or null. */
async function resolveToken(
  provider: Provider,
  ctx: Ctx,
): Promise<{ accountId: string; clientId: string; scopes: Set<string> } | null> {
  const auth = ctx.headers.authorization;
  if (typeof auth !== 'string') return null;
  const m = /^Bearer\s+(.+)$/i.exec(auth.trim());
  if (!m || !m[1]) return null;
  try {
    const token = await provider.AccessToken.find(m[1].trim());
    if (!token || token.isExpired) return null;
    if (typeof token.accountId !== 'string' || typeof token.clientId !== 'string') return null;
    const scopes = new Set(String(token.scope ?? '').split(' ').filter((x) => x.length > 0));
    return { accountId: token.accountId, clientId: token.clientId, scopes };
  } catch {
    return null;
  }
}
