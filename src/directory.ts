/**
 * Self-published bindings directory — "find-via-X" (CitrateNetwork/citrate-core#61).
 *
 * # What this is
 *
 * A directory of SIGNED, SELF-PUBLISHED, REVOCABLE bindings, each asserting
 * `(platform, handle) ↔ a Citrate address`. It exists so a member who has opted
 * in can be discovered by their social handle (typeahead / lookup) and paid to
 * the address they proved they control — nothing more. It is a deliberate D-7
 * privacy exception, so the honesty rules are load-bearing:
 *
 *   - a binding is stored ONLY when BOTH proofs verify (see below);
 *   - reads return ONLY published, non-revoked bindings — never a guess, never a
 *     handle nobody published, never a bulk dump;
 *   - the whole surface is Bearer-gated (a signed-in member) + rate-limited, so
 *     it is not an open scraper.
 *
 * # The two proofs (why one is not enough)
 *
 * Scope is **self-published bindings only** — NO X API, NO follower import. So the
 * backend cannot call X to confirm a handle. What it CAN verify is the artefact the
 * desktop app (`citrate-core/src-tauri/src/social.rs`) already produces: the
 * wallet-signed **IdentityBinding** attestation.
 *
 *   1. `ownership_proof` — the app's existing social-ownership attestation. The
 *      wallet signs the EXACT EIP-191 message `social.rs::binding_message`
 *      ({@link buildSocialBindingMessage}) over `(network, handle, address,
 *      nonce)`; recording that flips a link to `verified` in the app, and
 *      `social_ingest_binding` re-verifies a peer's copy the SAME way. We reuse
 *      that verifier byte-for-byte: reconstruct the message from the request's
 *      `(platform, handle, address)` + the proof's `nonce`, and require the
 *      signature to recover to `address`. This is the app's own proof of
 *      handle↔address, re-checked server-side.
 *
 *      HONEST LIMIT: the OAuth PKCE step that proves the human controls the X /
 *      Discord *handle* is DEVICE-LOCAL and server-blind by design (ADR-2026-08-30
 *      — the OAuth token never crosses the invoke boundary). So the backend does
 *      NOT re-verify the OAuth; the wallet-signed IdentityBinding is exactly the
 *      shareable artefact the app treats as the proof, and re-checking that
 *      signature is the faithful server-side reuse. See the module doc in
 *      social.rs (`social_ingest_binding`) for the mirror of this check.
 *
 *   2. `sig` — a fresh signature by the SAME address over a directory-scoped,
 *      versioned statement ({@link buildDirectoryPublishStatement}) carrying
 *      `bound_at`. It authorizes THIS publish into THIS directory at THIS time
 *      (last-writer-wins is keyed on `bound_at`), so re-presenting an old social
 *      binding cannot silently repurpose it.
 *
 * Both signatures must recover to the same `address`, which ties the social
 * attestation and the directory intent to one key.
 *
 * # Signature primitive
 *
 * EIP-191 `personal_sign`, verified with ethers `verifyMessage` — the SAME
 * primitive `identity-registry.ts::verifyWalletLinkProof` uses for wallet links,
 * so there is one signature-verification path in this service.
 */

import type Provider from 'oidc-provider';
import { getAddress, isAddress, verifyMessage } from 'ethers';

type Ctx = Parameters<Parameters<Provider['use']>[0]>[0];
type Next = Parameters<Parameters<Provider['use']>[0]>[1];

/** The only platforms self-published bindings are accepted for (mirror social.rs `net_cfg`). */
export const DIRECTORY_PLATFORMS = ['x', 'discord'] as const;
export type DirectoryPlatform = (typeof DIRECTORY_PLATFORMS)[number];

/** Max results a typeahead search returns — a cap, never a dump. */
export const SEARCH_LIMIT = 20;

/** Handles are alphanumeric + `_` + `.` (covers X and Discord), 1–64 chars. */
const HANDLE_RE = /^[A-Za-z0-9_.]{1,64}$/;

/** Oldest plausible `bound_at` (2020-01-01Z) — rejects a zero/garbage timestamp. */
const MIN_BOUND_AT = 1_577_836_800;
/** How far into the future a `bound_at` may sit (clock skew), in seconds. */
const BOUND_AT_FUTURE_SKEW = 300;

// ── canonical signed statements ──────────────────────────────────────────

/**
 * The EXACT EIP-191 message the desktop wallet signs to prove handle↔address —
 * ported byte-for-byte from `citrate-core/src-tauri/src/social.rs::binding_message`
 * so an attestation minted by the app verifies here without re-signing. `handle`
 * is the provider handle WITHOUT a leading `@` (the app stores it that way and the
 * message prepends the `@`), and `address` must be the exact string the app signed
 * (its EIP-55 checksummed address); verification also tries the checksummed form so
 * a client that lower-cased the field still validates.
 */
export function buildSocialBindingMessage(
  network: string,
  handle: string,
  address: string,
  nonce: string,
): string {
  return (
    `Citrate identity binding\n` +
    `Network: ${network}\n` +
    `Handle: @${handle}\n` +
    `Address: ${address}\n` +
    `Nonce: ${nonce}\n\n` +
    `Signing proves this wallet controls this social account. ` +
    `Shared only with your groups, never published.`
  );
}

/**
 * The directory-scoped statement `sig` covers — deterministic and case-folded so a
 * client and the server derive the identical string: lower-cased address, the
 * normalized (lower, no `@`) handle key, and the integer `bound_at`.
 */
export function buildDirectoryPublishStatement(args: {
  platform: DirectoryPlatform;
  handleKey: string;
  address: string;
  boundAt: number;
}): string {
  return (
    `citrate-directory-binding:v1:${args.platform}:${args.handleKey}:` +
    `${args.address.toLowerCase()}:${args.boundAt}`
  );
}

/** The statement `sig` covers for a revoke — no timestamp; re-revoking is idempotent. */
export function buildDirectoryRevokeStatement(args: {
  platform: DirectoryPlatform;
  handleKey: string;
  address: string;
}): string {
  return (
    `citrate-directory-revoke:v1:${args.platform}:${args.handleKey}:` +
    `${args.address.toLowerCase()}`
  );
}

/**
 * Recover an EIP-191 signature and test it against `address` (case-insensitive).
 * Returns false for any malformed signature rather than throwing.
 */
export function signatureMatches(message: string, signature: string, address: string): boolean {
  try {
    return verifyMessage(message, signature).toLowerCase() === address.toLowerCase();
  } catch {
    return false;
  }
}

/**
 * Verify the app's social-ownership attestation for `(platform, handle, address)`.
 * Reconstructs `binding_message` and accepts if the proof signature recovers to
 * `address` under EITHER the address exactly as supplied (the app signs its
 * checksummed address) or its EIP-55 form — so a lower-cased field still verifies.
 */
export function verifyOwnershipProof(args: {
  platform: DirectoryPlatform;
  handle: string; // signed handle, no leading @
  address: string;
  nonce: string;
  signature: string;
}): boolean {
  const candidates = new Set<string>([args.address]);
  try {
    candidates.add(getAddress(args.address));
  } catch {
    /* not a valid address — the caller already validated, defensive only */
  }
  for (const addr of candidates) {
    const message = buildSocialBindingMessage(args.platform, args.handle, addr, args.nonce);
    if (signatureMatches(message, args.signature, args.address)) return true;
  }
  return false;
}

// ── normalization ────────────────────────────────────────────────────────

/** Strip a single leading `@` — the signed handle form (matches social.rs). */
export function signedHandle(handle: string): string {
  return handle.startsWith('@') ? handle.slice(1) : handle;
}

/** Lower-cased, `@`-stripped handle used as the directory key + search prefix. */
export function handleKeyOf(handle: string): string {
  return signedHandle(handle).toLowerCase();
}

// ── store ────────────────────────────────────────────────────────────────

/** A binding as stored / returned by the store. `address` is lower-case 0x. */
export interface BindingRecord {
  platform: DirectoryPlatform;
  /** Lower-cased, `@`-stripped — the uniqueness + lookup key. */
  handleKey: string;
  /** The signed handle verbatim (display form, no `@`). */
  handle: string;
  /** Lower-case 0x address. */
  address: string;
  displayName?: string;
  boundAt: number;
}

/** What a lookup returns for a live binding. */
export interface LookupHit {
  address: string;
  boundAt: number;
}

/** A search row — handle is a discovery key; the app decides display. */
export interface SearchHit {
  handle: string;
  address: string;
  displayName?: string;
}

export type UpsertOutcome = 'stored' | 'unchanged' | 'stale';

/**
 * Directory store. In-memory for dev/tests; Postgres in prod ({@link
 * PgDirectoryStore} in directory-pg.ts), selected by `DATABASE_URL`. Mirrors the
 * `WalletRegistry` seam so the swap is a drop-in.
 */
export interface DirectoryStore {
  /**
   * Upsert a verified binding under `(platform, handleKey)`, last-writer by
   * `boundAt`. Returns `stored` when it lands (a fresh publish clears any
   * tombstone), `unchanged` when an identical live binding already exists, and
   * `stale` when `boundAt` does not advance past the stored one — which is also
   * what stops a replayed publish from silently un-revoking a tombstoned handle.
   */
  upsert(rec: BindingRecord): Promise<UpsertOutcome>;
  /**
   * Tombstone the binding for `(platform, handleKey)` iff it is live AND bound to
   * `address` (lower-case). Returns true when one was revoked, false when there is
   * no live binding for that address.
   */
  revoke(platform: DirectoryPlatform, handleKey: string, address: string): Promise<boolean>;
  /** The live (non-revoked) binding for an exact handle, or null. Never a guess. */
  lookup(platform: DirectoryPlatform, handleKey: string): Promise<LookupHit | null>;
  /** Up to `limit` live bindings whose handle key starts with `prefix`. */
  search(platform: DirectoryPlatform, prefix: string, limit: number): Promise<SearchHit[]>;
}

interface Row extends BindingRecord {
  revoked: boolean;
}

/** In-memory store (dev/test). The Postgres impl mirrors this behaviour exactly. */
export class InMemoryDirectoryStore implements DirectoryStore {
  private readonly rows = new Map<string, Row>();

  private key(platform: string, handleKey: string): string {
    return `${platform} ${handleKey}`;
  }

  async upsert(rec: BindingRecord): Promise<UpsertOutcome> {
    const k = this.key(rec.platform, rec.handleKey);
    const cur = this.rows.get(k);
    const address = rec.address.toLowerCase();
    if (!cur) {
      this.rows.set(k, { ...rec, address, revoked: false });
      return 'stored';
    }
    if (rec.boundAt > cur.boundAt) {
      this.rows.set(k, { ...rec, address, revoked: false });
      return 'stored';
    }
    // boundAt does not advance. Only an EXACT match of a still-live binding is a
    // harmless no-op; anything else (older, or an equal-boundAt replay against a
    // tombstone / different fields) is refused so a revoke cannot be undone.
    const identical =
      !cur.revoked &&
      rec.boundAt === cur.boundAt &&
      cur.address === address &&
      cur.handle === rec.handle &&
      (cur.displayName ?? undefined) === (rec.displayName ?? undefined);
    return identical ? 'unchanged' : 'stale';
  }

  async revoke(platform: DirectoryPlatform, handleKey: string, address: string): Promise<boolean> {
    const cur = this.rows.get(this.key(platform, handleKey));
    if (!cur || cur.revoked || cur.address !== address.toLowerCase()) return false;
    cur.revoked = true;
    return true;
  }

  async lookup(platform: DirectoryPlatform, handleKey: string): Promise<LookupHit | null> {
    const cur = this.rows.get(this.key(platform, handleKey));
    if (!cur || cur.revoked) return null;
    return { address: cur.address, boundAt: cur.boundAt };
  }

  async search(platform: DirectoryPlatform, prefix: string, limit: number): Promise<SearchHit[]> {
    const out: SearchHit[] = [];
    const keys: Row[] = [];
    for (const row of this.rows.values()) {
      if (row.platform !== platform || row.revoked) continue;
      if (!row.handleKey.startsWith(prefix)) continue;
      keys.push(row);
    }
    keys.sort((a, b) => (a.handleKey < b.handleKey ? -1 : a.handleKey > b.handleKey ? 1 : 0));
    for (const row of keys.slice(0, limit)) {
      out.push({
        handle: row.handle,
        address: getAddress(row.address),
        ...(row.displayName ? { displayName: row.displayName } : {}),
      });
    }
    return out;
  }
}

// ── process-wide singleton (mirrors identity-registry / KYC store pattern) ─

let store: DirectoryStore = new InMemoryDirectoryStore();

export function getDirectoryStore(): DirectoryStore {
  return store;
}

export function setDirectoryStore(s: DirectoryStore): void {
  store = s;
}

// ── request validation ─────────────────────────────────────────────────────

interface ParsedPublish {
  platform: DirectoryPlatform;
  handle: string; // signed handle, no @
  handleKey: string;
  address: string; // as supplied (checksum-preserving for the ownership message)
  displayName?: string;
  boundAt: number;
  ownershipNonce: string;
  ownershipSig: string;
  sig: string;
}

type ParseError = { error: string; reason: string };

function isPlatform(v: unknown): v is DirectoryPlatform {
  return typeof v === 'string' && (DIRECTORY_PLATFORMS as readonly string[]).includes(v);
}

/** Validate + normalize a publish body. Returns a {@link ParseError} on any bad field. */
export function parsePublishBody(
  body: Record<string, unknown> | null,
  now: number,
): ParsedPublish | ParseError {
  if (!body) return { error: 'invalid_request', reason: 'a JSON body is required' };
  if (!isPlatform(body.platform)) {
    return { error: 'invalid_request', reason: 'platform must be "x" or "discord"' };
  }
  if (typeof body.handle !== 'string' || !HANDLE_RE.test(signedHandle(body.handle))) {
    return { error: 'invalid_request', reason: 'handle is required (1–64 of [A-Za-z0-9_.], optional leading @)' };
  }
  if (typeof body.address !== 'string' || !isAddress(body.address)) {
    return { error: 'invalid_request', reason: 'address must be a 20-byte 0x address' };
  }
  if (
    typeof body.bound_at !== 'number' ||
    !Number.isInteger(body.bound_at) ||
    body.bound_at < MIN_BOUND_AT ||
    body.bound_at > now + BOUND_AT_FUTURE_SKEW
  ) {
    return { error: 'invalid_request', reason: 'bound_at must be a unix-seconds integer near now' };
  }
  const proof = body.ownership_proof;
  if (!proof || typeof proof !== 'object' || Array.isArray(proof)) {
    return { error: 'invalid_request', reason: 'ownership_proof object is required' };
  }
  const nonce = (proof as Record<string, unknown>).nonce;
  const proofSig = (proof as Record<string, unknown>).signature;
  if (typeof nonce !== 'string' || nonce === '' || nonce.length > 256) {
    return { error: 'invalid_request', reason: 'ownership_proof.nonce is required' };
  }
  if (typeof proofSig !== 'string' || !/^0x[0-9a-fA-F]+$/.test(proofSig)) {
    return { error: 'invalid_request', reason: 'ownership_proof.signature must be 0x hex' };
  }
  if (typeof body.sig !== 'string' || !/^0x[0-9a-fA-F]+$/.test(body.sig)) {
    return { error: 'invalid_request', reason: 'sig must be a 0x hex signature' };
  }
  let displayName: string | undefined;
  if (body.display_name !== undefined && body.display_name !== null) {
    if (typeof body.display_name !== 'string' || body.display_name.length > 128) {
      return { error: 'invalid_request', reason: 'display_name must be a string ≤ 128 chars' };
    }
    const trimmed = body.display_name.trim();
    if (trimmed !== '') displayName = trimmed;
  }
  return {
    platform: body.platform,
    handle: signedHandle(body.handle),
    handleKey: handleKeyOf(body.handle),
    address: body.address,
    ...(displayName ? { displayName } : {}),
    boundAt: body.bound_at,
    ownershipNonce: nonce,
    ownershipSig: proofSig,
    sig: body.sig,
  };
}

interface ParsedRevoke {
  platform: DirectoryPlatform;
  handleKey: string;
  address: string;
  sig: string;
}

export function parseRevokeBody(body: Record<string, unknown> | null): ParsedRevoke | ParseError {
  if (!body) return { error: 'invalid_request', reason: 'a JSON body is required' };
  if (!isPlatform(body.platform)) {
    return { error: 'invalid_request', reason: 'platform must be "x" or "discord"' };
  }
  if (typeof body.handle !== 'string' || !HANDLE_RE.test(signedHandle(body.handle))) {
    return { error: 'invalid_request', reason: 'handle is required' };
  }
  if (typeof body.address !== 'string' || !isAddress(body.address)) {
    return { error: 'invalid_request', reason: 'address must be a 20-byte 0x address' };
  }
  if (typeof body.sig !== 'string' || !/^0x[0-9a-fA-F]+$/.test(body.sig)) {
    return { error: 'invalid_request', reason: 'sig must be a 0x hex signature' };
  }
  return {
    platform: body.platform,
    handleKey: handleKeyOf(body.handle),
    address: body.address,
    sig: body.sig,
  };
}

// ── HTTP surface ────────────────────────────────────────────────────────────

/**
 * In-memory per-subject sliding-window limiter. Prod runs a single identity
 * container, so a process-local window is effectively global; it blunts a
 * leaked-token scrape/spam flood — the proof checks are the real guard. Mirrors
 * `kyc-handoff-routes.ts::SubjectRateLimiter`.
 */
class SubjectRateLimiter {
  private readonly hits = new Map<string, number[]>();
  constructor(
    private readonly windowMs = 60_000,
    private readonly max = 60,
  ) {}

  allow(sub: string): boolean {
    const now = Date.now();
    const cutoff = now - this.windowMs;
    const recent = (this.hits.get(sub) ?? []).filter((t) => t > cutoff);
    if (recent.length >= this.max) {
      this.hits.set(sub, recent);
      return false;
    }
    recent.push(now);
    this.hits.set(sub, recent);
    return true;
  }
}

export interface DirectoryRoutesOptions {
  /** Injectable clock (seconds resolution) for deterministic tests. */
  now?: () => number;
  /** Rate-limit window/cap override for tests. */
  rateLimit?: { windowMs: number; max: number };
}

export function mountDirectoryRoutes(provider: Provider, options: DirectoryRoutesOptions = {}): void {
  const nowSec = options.now ?? (() => Math.floor(Date.now() / 1000));
  const limiter = options.rateLimit
    ? new SubjectRateLimiter(options.rateLimit.windowMs, options.rateLimit.max)
    : new SubjectRateLimiter();

  provider.use(async (ctx: Ctx, next: Next) => {
    if (!ctx.path.startsWith('/directory/')) return next();

    // Every route requires a signed-in member — fail closed. Reads must not be an
    // open scraper; writes are additionally authenticated by the signatures below.
    const sub = await resolveSub(provider, ctx);
    if (!sub) {
      respond(ctx, 401, { error: 'unauthorized', reason: 'a valid Bearer access token is required' });
      return;
    }
    if (!limiter.allow(sub)) {
      respond(ctx, 429, { error: 'rate_limited', reason: 'too many directory requests; slow down' });
      return;
    }

    const dir = getDirectoryStore();

    // POST /directory/bindings — publishBinding
    if (ctx.path === '/directory/bindings' && ctx.method === 'POST') {
      const parsed = parsePublishBody(await readJson(ctx), nowSec());
      if ('error' in parsed) {
        respond(ctx, 400, parsed);
        return;
      }
      // Proof 1: the app's social-ownership attestation (handle ↔ address).
      const ownsHandle = verifyOwnershipProof({
        platform: parsed.platform,
        handle: parsed.handle,
        address: parsed.address,
        nonce: parsed.ownershipNonce,
        signature: parsed.ownershipSig,
      });
      if (!ownsHandle) {
        respond(ctx, 422, {
          error: 'invalid_ownership_proof',
          reason: 'ownership_proof does not prove this address controls this handle',
        });
        return;
      }
      // Proof 2: this address authorizes THIS directory publish (freshness/intent).
      const authorizes = signatureMatches(
        buildDirectoryPublishStatement({
          platform: parsed.platform,
          handleKey: parsed.handleKey,
          address: parsed.address,
          boundAt: parsed.boundAt,
        }),
        parsed.sig,
        parsed.address,
      );
      if (!authorizes) {
        respond(ctx, 422, {
          error: 'invalid_signature',
          reason: 'sig does not authorize this binding for this address',
        });
        return;
      }
      const outcome = await dir.upsert({
        platform: parsed.platform,
        handleKey: parsed.handleKey,
        handle: parsed.handle,
        address: parsed.address.toLowerCase(),
        ...(parsed.displayName ? { displayName: parsed.displayName } : {}),
        boundAt: parsed.boundAt,
      });
      if (outcome === 'stale') {
        respond(ctx, 409, {
          error: 'stale_binding',
          reason: 'a newer binding for this handle already exists (bound_at did not advance)',
        });
        return;
      }
      respond(ctx, 200, {
        status: outcome, // 'stored' | 'unchanged'
        binding: {
          platform: parsed.platform,
          handle: parsed.handle,
          address: getAddress(parsed.address),
          bound_at: parsed.boundAt,
        },
      });
      return;
    }

    // DELETE /directory/bindings — revokeBinding
    if (ctx.path === '/directory/bindings' && ctx.method === 'DELETE') {
      const parsed = parseRevokeBody(await readJson(ctx));
      if ('error' in parsed) {
        respond(ctx, 400, parsed);
        return;
      }
      const authorizes = signatureMatches(
        buildDirectoryRevokeStatement({
          platform: parsed.platform,
          handleKey: parsed.handleKey,
          address: parsed.address,
        }),
        parsed.sig,
        parsed.address,
      );
      if (!authorizes) {
        respond(ctx, 422, {
          error: 'invalid_signature',
          reason: 'sig does not authorize revoking this binding for this address',
        });
        return;
      }
      const revoked = await dir.revoke(parsed.platform, parsed.handleKey, parsed.address);
      if (!revoked) {
        respond(ctx, 404, {
          error: 'not_found',
          reason: 'no live binding for this handle is bound to this address',
        });
        return;
      }
      respond(ctx, 200, { status: 'revoked' });
      return;
    }

    // GET /directory/lookup?platform=&handle= — lookup
    if (ctx.path === '/directory/lookup' && ctx.method === 'GET') {
      const q = new URLSearchParams(ctx.querystring);
      const platform = q.get('platform');
      const handle = q.get('handle');
      if (!isPlatform(platform) || typeof handle !== 'string' || !HANDLE_RE.test(signedHandle(handle))) {
        respond(ctx, 400, { error: 'invalid_request', reason: 'platform and handle are required' });
        return;
      }
      const hit = await dir.lookup(platform, handleKeyOf(handle));
      respond(ctx, 200, hit ? { address: getAddress(hit.address), bound_at: hit.boundAt } : null);
      return;
    }

    // GET /directory/search?platform=&q= — search (typeahead)
    if (ctx.path === '/directory/search' && ctx.method === 'GET') {
      const q = new URLSearchParams(ctx.querystring);
      const platform = q.get('platform');
      const prefixRaw = q.get('q') ?? '';
      if (!isPlatform(platform)) {
        respond(ctx, 400, { error: 'invalid_request', reason: 'platform is required' });
        return;
      }
      const prefix = handleKeyOf(prefixRaw);
      // A blank prefix would match everything — that is a dump, which this service
      // never does. Require at least one character.
      if (prefix === '') {
        respond(ctx, 200, []);
        return;
      }
      const hits = await dir.search(platform, prefix, SEARCH_LIMIT);
      respond(
        ctx,
        200,
        hits.map((h) => ({
          handle: h.handle,
          address: h.address,
          ...(h.displayName ? { display_name: h.displayName } : {}),
        })),
      );
      return;
    }

    respond(ctx, 405, { error: 'method_not_allowed' });
  });
}

// ── helpers (shape-identical to identity-registry.ts) ─────────────────────

function respond(ctx: Ctx, status: number, body: unknown): void {
  ctx.status = status;
  ctx.type = 'application/json';
  ctx.set('cache-control', 'no-store');
  // Serialize explicitly: a `null` lookup result assigned to `ctx.body` directly
  // makes Koa collapse the response to a 204 with an empty body, so a lookup miss
  // would not round-trip as JSON `null`. Stringifying keeps `null` on the wire.
  ctx.body = JSON.stringify(body ?? null);
}

async function readJson(ctx: Ctx): Promise<Record<string, unknown> | null> {
  const existing = (ctx.request as { body?: unknown }).body;
  if (existing && typeof existing === 'object' && !Array.isArray(existing)) {
    return existing as Record<string, unknown>;
  }
  const chunks: Buffer[] = [];
  let size = 0;
  const ok = await new Promise<boolean>((resolve) => {
    const req = ctx.req as NodeJS.ReadableStream;
    req.on('data', (c: Buffer) => {
      size += c.length;
      if (size > 32 * 1024) {
        resolve(false);
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => resolve(true));
    req.on('error', () => resolve(false));
  });
  if (!ok || chunks.length === 0) return null;
  try {
    const parsed = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

/** Bearer token → accountId (sub), or null. Same shape as identity-registry / aa routes. */
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
