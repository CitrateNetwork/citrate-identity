/**
 * SIWE (EIP-4361) login core for the Citrate OIDC authority — IDP-S1.5.
 *
 * panva `oidc-provider` has NO built-in SIWE. This module is the verification
 * core that a custom interaction (`src/siwe-routes.ts`) drives:
 *
 *   GET  /siwe/challenge  → issue a fresh single-use nonce (replay defence)
 *   POST /siwe/verify     → parse + verify an EIP-4361 message, recover the
 *                            address, and hand it to panva as the logged-in
 *                            account (`accountId = checksummed address`).
 *
 * Security checks enforced here (red-team v2 must-haves):
 *   - fresh, single-use **nonce** (replay)            → NonceStore (consume once)
 *   - **domain binding** (anti-phishing)              → message.domain === host
 *   - **expirationTime** not in the past              → siwe verify `time`
 *   - **chainId** === Citrate (40204)                 → explicit equality check
 *   - **low-S** signatures only (malleability)        → parseSignature + s-bound
 *   - **EIP-1271** smart-contract-wallet signatures   → viem public client call
 */
import {
  createPublicClient,
  http,
  isAddressEqual,
  getAddress,
  parseSignature,
  recoverMessageAddress,
  verifyMessage,
  type Address,
  type Hex,
  type PublicClient,
} from 'viem';
import { SiweMessage, generateNonce } from 'siwe';

/** Citrate L2 chain id. SIWE messages MUST be bound to this chain. */
export const CITRATE_CHAIN_ID = 40204;

/**
 * secp256k1 group order N. A signature is non-malleable (canonical, "low-S")
 * iff s <= N/2. Ethereum (EIP-2) only accepts low-S on-chain, but raw
 * `ecrecover` (and viem's `recoverMessageAddress`) will happily recover the
 * SAME address from the high-S twin of a signature — so we reject high-S
 * explicitly to close the malleability hole.
 */
const SECP256K1_N =
  0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const SECP256K1_HALF_N = SECP256K1_N / 2n;

/** Reasons a verification can fail. Surfaced to the caller as 4xx, never 5xx. */
export type SiweFailureReason =
  | 'unknown_nonce'
  | 'nonce_mismatch'
  | 'domain_mismatch'
  | 'expired'
  | 'not_yet_valid'
  | 'wrong_chain'
  | 'malleable_signature'
  | 'bad_signature'
  | 'malformed_message';

export class SiweVerificationError extends Error {
  constructor(public readonly reason: SiweFailureReason, message?: string) {
    super(message ?? reason);
    this.name = 'SiweVerificationError';
  }
}

/** A value returned directly (in-memory) or via a Promise (Redis round-trip). */
export type MaybeAsync<T> = T | Promise<T>;

/**
 * Single-use nonce store with a short TTL.
 *
 * An in-memory Map is correct for the single-instance dev / test authority. For
 * the multi-instance / HA deployment of auth.citrate.ai the SAME interface is
 * backed by Redis ({@link RedisNonceStore} in nonce-redis.ts), selected by
 * `REDIS_URL`, so a nonce issued by one instance is consumable exactly once
 * across all of them. The interface is deliberately small (and `MaybeAsync`, like
 * the {@link KycStore} seam) so the swap is a true drop-in: every call site
 * `await`s the result, and awaiting the in-memory store's plain value is a no-op
 * — so the in-memory path stays synchronous in practice while Redis is async.
 */
export interface NonceStore {
  issue(): MaybeAsync<string>;
  /** Returns true and consumes the nonce iff it is known and unexpired. */
  consume(nonce: string): MaybeAsync<boolean>;
}

export class InMemoryNonceStore implements NonceStore {
  private readonly nonces = new Map<string, number>(); // nonce → expiry (ms epoch)

  constructor(private readonly ttlMs: number = 5 * 60 * 1000) {}

  issue(): string {
    this.sweep();
    const nonce = generateNonce();
    this.nonces.set(nonce, Date.now() + this.ttlMs);
    return nonce;
  }

  consume(nonce: string): boolean {
    const expiry = this.nonces.get(nonce);
    if (expiry === undefined) return false; // unknown OR already consumed
    // One-time: remove immediately, regardless of expiry, so a replay of the
    // same value can never succeed even within the TTL window.
    this.nonces.delete(nonce);
    if (Date.now() > expiry) return false; // known but expired
    return true;
  }

  private sweep(): void {
    const now = Date.now();
    for (const [nonce, expiry] of this.nonces) {
      if (now > expiry) this.nonces.delete(nonce);
    }
  }
}

/** Enforce EIP-2 low-S to defeat signature malleability. */
function assertLowS(signature: Hex): void {
  let parsed;
  try {
    parsed = parseSignature(signature);
  } catch {
    // Not an ECDSA r,s,v hex (e.g. an EIP-1271 contract signature blob). The
    // malleability bound is meaningless for contract signatures; the contract
    // is the authority on validity. Let the 1271 path handle it.
    return;
  }
  const s = BigInt(parsed.s);
  if (s > SECP256K1_HALF_N) {
    throw new SiweVerificationError(
      'malleable_signature',
      'high-S signature rejected (EIP-2 malleability)',
    );
  }
}

export interface VerifySiweParams {
  /** Raw EIP-4361 message string the wallet signed. */
  message: string;
  /** Hex signature (EOA ECDSA, or EIP-1271 contract signature bytes). */
  signature: string;
  /** The authority host the message must be bound to (e.g. `auth.citrate.ai`). */
  expectedDomain: string;
  /** Nonce store; the message nonce is consumed one-time on success path. */
  nonceStore: NonceStore;
  /**
   * Optional viem public client for EIP-1271 (smart-contract / Safe wallets).
   * When the recovered EOA path fails AND a client is provided, we ask the
   * account contract via `isValidSignature` (ERC-1271 / ERC-6492) on-chain.
   */
  publicClient?: PublicClient;
  /** Override for tests / chains; defaults to {@link CITRATE_CHAIN_ID}. */
  chainId?: number;
  /** Injectable clock for deterministic expiry tests. */
  now?: Date;
}

export interface VerifySiweResult {
  /** EIP-55 checksummed address that authenticated. Used as OIDC `accountId`. */
  address: Address;
  /** The verified EIP-4361 message fields. */
  message: SiweMessage;
  /** How the signature was verified. */
  method: 'eoa' | 'eip1271';
}

/**
 * Verify a SIWE login end-to-end. Throws {@link SiweVerificationError} for any
 * policy failure (caller maps to 401/400). The nonce is consumed exactly once,
 * up front, so a replay of a valid (message, signature) pair is rejected.
 */
export async function verifySiweLogin(
  params: VerifySiweParams,
): Promise<VerifySiweResult> {
  const {
    message,
    signature,
    expectedDomain,
    nonceStore,
    publicClient,
    chainId = CITRATE_CHAIN_ID,
    now = new Date(),
  } = params;

  let siwe: SiweMessage;
  try {
    siwe = new SiweMessage(message);
  } catch {
    throw new SiweVerificationError(
      'malformed_message',
      'message is not a valid EIP-4361 message',
    );
  }

  // 1) Replay defence: the nonce must be known and unused. Consume it ONCE,
  //    before any expensive crypto, so even a valid signature cannot be
  //    replayed and a forced-error path cannot leave the nonce reusable.
  if (!(await nonceStore.consume(siwe.nonce))) {
    throw new SiweVerificationError(
      'unknown_nonce',
      'nonce is unknown, already used, or expired',
    );
  }

  // 2) Chain binding: the session must be bound to Citrate.
  if (siwe.chainId !== chainId) {
    throw new SiweVerificationError(
      'wrong_chain',
      `chainId ${siwe.chainId} != Citrate ${chainId}`,
    );
  }

  // 3) Malleability: reject high-S ECDSA signatures (no-op for 1271 blobs).
  assertLowS(signature as Hex);

  // 4) Domain binding + expiry/notBefore + nonce echo: let siwe enforce the
  //    EIP-4361 invariants. We pass our expectedDomain and the consumed nonce
  //    so a message minted for a different host/nonce is rejected here.
  //    `suppressExceptions` returns a result object instead of throwing so we
  //    can map siwe's error types onto our own taxonomy.
  const verification = await siwe.verify(
    {
      signature,
      domain: expectedDomain,
      nonce: siwe.nonce,
      time: now.toISOString(),
    },
    {
      // EIP-1271: a viem PublicClient is adapted to the minimal ethers-like
      // provider siwe expects (a `call`-capable object). See below.
      provider: publicClient
        ? viemPublicClientAsSiweProvider(publicClient)
        : undefined,
      suppressExceptions: true,
    },
  );

  if (!verification.success) {
    throw mapSiweError(verification.error);
  }

  // 5) Determine HOW it verified + recover the canonical address.
  //    For an EOA, recover from the ECDSA signature and confirm it matches the
  //    message address. For a contract wallet (EIP-1271) recovery is not
  //    applicable — siwe already confirmed validity on-chain — so we trust the
  //    message's (checksummed) address.
  const claimed = getAddress(siwe.address);
  let method: VerifySiweResult['method'] = 'eip1271';
  try {
    const recovered = await recoverMessageAddress({
      message: siwe.prepareMessage(),
      signature: signature as Hex,
    });
    if (isAddressEqual(recovered, claimed)) {
      method = 'eoa';
    } else if (!publicClient) {
      // Recovery mismatch and no on-chain path → not us.
      throw new SiweVerificationError('bad_signature', 'address mismatch');
    }
  } catch (err) {
    if (err instanceof SiweVerificationError) throw err;
    // Signature is not a recoverable ECDSA sig (contract signature). The
    // EIP-1271 on-chain check in step 4 is authoritative; keep method=eip1271.
    if (!publicClient) {
      throw new SiweVerificationError(
        'bad_signature',
        'signature is neither a valid EOA signature nor verifiable on-chain',
      );
    }
  }

  return { address: claimed, message: siwe, method };
}

/** Map siwe's error taxonomy to ours; default to a generic bad signature. */
function mapSiweError(error: unknown): SiweVerificationError {
  const type =
    error && typeof error === 'object' && 'type' in error
      ? String((error as { type: unknown }).type)
      : '';
  if (type.includes('Expired')) return new SiweVerificationError('expired', type);
  if (type.includes('not valid yet'))
    return new SiweVerificationError('not_yet_valid', type);
  if (type.includes('Domain'))
    return new SiweVerificationError('domain_mismatch', type);
  if (type.includes('Nonce'))
    return new SiweVerificationError('nonce_mismatch', type);
  return new SiweVerificationError('bad_signature', type || 'signature invalid');
}

/**
 * Build a viem PublicClient for EIP-1271 verification against a chain RPC.
 * Production passes the Citrate RPC URL; tests can inject their own client
 * (e.g. pointed at an anvil/mock node) instead of calling this.
 */
export function createCitratePublicClient(rpcUrl: string): PublicClient {
  return createPublicClient({ transport: http(rpcUrl) }) as PublicClient;
}

/**
 * siwe@3 still types its EIP-1271 `provider` as an ethers v5 provider and only
 * uses `provider.call({ to, data })` under the hood to invoke
 * `isValidSignature`. We adapt a viem PublicClient to that single method so we
 * can keep viem as the only chain library (no ethers dependency). The cast is
 * intentional and narrow: siwe never touches any other provider method during
 * EIP-1271 validation.
 */
export function viemPublicClientAsSiweProvider(client: PublicClient): unknown {
  return {
    async call(tx: { to: string; data: string }): Promise<string> {
      const result = await client.call({
        to: tx.to as Address,
        data: tx.data as Hex,
      });
      return result.data ?? '0x';
    },
  };
}
