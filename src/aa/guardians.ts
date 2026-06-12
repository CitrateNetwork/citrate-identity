/**
 * Guardian nominations (EW-S1 WP-10, sprint item 31).
 *
 * A signed-in user nominates 2–7 guardian EOAs + an M-of-N threshold.
 * The nomination is STORED here and rides on-chain with the wallet's
 * first deploy: the SDK reads `GET /aa/guardians` and appends the
 * returned `initConfig` entry (a Kernel `installModule` self-call for
 * the GuardianRecoveryModule, including the `execute`-selector grant
 * non-root validators require) to the `initialize` calldata it sends
 * to `/aa/enroll-validator`. The exact wire shape is proven end-to-end
 * in citrate-chain `test/aa/GuardianRecoveryE2E.t.sol`.
 *
 * Citrate is NEVER a guardian (ADR-2026-06-05-ew-recovery) — this
 * module stores user-chosen addresses and refuses the authority's own
 * identity-signer address defensively.
 */

import { getAddress, isAddress } from 'viem';

export class GuardianNominationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'GuardianNominationError';
  }
}

export interface GuardianNomination {
  sub: string;
  /** 2–7 unique EOA addresses (lowercase). */
  guardians: string[];
  /** M-of-N threshold, 1 ≤ threshold ≤ guardians.length. */
  threshold: number;
  updatedAt: Date;
}

export interface GuardianStore {
  set(nomination: GuardianNomination): Promise<void>;
  get(sub: string): Promise<GuardianNomination | undefined>;
  clear(sub: string): Promise<void>;
}

export class InMemoryGuardianStore implements GuardianStore {
  private bySub = new Map<string, GuardianNomination>();

  async set(n: GuardianNomination): Promise<void> {
    this.bySub.set(n.sub, n);
  }

  async get(sub: string): Promise<GuardianNomination | undefined> {
    return this.bySub.get(sub);
  }

  async clear(sub: string): Promise<void> {
    this.bySub.delete(sub);
  }
}

let store: GuardianStore = new InMemoryGuardianStore();

export function getGuardianStore(): GuardianStore {
  return store;
}

export function setGuardianStore(s: GuardianStore): void {
  store = s;
}

/**
 * Validate + normalize a nomination request. Mirrors the
 * GuardianRecoveryModule's on-chain bounds so users get a clear error
 * at nomination time, not a revert at deploy time.
 */
export function normalizeNomination(args: {
  sub: string;
  guardians: unknown;
  threshold: unknown;
  /** Addresses the authority refuses as guardians (its own signer). */
  forbidden?: string[];
}): GuardianNomination {
  if (!Array.isArray(args.guardians)) {
    throw new GuardianNominationError('guardians must be an array of addresses');
  }
  const normalized: string[] = [];
  const seen = new Set<string>();
  for (const g of args.guardians) {
    if (typeof g !== 'string' || !isAddress(g)) {
      throw new GuardianNominationError(`not a valid address: ${String(g)}`);
    }
    const lower = g.toLowerCase();
    if (seen.has(lower)) {
      throw new GuardianNominationError(`duplicate guardian: ${getAddress(g)}`);
    }
    if ((args.forbidden ?? []).some((f) => f.toLowerCase() === lower)) {
      throw new GuardianNominationError(
        'the Citrate authority cannot be a guardian (ADR-2026-06-05-ew-recovery)',
      );
    }
    seen.add(lower);
    normalized.push(lower);
  }
  if (normalized.length < 2 || normalized.length > 7) {
    throw new GuardianNominationError(
      `guardian count must be in [2, 7] (got ${normalized.length})`,
    );
  }
  const threshold = Number(args.threshold);
  if (!Number.isInteger(threshold) || threshold < 1 || threshold > normalized.length) {
    throw new GuardianNominationError(
      `threshold must be an integer in [1, ${normalized.length}]`,
    );
  }
  return { sub: args.sub, guardians: normalized, threshold, updatedAt: new Date() };
}
