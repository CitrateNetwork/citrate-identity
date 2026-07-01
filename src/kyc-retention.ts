/**
 * VERI retention + destruction sweep (VERI-S1-WP4).
 *
 * The scheduled job that enforces the three-tier retention model
 * (`ADR-2026-07-01-kyc-not-msb-retention-erasure`, `-biometric-bipa`):
 *   - Tier-2 biometrics: wipe ciphertext once `destroy_after` has passed
 *     (the belt-and-suspenders backstop; the adapter destroys after the match).
 *   - Tier-1 identity records: hard-delete once the policy retention window
 *     (`retention_until`) has passed and there is no legal hold.
 *
 * Pure over the store + a clock, so it is fully testable offline. The boot-time
 * scheduler that calls this on an interval is wired in `server.ts` (a one-liner
 * `setInterval`); this function is the unit that does the work.
 */

import type { KycCaseStore } from './kyc-cases-pg.js';

export interface RetentionSweepResult {
  biometricsDestroyed: number;
  casesPurged: number;
  ranAt: number;
}

/** Run one retention/destruction pass. Idempotent; safe to run on any interval. */
export async function runRetentionSweep(
  store: KycCaseStore,
  now: number = Date.now(),
): Promise<RetentionSweepResult> {
  const biometricsDestroyed = await store.destroyDueBiometrics(now);
  const casesPurged = await store.purgeExpiredCases(now);
  return { biometricsDestroyed, casesPurged, ranAt: now };
}

/**
 * Start a periodic retention sweep. Returns a stop handle. Errors in a sweep are
 * logged and swallowed so one bad pass never crashes the authority. Called once at
 * boot when `KYC_PROVIDER=inhouse`.
 */
export function startRetentionScheduler(
  store: KycCaseStore,
  intervalMs: number = 60 * 60 * 1000,
): { stop: () => void } {
  const timer = setInterval(() => {
    runRetentionSweep(store).catch((err: unknown) => {
      // eslint-disable-next-line no-console
      console.error('[citrate-identity] KYC retention sweep failed:', err);
    });
  }, intervalMs);
  // Don't keep the event loop alive for the timer alone.
  if (typeof timer.unref === 'function') timer.unref();
  return { stop: () => clearInterval(timer) };
}
