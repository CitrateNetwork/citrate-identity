/**
 * How long a browser stays signed in to auth.citrate.ai.
 *
 * panva saves the session on every sign-in request with this TTL, and derives
 * the session cookie's expiry from it, so the TTL is a sliding idle window.
 * Until 2026-11-12 it was a flat 14 days, which kept a browser that signed in
 * once completing every later sign-in silently as that account.
 *
 * Two limits, both configurable:
 *   - SESSION_IDLE_TTL_SECONDS: the session ends after this long without a
 *     sign-in request. Default 1209600 (14 days, the previous behaviour).
 *   - SESSION_ABSOLUTE_TTL_SECONDS: the session ends this long after the
 *     member last authenticated (`loginTs`), however active it is. Default
 *     unset: no absolute limit (the previous behaviour).
 * Proposed production values: 43200 (12h) idle, 604800 (7d) absolute.
 *
 * Error messages name the variable and the expected format, never the value
 * (it reaches the boot log; CodeQL js/clear-text-logging).
 * A value that is not a positive whole number of seconds, or an idle limit
 * above the absolute one, refuses to boot rather than running with a
 * lifetime nobody chose.
 */

/** The previous flat session TTL (PBA-L3a-013), kept as the default. */
export const DEFAULT_SESSION_IDLE_TTL_SEC = 14 * 24 * 60 * 60;

export interface SessionLifetime {
  idleSec: number;
  /** Undefined: no absolute limit. */
  absoluteSec?: number;
}

/**
 * Upper bound for both limits: 30 days, the account-epoch lifetime
 * (account-epoch.ts EPOCH_TTL_SEC). A session living longer could outlive a
 * "log out everywhere" or password-reset stamp on its account.
 */
export const MAX_SESSION_TTL_SEC = 30 * 24 * 60 * 60;

function seconds(name: string, raw: string | undefined): number | undefined {
  if (raw === undefined || raw.trim() === '') return undefined;
  const v = raw.trim();
  if (!/^\d+$/.test(v) || Number(v) <= 0 || !Number.isSafeInteger(Number(v))) {
    throw new Error(`${name} must be a positive whole number of seconds`);
  }
  if (Number(v) > MAX_SESSION_TTL_SEC) {
    throw new Error(`${name} must be at most ${MAX_SESSION_TTL_SEC} seconds (30 days)`);
  }
  return Number(v);
}

export function sessionLifetimeFromEnv(
  env: { SESSION_IDLE_TTL_SECONDS?: string; SESSION_ABSOLUTE_TTL_SECONDS?: string } = process.env,
): SessionLifetime {
  const idleSec = seconds('SESSION_IDLE_TTL_SECONDS', env.SESSION_IDLE_TTL_SECONDS) ?? DEFAULT_SESSION_IDLE_TTL_SEC;
  const absoluteSec = seconds('SESSION_ABSOLUTE_TTL_SECONDS', env.SESSION_ABSOLUTE_TTL_SECONDS);
  if (absoluteSec !== undefined && idleSec > absoluteSec) {
    throw new Error(
      `SESSION_IDLE_TTL_SECONDS (${idleSec}) must not exceed SESSION_ABSOLUTE_TTL_SECONDS (${absoluteSec})`,
    );
  }
  return absoluteSec === undefined ? { idleSec } : { idleSec, absoluteSec };
}

/**
 * Seconds the session record (and cookie) should live from `nowSec`: the idle
 * window, cut short by the absolute deadline counted from the last sign-in
 * when one is set. Never below one second (panva requires a positive TTL), so
 * a session past its absolute deadline expires immediately.
 */
export function sessionTtlSeconds(
  lifetime: SessionLifetime,
  session: { loginTs?: number } | undefined,
  nowSec: number = Math.floor(Date.now() / 1000),
): number {
  const loginTs = session?.loginTs;
  if (lifetime.absoluteSec === undefined || typeof loginTs !== 'number' || !Number.isFinite(loginTs)) {
    return lifetime.idleSec;
  }
  const remaining = loginTs + lifetime.absoluteSec - nowSec;
  return Math.max(1, Math.min(lifetime.idleSec, remaining));
}
