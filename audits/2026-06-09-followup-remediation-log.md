---
created: 2026-06-10
author: Fable 5 (Claude Code)
status: active
sprint: SECREM-02-followup-remediation
repo: citrate-identity
baseline_test_count: 100
---

# citrate-identity — SECREM-02 Remediation Log

> Evidence chain for findings assigned to this repo (coverage matrix in
> `citrate-security/planset/2026-06-10-followup-remediation.md`). Protocol per
> finding: re-verify → red test → fail-closed fix → suite green (count ≥ baseline)
> → mutation pass → row complete.

## Phase 1 — Identity & auth foundation (issuer side)

| Finding | Sev | WP | Red test(s) | Fix (file:line) | Suite (≥100?) | Mutation | Disposition |
|---|---|---|---|---|---|---|---|
| FUA-IDENTITY-01 | Med | 1.1 | `siwe-issuer-hardening.test.ts` → "direct token … refused" | Path B gated behind `allowDirectTokenGrant` (default off) + audience bound to a registered first-party client, validated at mount — `siwe-routes.ts` (mount guard + Path-B `if (!allowDirectTokenGrant)`); `server.ts` threads the flag | 109 ✓ | M3 killed (neuter gate → test FAIL) | **FIXED** |
| FUA-IDENTITY-04 | Med | 1.2 | hardening test → cross-site `/consent/approve` via Origin + Sec-Fetch-Site → 403; same-origin → 400 | `isSameOriginRequest()` guard on Path-A `interactionResult` and `/consent/approve` — `siwe-routes.ts` | 109 ✓ | M2 killed (force guard true → test FAIL) | **FIXED** |
| FUA-IDENTITY-07 | Low | 1.3 | hardening test → `jsonForScript('</script>…')` has no `<`/`>`/`</script>` | `jsonForScript()` escapes `<>&  `; used for the interaction page's inline `CFG` — `siwe-routes.ts` | 109 ✓ | covered by unit assertion | **FIXED** |
| FUA-IDENTITY-08 | Low | 1.3 | existing `logout.test.ts` cascade still green (regression guard) | introspection `allowedPolicy`: a client may introspect only tokens issued to itself — `config.ts` | 109 ✓ | logout cascade green post-change | **FIXED** (dedicated cross-client probe test = follow-up) |
| FUA-IDENTITY-09 | Low | 1.3 | hardening test → missing `expirationTime` / too-far / uri-host mismatch all rejected | require `expirationTime` (+ NaN guard), cap lifetime at `MAX_SIWE_EXPIRATION_MS` (24h), bind `uri` host to authority — `siwe.ts` | 109 ✓ | M1 equivalent (redundant NaN guard); both-guards-removed → test FAIL (killed); M4 (uri) killed | **FIXED** |

## Phase 2 — control-surface (WP 2.2)

| Finding | Sev | Red test(s) | Fix (file) | Suite (≥109?) | Mutation | Disposition |
|---|---|---|---|---|---|---|
| FUA-IDENTITY-02 | Med | `logout.test.ts` → SSE no-token/garbage-token → 401; "delivers ONLY the subscriber's own sub" | `/sessions/events` requires a valid access token (resolve via `provider.AccessToken.find`); `onEvent` delivers only `event.sub === subscriberSub` — `src/logout-routes.ts` | 112 ✓ | killed: bypass auth → 2 tests FAIL; bypass scope filter → scoping test FAIL | **FIXED** |
| FUA-IDENTITY-05 | Med | (cap is code-guarded; per-IP throttle = follow-up) | `maxSseConnections` cap (default 1000) → 503 over cap on `/sessions/events`; auth requirement (above) already bounds the firehose — `src/logout-routes.ts` | 112 ✓ | — | **PARTIAL** — SSE cap + auth done; per-IP nonce/verify throttle deferred (best at Caddy, per audit) |
| FUA-IDENTITY-03 | Med | — | — | — | — | **OPEN** — strict CSP + self-host the WalletConnect bundle (drop the esm.sh runtime import). Larger change; the Phase-1 `jsonForScript` escaping already cut the inline-XSS surface. Follow-up. |

### Still deferred to later phases (tracked, not done here)
- FUA-IDENTITY-03 (CDN import / CSP) — above; FUA-IDENTITY-06 (signing-key rotation) → KEYSAFE-K2.

### (Original Phase-1 note)
- FUA-IDENTITY-02 (unauth `/sessions/events` leak — **now FIXED above**), -03 (CDN import / CSP),
  -05 (rate limiting) → **Phase 2.2** (control-surface seam). -06 (key rotation)
  → **KEYSAFE-K2**.

## Notes
- Baseline test count (Phase 0): **100** (`vitest run`, 13 files). Post-fix: **109**
  (14 files; +9 net — Rule 2 satisfied, no test removed).
- Mutation harness: Stryker not yet configured for this repo (Phase 0.3). Used
  targeted manual mutants (neuter each guard → confirm a test fails) as the
  interim kill-proof; M2/M3/M4 killed outright, M1 is an equivalent mutant
  (redundant guard) and the property is killed when both guards are removed.
  **Follow-up:** wire Stryker (`@stryker-mutator/vitest-runner`) for an automated
  campaign.
- Semgrep tripwire(s): **TODO Phase 8** — encode "fail-open OIDC token validation"
  + "out-of-band token mint" patterns.
- Branch: `audit/secrem02-identity-issuer-hardening`.

## KEYSAFE K2 — FUA-IDENTITY-06 (signing-key lifecycle)

| Finding | Sev | Red test(s) | Fix (file) | Suite (≥200?) | Mutation | Disposition |
|---|---|---|---|---|---|---|
| FUA-IDENTITY-06 | Low | `test/jwks-keysafe.test.ts` (6 tests) — JWKS created 0600; loose mode repaired on load; 0600 survives rotation rewrite; rotation overlap (retiring-key token still verifies, new tokens carry new kid); two-deep publish window; live `/jwks` serves both kids and no private members. All 5 runnable tests FAILED pre-fix (rotateJwks absent; file written default 0644) | `src/config.ts`: `assertJwksFileMode()` (assert/repair 0600 on every load, **fail closed** — throws if the mode can't be restricted), `persistJwks()` (write `mode: 0o600` + assert), `generateSigningJwk()` (collision-proof kid), `rotateJwks()` (new key signs at `keys[0]`, previous signer retained as published-but-retiring verify-only key, window depth 2), `JWKS_PATH` env override; `src/server.ts` comment pins the keys[0]-signs invariant (direct-path `mintIdToken` already uses `keys[0]`); panva serves the whole `jwks` → both kids published; ops: `npm run rotate-key` (`scripts/rotate-jwks.ts`, prints kids only); KMS/HSM upgrade path documented in `docs/KEY_MANAGEMENT.md`; live `.keys/jwks.json` chmod'd 600 in place | 206 ✓ (baseline this session 200, 22 files; +6) | M1 (file mode reverted to 0644): 3 tests FAIL — killed. M2 (retiring-key retention dropped from `rotateJwks`): 2 tests FAIL — killed. Restored, suite re-green 206 | **FIXED** (KMS/HSM move = documented follow-up, not in K2 scope) |

### Notes
- The persisted JWKS path is now overridable (`JWKS_PATH` env or explicit arg) so
  tests use ephemeral keys instead of the repo-local `.keys/` file.
- Fail-closed posture: boot aborts if the key file cannot be restricted to 0600
  (POSIX; Windows ACL caveat noted in code).
- No key material was read, copied, or logged during this WP; `rotate-jwks.ts`
  prints kids only.
- Branch: `audit/secrem02-keysafe-k2`.
