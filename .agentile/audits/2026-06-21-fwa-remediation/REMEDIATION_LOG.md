---
created: 2026-06-21T00:00:00Z
author: Claude Opus 4.8 (1M context) — RM-IDENT remediation agent
status: complete
standard: Agentile-Audit v0.2
audit_id: 2026-06-20-federation-wide-audit
chunk: FWA-C6
repo: citrate-identity
branch: remediation/fwa-2026-06
base_sha: 26c4c090988db2aff046a9caacf9d034de78b742
---

# FWA-C6 Remediation Log — citrate-identity

Source audit: `citrate-security/audits/2026-06-20-federation-wide-audit/per-chunk/FWA-C6/`
(REPORT.md + findings.json + evidence/FWA-C6-01-google-unverified-email-link.md).

Protocol: RED → FIX → SWEEP → TRIPWIRE → MUTATION → RECORD. Red-test-first;
test count monotone non-decreasing (317 → 341, +24). Full suite green at every
checkpoint. READ-ONLY constraint of the original audit lifted for remediation.

---

## FWA-C6-01 (HIGH) — Google federation links/creates on an UNVERIFIED email

**Status: FIXED (close-gate discharged).**

### Root cause
`google-routes.ts` read `email` from the verified Google id_token but never
`email_verified`, then linked the Google `sub` onto an email-matched account /
created an `emailVerified:true` account. A signed id_token proves Google ISSUED
it, not that the subject owns the email — Google emits `email_verified:false`
for domain-unverified Workspace/Cloud-Identity tenants an attacker provisions.

### Fix (smallest change)
Extracted the link/create decision (the locus of the bug, previously inline and
un-unit-testable because the surrounding callback hits the live Google token
endpoint + remote JWKS) into two pure, exported functions:

- `trustedEmailFromIdToken(payload)` — `src/auth/google-routes.ts:59` — returns
  the email ONLY when `email_verified` is boolean `true` OR the legacy Google
  string `"true"`; everything else (false, `"false"`, missing, non-string,
  `1`, …) → `undefined` (email ignored entirely).
- `resolveGoogleUser(payload, store)` — `src/auth/google-routes.ts:82` —
  look-up order: by `google_sub` first (always trusted; stable IdP id), then
  `findByEmail`-link / `createWithGoogle(email)` ONLY for a trusted (verified)
  email, else create with NO email binding (matches the passkey path).

Callback rewired to call `resolveGoogleUser` (`google-routes.ts:450`),
replacing the inline buggy logic. Misleading comment at `stores.ts:128`
replaced with the corrected invariant (an email reaches `createWithGoogle` only
after the caller confirmed `email_verified===true`; presence of email == the
verified signal). The off-by-default mount gate (`server.ts:302`) is unchanged
and retained.

### RED → GREEN evidence
Test file: `test/auth/google-email-verified.test.ts` (15 cases).
- RED: with the verify gate replaced by `isVerified = true` (pre-fix
  "trust-any-email" behavior), **7/14 cases failed** — incl.
  `does NOT link the google_sub onto a victim account on email_verified:false`
  and `does NOT create an email-bound, emailVerified account on
  email_verified:false`. Failure proves the test catches the account-takeover.
- GREEN: with the `email_verified===true || ==="true"` gate restored, all pass.

Key cases: rejects `false` / `"false"` / missing / non-boolean; preserves the
verified happy path (link + create); returning-`google_sub` short-circuit; a
matched `google_sub` ignores a conflicting verified email (no relink onto a
different account); missing-sub → `undefined` (caller 401s).

### Files + LOC
- `src/auth/google-routes.ts` — +`trustedEmailFromIdToken` (59-65),
  +`resolveGoogleUser` (82-119), callback rewired (438-460).
- `src/auth/stores.ts` — comment/invariant corrected (128-133).
- `test/auth/google-email-verified.test.ts` — NEW (15 cases).

### Test-count delta: +15 (C6-01 cases).

### Mutation (manual sampling — see MUTATION block below): 5/5 killed on the
touched verify functions. Notably the "drop findByGoogleSub-first" mutant
initially SURVIVED and was killed by adding the no-relink test
(`a matched google_sub short-circuits BEFORE the email path`).

### Tripwire
- `test/auth/email-verified-tripwire.test.ts` — permanent, dependency-free,
  runs in `vitest run`: scans `src/`, FAILS if any `jwtVerify` consumer reads a
  `.email` claim without referencing `email_verified`. Proven: stripping
  `email_verified` from `google-routes.ts` flags it; restoring passes.
- `.semgrep/email-verified-trust.yml` — equivalent semgrep rule
  (`federated-email-without-email-verified`, ERROR) for CI where semgrep runs.

### Disposition: OPEN → REMEDIATED-PENDING-QUORUM.

---

## FWA-C6-02 (MED) — Process-local Google OAuth state store is not multi-instance

**Status: FIXED (close-gate discharged).**

### Root cause
The Google `state`/`nonce`/`code_verifier` triple lived in a per-process `Map`
(`StateStore`), unlike the SIWE nonce store + panva adapter which are Redis-
backed under `REDIS_URL`. Behind a multi-instance load balancer a callback
landing on a different instance than `/start` found no state (availability) and
single-use/replay protection held only per-process.

### Fix
Replaced the single `StateStore` class with a seam:
- `StateStore` interface (`google-routes.ts:150`).
- `InMemoryStateStore` (`:156`) — dev/test, delete-on-read single-use + TTL.
- `RedisStateStore` (`:184`) — keyed `google_state:<state>`; `put` = `SET … PX
  STATE_TTL_MS NX` (TTL in the same command, NX prevents silent overwrite);
  `take` = atomic single-command `GETDEL` (the delete enforces one-time use
  ACROSS instances — same discipline as `RedisNonceStore`); malformed JSON →
  treated as absent (fail-closed).

`mountGoogleRoutes` now selects `RedisStateStore` when a `RedisLike` is wired,
else `InMemoryStateStore`. `put`/`take` are awaited and **fail-closed**: if the
shared store is unreachable, `/start` and `/callback` return `503
temporarily_unavailable` rather than emit/accept a state that can't be
single-use-consumed cluster-wide. `server.ts:315` threads the existing shared
`options.redis` client into the mount (omitted in dev → in-memory).

### RED → GREEN evidence
Test file: `test/auth/google-state-store.test.ts` (8 cases). Two
`RedisStateStore`s over one shared `ioredis-mock` keyspace model two instances.
- RED (pre-fix): state in a per-mount `Map` → a key put by instance A is
  invisible to instance B; the cross-instance `take` test
  (`a state PUT on instance A is TAKEable on instance B`) could not pass and
  replay was only per-process.
- GREEN: cross-instance take works; `take` consumes exactly once (replay on
  either instance → `undefined`); NX prevents overwrite; unknown/expired →
  `undefined`; malformed JSON → `undefined`; keys namespaced under
  `google_state:`. `InMemoryStateStore` fallback: single-use + fail-closed.

### Files + LOC
- `src/auth/google-routes.ts` — StateStore seam (150-220), awaited+fail-closed
  call sites (`put` 300-318, `take` 358-373), redis option (134-145), mount
  selection (262-266).
- `src/server.ts` — redis threaded into `mountGoogleRoutes` (315).
- `test/auth/google-state-store.test.ts` — NEW (8 cases).

### Test-count delta: +8.

### Mutation (manual sampling): 4/4 killed on `RedisStateStore`
(drop-NX, get-not-getdel, null-not-undefined, drop-key-prefix) — after
exporting the classes so the class methods (not just the Redis primitives) are
exercised directly.

### Tripwire
Covered by the permanent cross-instance + single-use assertions in
`google-state-store.test.ts` (the `take consumes exactly once` and
`PUT on A … TAKEable on B` cases). A regression to a per-process map breaks
both.

### Disposition: OPEN → REMEDIATED-PENDING-QUORUM.

---

## MUTATION

Stryker is NOT configured in this repo and not installed
(`@stryker-mutator` absent; no `stryker.conf.*`). Per the honesty rule this is
recorded as a **BLOCK** for the automated `npx stryker run` step. Installing
Stryker is a multi-package network operation outside the remediation footprint.

**Compensating control — manual mutation sampling** on the touched functions
(`trustedEmailFromIdToken`, `resolveGoogleUser`, `RedisStateStore.{put,take}`):
**9 representative mutants injected, 9 killed (100%).**

| # | Mutant | Target | Result |
|---|---|---|---|
| 1 | drop boolean-`true` branch (only `"true"`) | trustedEmail | KILLED (3 fail) |
| 2 | `isVerified = true` (always trust) | trustedEmail | KILLED (7 fail) |
| 3 | invert return guard | trustedEmail | KILLED (11 fail) |
| 4 | drop `!user &&` (skip google_sub-first) | resolveGoogleUser | KILLED (after no-relink test added) |
| 5 | bind raw `payload.email` ignoring gate | resolveGoogleUser | KILLED (3 fail) |
| 6 | drop `NX` | RedisStateStore.put | KILLED |
| 7 | `getdel` → `get` (no delete) | RedisStateStore.take | KILLED |
| 8 | null → `{}` not undefined | RedisStateStore.take | KILLED |
| 9 | drop `google_state:` key prefix | RedisStateStore.put | KILLED |

Recommended follow-up: wire Stryker against
`src/auth/google-routes.ts` to confirm ≥90% automated kill across the full
mutant set (the manual sample targets the load-bearing operators only).

---

## SWEEP (variant analysis — all OAuth/OIDC federation routes)

Audited every `src/**/*.ts` that consumes an email/claim from a token:

- **Google** (`google-routes.ts`) — the ONLY route consuming a third-party
  id_token's `email`. FIXED.
- **password-routes.ts** — `findByEmail` keyed on the user-typed registration/
  login email, NOT a token claim; no cross-method linking
  (`password-routes.ts:148,189`). Clear.
- **siwe-routes.ts** — keys on the recovered wallet address and MINTS its own
  id_token (`:1158-1181`); never trusts a foreign token's email. Clear.
- **config.ts** (`:649,913`) — the authority EMITTING `email_verified` into ITS
  OWN id_token, sourced from the verified DB row `rec.emailVerified` (producer
  side, correct). Not a trust-the-foreign-token site.
- **users-pg.ts / stores.ts `linkGoogleSub`** — set `email_verified = true`;
  reached only via the now-gated `resolveGoogleUser`. Defense-in-depth note: the
  store-level set is safe because the caller is the gate. No standalone fix
  required.

**Coverage: Google was the sole instance of the unverified-claim-trust pattern.
No sibling federation route required a fix.**

---

## Verification summary

- `npm run typecheck` — clean.
- `npx vitest run` — **341 passed (39 files)**. Baseline 317 → 341 (+24:
  15 C6-01 + 8 C6-02 + 1 tripwire). Monotone non-decreasing; no existing test
  weakened or removed.
- All work on branch `remediation/fwa-2026-06`. Not pushed.
