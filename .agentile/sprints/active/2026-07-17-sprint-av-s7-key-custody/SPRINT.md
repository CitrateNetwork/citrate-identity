---
created: 2026-07-17T02:00:00Z
branch: sprint/kyc-autoverify-av-s0-s1-2026-07-16
author: Larry Klosowski (@SaulBuilds) + Claude Opus 4.8
sprint: AV-S7
status: active
---

# Sprint AV-S7: Key custody seam (KMS/HSM) — HAR-244

## Sprint Metadata

| Field | Value |
|-------|-------|
| **Sprint ID** | `AV-S7` |
| **Sprint Name** | Provider-agnostic master-key custody seam + fail-closed prod gate |
| **Goal** | Make moving `KYC_MASTER_KEY` from a plaintext env var to KMS/HSM a wiring change, not a rewrite — with a fail-closed resolver and an opt-in prod gate — WITHOUT touching the live decrypt path. |
| **Branch** | `sprint/kyc-autoverify-av-s0-s1-2026-07-16` |
| **Start Date** | 2026-07-17 |
| **End Date (target)** | 2026-07-17 (seam + gate); real backend is WP-2 |
| **Status** | `IN PROGRESS` |
| **Planset** | `.agentile/planset/2026-07-16-kyc-autoverify.md` (AV-S7 row); ADR-AV-4; `HAR-244` |
| **Predecessors** | AV-S0 (ADR-AV-4) |

## Why this sprint

The KYC master key is a plaintext env var (`masterKeyFromEnv`, `kyc-crypto.ts:57`); the
server unwraps DEKs in the clear (`inhouse.ts:242-254`). ADR-AV-4 moves it to KMS/HSM.
Decision this session (owner): **seam only, provider chosen later; config gate + tests;
no change to the live decrypt path.** So this WP builds the abstraction + fail-closed
resolver + an opt-in prod gate, all defaulting to today's behavior.

## Deliverables

- `src/kyc-key-source.ts` — `MasterKeySource` + `EnvMasterKeySource` + `KmsMasterKeySource`
  + `KmsKeyUnwrapper` seam + fail-closed `resolveMasterKeySource`.
- `src/config.ts` — opt-in prod gate: `KYC_REQUIRE_KMS=true` refuses the env key in prod
  unless `KYC_MASTER_KEY_SOURCE=kms` (default off → unchanged).
- `test/kyc-key-source.test.ts` (5) + `test/config-prod.test.ts` (3 new).
- `.env.production.example` — documents `KYC_MASTER_KEY_SOURCE` / `KYC_REQUIRE_KMS`.

## Test Baseline

| Metric | Count | Captured | Command |
|--------|-------|----------|---------|
| **Tests** | 457 (post AV-S6) → **465** | 2026-07-17 | `npm test` |

## Method

Red → green + a mutation check (greenfield module, so the fail-closed lines were
verified to bite by mutating them and watching the guard tests fail, then reverting).

## Work Packages

### WP-1: Custody seam + fail-closed resolver + opt-in prod gate

| Field | Value |
|-------|-------|
| **Status** | `[x] COMPLETE` |
| **Order step** | code → verify (mutation-checked) |
| **Estimated effort** | M |
| **Commit(s)** | — (this branch) |

**Scope:** The abstraction + gate only. Does NOT wire the seam into the live
`inhouse.ts` boot/decrypt path (that is WP-2, gated on a real backend + staging), and
ships NO concrete KMS backend — selecting `kms` without one fails closed.

**Acceptance Criteria** *(Rule 11 — data source named)*
- [x] Default (no `KYC_MASTER_KEY_SOURCE`) → `EnvMasterKeySource`, 32-byte env key —
      `kyc-key-source.test.ts` "defaults to the env source".
- [x] `kms` without a backend → throws, no env fallback — "FAILS CLOSED" (mutation-verified).
- [x] `kms` with an injected `KmsKeyUnwrapper` → `KmsMasterKeySource`, key from it —
      "drives a wired KMS backend through the seam".
- [x] KMS key length validated (non-32-byte → throws) — "validates key length".
- [x] Prod + `KYC_REQUIRE_KMS=true` + env source → `assertProductionConfig` throws —
      `config-prod.test.ts` "REFUSES the plaintext env key in prod" (mutation-verified).
- [x] Default `KYC_REQUIRE_KMS` unset → no custody problem (live path unchanged) —
      "default … the live env-key path is unchanged".
- [x] No regression; 457 → 465; typecheck clean.

**Tests added:** 5 in `kyc-key-source.test.ts`; 3 in `config-prod.test.ts` (describe
"KYC key custody gate").

**Live-path note:** the seam is NOT yet called by prod boot — `inhouse.ts` still uses
`masterKeyFromEnv` directly, unchanged, per the session decision. Wiring it in is WP-2.

**Daily update:** 2026-07-17 — WP-1 green + mutation-checked. Env-key path untouched;
KMS seam fail-closed; opt-in gate off by default. 457→465.

### WP-2: Concrete KMS backend + wire into boot

> ⏸ **DEFERRED (owner, 2026-07-17) — deferral D-2 in `../../../planset/DEFERRALS.md`.**
> The owner deferred the **KMS provider choice** (AWS vs GCP vs HSM) until the **week of
> 2026-07-21**. Until then this WP cannot start. The seam (WP-1) is done and fail-closed,
> so the swap is a wiring job — but it is NOT done, and "server-blind" stays only
> partially true until it is.

| Field | Value |
|-------|-------|
| **Status** | `[!] BLOCKED / ⏸ DEFERRED` (KMS provider choice deferred to week of 2026-07-21) |
| **Order step** | code → live-path verification |
| **Estimated effort** | L |

**Scope:** Implement `KmsKeyUnwrapper` for the chosen provider (AWS/GCP KMS), wire
`resolveMasterKeySource` into `inhouse.ts` boot, verify decrypt on staging, then flip
`KYC_MASTER_KEY_SOURCE=kms` + `KYC_REQUIRE_KMS=true` in prod. Higher model (client-
generated DEKs under an asymmetric KMS pubkey, `inhouse.ts:242-254`) is the end-state.

## Notes

The env-key path staying live is deliberate: the running authority must keep decrypting.
This WP de-risks the swap (the seam + fail-closed resolver + gate) so WP-2 is a wiring +
verification job, not a redesign. Until WP-2, "server-blind" remains partially true
(planset §6) and copy must stay honest.
