---
created: 2026-07-17T01:30:00Z
branch: sprint/kyc-autoverify-av-s0-s1-2026-07-16
author: Larry Klosowski (@SaulBuilds) + Claude Opus 4.8
sprint: AV-S6
status: active
---

# Sprint AV-S6: Tiered decisioning (turn the advisor into the approver)

## Sprint Metadata

| Field | Value |
|-------|-------|
| **Sprint ID** | `AV-S6` |
| **Sprint Name** | Implement the ADR-AV-2 three-tier matrix, red-tests-first |
| **Goal** | Extend `decide` to auto-verify / review-band / auto-reject, with auto-reject bounded to a DOB-corroborated sanctions hit and GATED OFF by default until AV-S8 shadow mode. |
| **Branch** | `sprint/kyc-autoverify-av-s0-s1-2026-07-16` |
| **Start Date** | 2026-07-17 |
| **End Date (target)** | 2026-07-17 (structure + gated auto-reject); tier-1 tightening waits on AV-S2/S3/S4 |
| **Status** | `IN PROGRESS` |
| **Planset** | `.agentile/planset/2026-07-16-kyc-autoverify.md` (AV-S6 row) |
| **Predecessors** | AV-S0 (ADR-AV-2), AV-S5 (corroboration signal) |

## Why this sprint

ADR-AV-2 replaces the binary outcome with three tiers. Auto-reject is the highest-stakes
change in the program (a wrong reject harms a real member — planset §6), so it must be
red-tested AND gated behind shadow mode. This sprint lands the matrix structure and the
one safe auto-reject path (a DOB-corroborated sanctions hit), defaulting OFF. Tier-1
auto-verify is NOT expanded here — that needs the calibrated thresholds from AV-S2/S3/S4
(still blocked on datasets), and fail-closed-on-unmeasured is the ADR-AV-2 default.

## Deliverables

- `src/kyc-engine.ts` — `decide` rewritten to the three-tier matrix; `autoRejectEnabled`
  gate on `VerificationEngineDeps` (default off → falls through to needs-review).
- `src/kyc-inference-client.ts` — `buildVerificationEngine` reads `KYC_AUTO_REJECT_ENABLE`.
- `test/kyc-engine.test.ts` — 5 tier-3 tests (red-first on the reject path).
- `test/kyc-inference-client.test.ts` — 1 E2E test the env flag wires through.
- `.env.production.example` — documents `KYC_AUTO_REJECT_ENABLE` (default off) + inference vars.

## Test Baseline

| Metric | Count | Captured | Command |
|--------|-------|----------|---------|
| **Tests** | 451 (post AV-S5) → **457** | 2026-07-17 | `npm test` |

## Method

Red → green on `decide`. The reject path was written as a failing test first
(`expected 'needs-review' to be 'rejected'`), then implemented as the smallest gated
change. Boundary tests (gate-off default, corroboration-required, conflict-suppressed,
clean-path-unaffected) pin the matrix edges. No test removed (Rule 2).

## Work Packages

### WP-1: Three-tier `decide` + gated auto-reject

| Field | Value |
|-------|-------|
| **Status** | `[x] COMPLETE` |
| **Order step** | red test → code → verify |
| **Estimated effort** | M |
| **Commit(s)** | — (this branch) |

**Scope:** Structure `decide` as ADR-AV-2 tiers; implement tier-3 auto-reject for a
DOB-corroborated sanctions hit only, gated by `autoRejectEnabled` (default off). Keep
fail-closed default for everything else. Does NOT expand tier-1 auto-verify (needs
AV-S2/S3/S4 thresholds). Does NOT add the enforced-PAD-spoof reject (needs AV-S3 signal).

**Acceptance Criteria** *(Rule 11 — data source named)*
- [x] Corroborated sanctions hit + flag ON → `rejected` — `kyc-engine.test.ts`
      "DOB-corroborated sanctions hit + auto-reject ENABLED → rejected".
- [x] Corroborated hit + flag OFF (default) → `needs-review` — "...DISABLED (default)".
- [x] Name-only hit + flag ON → `needs-review`, NOT rejected — "name-only ... NOT rejected".
- [x] DOB-conflicting match + flag ON → `needs-review` (AV-S5 suppression holds) — "DOB-conflicting...".
- [x] Clean path + flag ON → `verified` (auto-reject never touches a good case) — "...clean verified path".
- [x] Env flag wires end-to-end — `kyc-inference-client.test.ts` "KYC_AUTO_REJECT_ENABLE wires through".
- [x] No regression; 451 → 457; typecheck clean.

**Tests added:** 5 in `kyc-engine.test.ts` (describe "tier-3 auto-reject"), 1 in
`kyc-inference-client.test.ts`.

**Live-path note:** verified via the E2E wiring test (env → `buildVerificationEngine` →
engine → `rejected`). Not yet exercised against a deployed inference host (AV-S1 WP-3)
or real shadow traffic (AV-S8) — auto-reject stays OFF in prod until then.

**Daily update:** 2026-07-17 — WP-1 green. Three-tier `decide`; auto-reject gated off by
default; corroboration + conflict boundaries pinned. 451→457.

### WP-2: Tier-1 auto-verify tightening + projected queue-split replay

| Field | Value |
|-------|-------|
| **Status** | `[!] BLOCKED` (needs AV-S2/S3/S4 calibrated thresholds + a replay dataset) |
| **Order step** | code |
| **Estimated effort** | M |

**Scope:** Apply calibrated score thresholds to tier-1 (stricter than today's binary
pass) and report the projected auto-verify/review/reject split from a replay over the
AV-S2 holdout (planset AV-S6 acceptance). Blocked until AV-S2/S3/S4 land.

## Notes

Auto-reject shipping OFF by default is deliberate and matches the planset: it is
"introduced" (code + red tests) here but only "trusted" after AV-S8 shadow mode. The
flag (`KYC_AUTO_REJECT_ENABLE`) is the AV-S8 kill-switch's on-ramp.
