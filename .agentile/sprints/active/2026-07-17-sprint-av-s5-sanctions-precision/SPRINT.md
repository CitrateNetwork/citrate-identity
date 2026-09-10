---
created: 2026-07-17T01:00:00Z
branch: sprint/kyc-autoverify-av-s0-s1-2026-07-16
author: Larry Klosowski (@SaulBuilds) + Claude Opus 4.8
sprint: AV-S5
status: active
---

# Sprint AV-S5: Sanctions/PEP precision (secondary-identifier disambiguation)

## Sprint Metadata

| Field | Value |
|-------|-------|
| **Sprint ID** | `AV-S5` |
| **Sprint Name** | Stop a name-only match from being treated as a real hit |
| **Goal** | Add DOB secondary-identifier disambiguation to `kyc-screening.ts` so a strong name match with a conflicting DOB is suppressed to review (fewer false-hits), and expose corroboration status so AV-S6 can gate auto-reject on a *corroborated* hit only. |
| **Branch** | `sprint/kyc-autoverify-av-s0-s1-2026-07-16` |
| **Start Date** | 2026-07-17 |
| **End Date (target)** | 2026-07-17 |
| **Status** | `IN PROGRESS` |
| **Planset** | `.agentile/planset/2026-07-16-kyc-autoverify.md` (AV-S5 row) |
| **Predecessors** | AV-S0 (ADR-AV-2 defines corroboration requirement) |

## Why this sprint

Screening is name-only today: `screen()` accepts `dob` but never uses it
(`kyc-screening.ts:102`). A common name (e.g. a frequent Slavic or Arabic name) matching
an SDN entry becomes a `hit` even when it is plainly a different person. ADR-AV-2 makes
a *corroborated* sanctions hit the only sanctions path to tier-3 auto-reject — so the
screener must (a) suppress a strong name match whose DOB conflicts, and (b) tell the
engine whether a hit is DOB-corroborated or name-only. This is fully autonomous (the
matcher is offline-testable; no datasets needed).

## Deliverables

- `src/kyc-screening.ts` — DOB on `SanctionsEntry`; `corroboration` on `ScreeningResult`;
  DOB compare + suppress/corroborate logic in `screen()`.
- `test/kyc-screening.test.ts` — new disambiguation tests (red-first).

## Test Baseline (start of sprint)

| Metric | Count | Captured | Canonical command |
|--------|-------|----------|-------------------|
| **Tests** | 447 | 2026-07-17 (post AV-S1) | `npm test` |

## Method

Red → green on `kyc-screening.ts`. Write the disambiguation tests first, watch them
fail against the name-only matcher, then implement the smallest DOB logic to green.
Existing screening invariants must not regress (Rule 2).

## Work Packages

### WP-1: DOB secondary-identifier disambiguation

| Field | Value |
|-------|-------|
| **Status** | `[x] COMPLETE` |
| **Order step** | red test → code |
| **Estimated effort** | M |
| **Commit(s)** | — (this branch) |

**Scope:** Use DOB to (a) suppress a strong name match with a conflicting DOB to
`review`, and (b) label the top hit `dob-match` / `dob-conflict` / `name-only`. Does NOT
touch the engine (`decide`) — that is AV-S6. Does NOT add a PEP list (separate WP,
needs a PEP data feed).

**Acceptance Criteria** *(Rule 11 — data source named)*
- [x] A strong name match with a conflicting DOB → `result: 'review'`,
      `corroboration: 'dob-conflict'`, reviewReason names the DOB conflict — verified by
      `test/kyc-screening.test.ts` "DOB conflict suppresses a false hit".
- [x] A strong name match with a matching DOB → `result: 'hit'`,
      `corroboration: 'dob-match'` — verified by "DOB match corroborates a hit".
- [x] A strong name match with no comparable DOB → `result: 'hit'`,
      `corroboration: 'name-only'` (NOT auto-rejectable) — verified by "name-only hit".
- [x] Existing screening tests still pass (no regression) — `npm test` 447 → 451.

**Tests added** (`test/kyc-screening.test.ts`, describe "secondary-identifier disambiguation (AV-S5)"):
- "DOB conflict suppresses a false hit: same name, different DOB → REVIEW, not HIT"
- "DOB match corroborates a hit: same name AND same DOB → HIT, dob-match"
- "name-only hit (no comparable DOB supplied) stays HIT but is marked name-only"
- "DOB does not affect a clean identity"

**Daily update:** 2026-07-17 — WP-1 green. `dobCompare` + `corroboration` on
`ScreeningResult`; conflict suppresses false hit to review, match corroborates. 447→451,
typecheck clean. Feeds AV-S6 tier-3 (corroborated-hit auto-reject).

### WP-2: Dedicated PEP list

| Field | Value |
|-------|-------|
| **Status** | `[!] BLOCKED` (needs a PEP data feed) |
| **Order step** | data-source tracing |
| **Estimated effort** | M |

**Scope:** A dedicated politically-exposed-persons list separate from OFAC SDN. Blocked
on choosing/ingesting a PEP feed (provenance + licensing, like `calibration/DATASETS.md`).

## Notes

Embargo-list counsel confirmation (O4) remains an AV-S0/WP-5 external item. This sprint
is the matcher precision only.
