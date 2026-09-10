---
created: 2026-07-17T00:00:00Z
branch: sprint/kyc-autoverify-av-s0-s1-2026-07-16
author: Larry Klosowski (@SaulBuilds) + Claude Opus 4.8
status: owner-approved — pending counsel co-sign
adr: AV-2
planset: 2026-07-16-kyc-autoverify (VERI-AV)
co-sign-required: outside counsel, a compliance lead (compliance)
---

# ADR-AV-2 — Three-tier decision matrix (advisor → approver)

> Implements planset §3 ADR-AV-2. Turns the current binary outcome into a measured
> three-tier policy. Red-tests-first in AV-S6 (`src/kyc-engine.ts`).

## Context

Today `decide` (`src/kyc-engine.ts:163-184`) returns one of `'verified' |
'needs-review'` in practice; the `EngineDecision` type already admits `'rejected'` but
**no code path emits it** — the engine is deliberately lenient and never auto-rejects.
Every non-ideal signal (missing evidence, dead backend, failed PAD, inauthentic doc,
any sanctions result other than `clear`) routes to `needs-review` (lines 176-180), and
only a full confident pass reaches `verified` (line 183).

To make the machine the approver we need (a) a *stricter* auto-verify that applies the
ADR-AV-1 calibrated thresholds, and (b) a bounded, high-confidence **auto-reject** for
cases where human review adds nothing but latency — while keeping fail-closed as the
default for anything unmeasured.

## Decision (proposed 2026-07-17)

`decide` returns one of three tiers. Fail-closed is the default: **anything not
provably in tier 1 or tier 3 falls to tier 2.**

### Tier 1 — `auto-verify`
All of the following hold:
- `hasFace && hasDoc` (evidence present) — unchanged gate (`kyc-engine.ts:176`).
- `liveness` and `document` results exist (live model backend) — unchanged (`:177`).
- `liveness.pass === true` **and** `liveness` scores clear the ADR-AV-1 auto-verify
  thresholds (match FMR ≤ 1e-4 threshold **and** enforced PAD ≥ APCER-calibrated
  threshold — PAD enforcement per ADR-AV-3).
- `document.authentic === true` **and** tamper score below the AV-S4 auto-verify bar.
- `screening.result === 'clear'` (`:180`).

This is **strictly narrower** than today's `verified`: today's `verified` becomes
tier-1 only when the *calibrated* score thresholds are also met; borderline-but-passing
scores now fall to tier 2.

### Tier 2 — `review-band` (the fail-closed default)
Any uncertainty. Includes everything the engine sends to `needs-review` today, plus:
- Missing evidence, absent/failed model backend (fail-closed — planset §1, `HAR-048`).
- Match or PAD score in the **review band** (between the auto-reject and auto-verify
  thresholds calibrated in AV-S2/S3).
- `document.authentic === false` **without** high-confidence tamper (weak/ambiguous).
- `screening.result === 'review'` (weak sanctions match or embargoed nationality per
  `src/kyc-screening.ts`).
- **Any path not explicitly measured.** Unmeasured ≠ safe.

### Tier 3 — `auto-reject` (bounded, high-confidence only)
Reserved for clear, corroborated failures where review adds only latency. Auto-reject
fires **only** on:
- **Confirmed sanctions hit:** `screening.result === 'hit'` (name score ≥ 0.87)
  **corroborated** by a matching secondary identifier (DOB or nationality) per AV-S5.
  A name-only hit **without** corroboration stays tier 2 (a common name is not a
  criminal).
- **Enforced-PAD presentation attack:** PAD enforcement on (ADR-AV-3) **and** the PAD
  model reports a spoof above a **high-confidence attack threshold** (distinct from,
  and stricter than, the tier-1 liveness threshold) **and** a face is present (i.e., a
  deliberate spoof, not a no-face capture error).

Everything else that "fails" → **tier 2, not tier 3.** Auto-reject is the highest-stakes
change in the program: a wrong reject harms a real member (planset §6). It is gated
behind shadow mode (AV-S8) and ships *after* auto-verify has proven itself, not with it.

## Consequences

- The type already supports three tiers; this is a *policy* + threshold change plus new
  red tests (AV-S6), not a signature change. Mutation-tested (planset §5.5).
- Auto-reject's corroboration requirement deliberately trades a higher manual-queue
  rate for near-zero wrongful auto-rejects — the asymmetric-harm choice.
- The projected auto-verify / review / auto-reject split is reported from a replay over
  the AV-S2 holdout before the tiers are trusted (planset AV-S6 acceptance).
- Fail-closed-on-unmeasured means new document types, new locales, or a model swap land
  in tier 2 until they earn their own evidence — no silent scope creep into auto-verify.

## Related

- ADR-AV-1 (the thresholds this matrix applies), ADR-AV-3 (PAD enforcement gates tier 1
  and tier 3), AV-S5 (sanctions corroboration for tier 3), AV-S6 (implementation),
  AV-S8 (shadow → canary before auto-reject trusts itself).
- Code: `src/kyc-engine.ts:163-184`, `src/kyc-screening.ts`.
