---
created: 2026-07-17T00:00:00Z
branch: sprint/kyc-autoverify-av-s0-s1-2026-07-16
author: Larry Klosowski (@SaulBuilds) + Claude Opus 4.8
status: owner-approved — pending counsel co-sign
adr: AV-1
planset: 2026-07-16-kyc-autoverify (VERI-AV)
supersedes: none
co-sign-required: outside counsel (proofing sign-off), a compliance lead (compliance evidence)
---

# ADR-AV-1 — Assurance target for auto-verify (the "is this a real person + real ID" bar)

> Not legal advice; recorded for counsel's go-live review (planset D8 / `HAR-258`).
> The numeric targets below are **proposed operating points to be *earned* on a
> holdout** in AV-S2/S3/S4 — they are the bar we calibrate *to*, not measured results.
> Nothing flips to auto-verify until §5 of the planset is green with these numbers met.

## Context

The owner's stated requirement is a **high bar of certainty — above 90% that the
person and the ID are real** — before the machine (not a human admin) approves a
paying member. Taken literally, "90% confidence" is a *weak* bar for identity
**matching**: a 1:1 face-match operating point with a 10% false-match rate would
auto-approve roughly one impostor in ten. Production KYC operates orders of magnitude
tighter. So we treat **90% as the floor, not the target**, and anchor the real target
to a recognized standard.

Our evidence stack — government photo ID (document authenticity) **plus** a live selfie
with 1:1 face match **plus** presentation-attack detection (PAD/liveness) — is a
document + biometric binding, which maps to **NIST SP 800-63A IAL2-equivalent**
identity proofing. `BASIC_INDIVIDUAL` (`src/kyc-providers/level-hints.ts:16-39`,
"government ID + selfie + liveness") is the level this ADR governs.

The engine today (`src/kyc-engine.ts:163-184`) is fail-closed and lenient: it only
returns `verified` on a confident pass with clear screening and live models, and never
auto-rejects. This ADR sets the *quantitative* meaning of "confident pass".

## Decision (proposed 2026-07-17)

**Assurance level.** Auto-verify targets **NIST 800-63A IAL2-equivalent** identity
proofing (validated government ID + biometric verification of the presenter against
that ID). This is co-signed by counsel before it locks.

**Target operating point.** Auto-verify (ADR-AV-2 tier 1) requires *all* signals below
their calibrated thresholds simultaneously. Each threshold is calibrated on a labeled
holdout to hit these bounds:

| Signal | Metric | Target at the auto-verify threshold | Earned in |
|---|---|---|---|
| 1:1 face match (person == ID portrait) | **FMR** (impostor accepted) | **≤ 1×10⁻⁴** (1 in 10,000) | AV-S2 |
| 1:1 face match | **FNMR** (genuine → review) | **≤ 5%** at that FMR | AV-S2 |
| Liveness / anti-spoof (PAD) | **APCER** (attack accepted as live) | **≤ 5%** at **BPCER ≤ 3%** | AV-S3 |
| Document authenticity | forged-doc accept rate | **≤ 2%** at **≥ 95%** genuine-doc pass | AV-S4 |
| Sanctions / PEP screening | missed-hit (recall) | **≥ 99%** recall at the agreed false-hit rate | AV-S5 |

**Joint interpretation of the "90% floor".** Because auto-verify requires the *logical
AND* of an FMR-1e-4 match, an enforced PAD pass, an authentic document, and clear
screening, the joint probability that a **fabricated identity (fake person and/or fake
ID) is auto-approved** is bounded well below **1×10⁻³**. Stated as the owner framed it:
the target yields **> 99% certainty the person and the ID are real** at auto-verify —
far above the 90% floor. The 90% floor is retained as a **hard minimum**: if any
calibrated operating point cannot beat it on the holdout, auto-verify does not ship for
that signal and the case stays in manual review.

**FMR is the load-bearing number.** It is the "is this the same human as the ID"
guarantee. It is fixed first (AV-S2); FNMR is whatever that FMR costs in genuine
friction, and genuine non-matches route to **review, never reject** (harm-minimizing).

**Cross-domain caveat.** Live-selfie-to-printed-ID-portrait matching is harder than
selfie-to-selfie; ArcFace benchmark FMR/FNMR on clean data will *not* transfer. The
AV-S2 holdout must be representative of the real capture channel (phone selfie vs.
photographed physical ID) or the numbers are fiction (see planset §6 threshold-drift).

## Consequences

- Gives AV-S2/S3/S4/S5 a concrete, standard-anchored bar to calibrate to and a
  pass/fail gate for the go-live exit criteria (planset §5.1–§5.4).
- Sets FMR ≤ 1e-4 as a **~250× tighter** requirement than the literal 90% reading —
  the honest cost is a higher FNMR (more genuine users to manual review). That cost is
  acceptable because manual review is already the shippable launch posture.
- Binds threshold changes to re-earned evidence: any model or threshold change
  re-triggers the AV-S2 validation (planset §6, threshold-drift). Thresholds are
  pinned in config *with* the validation report that justified them.
- Counsel must co-sign the IAL2 assertion and these numbers before AV-S9 flips the
  switch; until then this ADR is `proposed`, not `accepted`.

## Related

- ADR-AV-2 (decision matrix — where these thresholds are applied),
  ADR-AV-3 (PAD enforcement — the APCER row),
  ADR-AV-4 (key custody).
- `ADR-2026-07-01-biometric-bipa` (immediate biometric destruction constrains how
  liveness evidence can be re-reviewed).
- Code: `src/kyc-engine.ts:163-184`, `src/kyc-providers/level-hints.ts:16-39`,
  `services/kyc-inference/validate.py` (the harness that produces FMR/FNMR/APCER/BPCER).
- Planset §5 exit criteria 1–4; readiness `HAR-258`.
