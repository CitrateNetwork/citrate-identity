---
created: 2026-07-17T00:00:00Z
branch: sprint/kyc-autoverify-av-s0-s1-2026-07-16
author: Larry Klosowski (@SaulBuilds) + Claude Opus 4.8
sprint: AV-S2
status: scaffolded (blocked on datasets)
---

# Sprint AV-S2: Accuracy validation (the S6 gate)

## Sprint Metadata

| Field | Value |
|-------|-------|
| **Sprint ID** | `AV-S2` |
| **Sprint Name** | Prove accuracy on a holdout before trusting the machine |
| **Goal** | Measure FMR/FNMR + APCER/BPCER on a labeled holdout and calibrate thresholds to the ADR-AV-1 bar, with the report on file. |
| **Branch** | `sprint/kyc-autoverify-av-s0-s1-2026-07-16` (scaffolding); a fresh branch when datasets land |
| **Start Date** | 2026-07-17 (scaffolding only) |
| **End Date (target)** | blocked — depends on dataset procurement + counsel export review |
| **Status** | `SCAFFOLDED — BLOCKED` |
| **Planset** | `.agentile/planset/2026-07-16-kyc-autoverify.md` (AV-S2 row) |
| **Predecessors** | AV-S0 (ADR-AV-1 targets), AV-S1 (service deployed + models pinned) |

## Why this sprint

Thresholds today are uncalibrated defaults (`MATCH_THRESHOLD=0.40`, `PAD_THRESHOLD=0.60`,
`tamperThreshold=0.5`); accuracy is unproven (`validate.py` has never run — planset §1).
This sprint earns the numbers ADR-AV-1 sets as targets. It is the gate the whole
program turns on: no auto-verify without a passing holdout report.

## Scaffolding delivered this session (agent-doable without datasets)

- `services/kyc-inference/calibration/THRESHOLDS.md` — provisional-vs-calibrated table,
  marks the current defaults UNCALIBRATED so they are never mistaken for validated.
- `services/kyc-inference/calibration/DATASETS.md` — required labeled sets + sizes +
  provenance/licensing/export (ITAR/EAR) checklist (planset §6).
- `services/kyc-inference/calibration/REPORT_TEMPLATE.md` — the immutable report skeleton
  with the ADR-AV-1 exit-gate table and owner+counsel sign-off lines.

## What remains (BLOCKED — external inputs)

- [!] Procure labeled bona-fide + attack + document datasets (counsel-gated; `DATASETS.md`).
- [!] Run `validate.py` (match + pad) on a frozen holdout; sweep thresholds; plot DET.
- [!] Calibrate + pin `KYC_MATCH_THRESHOLD` / `KYC_PAD_THRESHOLD` / `tamperThreshold` to
      the ADR-AV-1 targets; land the report; promote rows to CALIBRATED in `THRESHOLDS.md`.
- [ ] (Optional, agent-doable next) extend `validate.py` with a `--sweep` grid + JSON
      output + DET export so calibration is reproducible — deferred: writing a sweep we
      cannot run or test here would be scaffolding masquerading as done.

## Test Baseline

Unchanged from AV-S1 (447). This sprint adds no source/tests until datasets exist; the
`validate.py` enhancement (if taken) needs a Python test runner the repo does not yet
have — that decision is itself an AV-S2 WP, not silently assumed.

## Notes

Everything here is either scaffolding (done) or blocked on procured datasets + counsel
export review. AV-S2 is the reason auto-verify is a "measured, reversible rollout rather
than a leap" (planset §0) — do not shortcut it. The provisional thresholds must NOT be
promoted without a holdout report meeting the ADR-AV-1 bar.
