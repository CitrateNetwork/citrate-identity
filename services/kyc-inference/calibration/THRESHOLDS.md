---
created: 2026-07-17T00:00:00Z
branch: sprint/kyc-autoverify-av-s0-s1-2026-07-16
author: Larry Klosowski (@SaulBuilds) + Claude Opus 4.8
status: PROVISIONAL — uncalibrated (AV-S2 not yet run)
planset: 2026-07-16-kyc-autoverify
---

# VERI thresholds — provisional vs. calibrated

> **These thresholds are UNCALIBRATED DEFAULTS.** They are *not* validated against any
> labeled dataset and must not be mistaken for the AV-S2 result. Until AV-S2 runs
> `validate.py` on a holdout and this file records the earned operating point, the
> engine stays in advisor/manual-review mode (planset §5). Pinning a threshold without
> its validation report is a Rule-11 violation.

## Current (provisional) values and their targets

| Threshold | Env var | Provisional default | Set in | Calibrate to (ADR-AV-1) | Earned in |
|---|---|---|---|---|---|
| 1:1 face match | `KYC_MATCH_THRESHOLD` | `0.40` | `inference.py:36` | operating point at **FMR ≤ 1e-4**, FNMR ≤ 5% | AV-S2 |
| PAD live-prob | `KYC_PAD_THRESHOLD` | `0.60` | `inference.py:38` | **APCER ≤ 5% at BPCER ≤ 3%** | AV-S3 |
| Document tamper | `tamperThreshold` | `0.5` (Node side) | doc analyzer | forged-accept ≤ 2% at genuine-pass ≥ 95% | AV-S4 |
| PAD enforce | `KYC_PAD_ENFORCE` | `false` | `inference.py:137` | flip `true` only after AV-S3 evidence (ADR-AV-3) | AV-S3 |

## The calibration procedure (AV-S2 / AV-S3 / AV-S4)

1. Assemble the labeled holdout (see `DATASETS.md`) — bona-fide + attack, representative
   of the **real capture channel** (phone selfie vs. photographed physical ID). A
   holdout that isn't representative produces fiction (planset §6 threshold-drift).
2. Run the harness:
   ```bash
   python validate.py match --pairs holdout/pairs.csv        # → FMR / FNMR at a threshold
   python validate.py pad --live_dir holdout/live --attack_dir holdout/<attack_type>
   ```
   Sweep the threshold (repeat across a grid) to find the operating point that meets the
   ADR-AV-1 target, and plot the DET curve.
3. Record the chosen threshold **and** the report that justifies it in
   `REPORT_TEMPLATE.md` (dated, immutable — Rule 3).
4. Pin the threshold in the deploy env **with a pointer to that report**. Any model or
   threshold change re-triggers steps 1–4 (planset §6).

## Exit-gate binding

A threshold may move from PROVISIONAL to CALIBRATED here only when its row in the
AV-S2/S3/S4 report meets the ADR-AV-1 target on a holdout. This table is the single
source of truth for threshold state (Rule 9); the deploy env quotes it, never the
reverse.
