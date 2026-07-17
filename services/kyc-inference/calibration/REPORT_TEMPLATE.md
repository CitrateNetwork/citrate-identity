---
created: 2026-07-17T00:00:00Z
branch: <sprint branch when AV-S2 runs>
author: <who ran it>
status: TEMPLATE — copy to REPORT_<YYYY-MM-DD>.md when AV-S2 runs (then immutable, Rule 3)
planset: 2026-07-16-kyc-autoverify
---

# VERI accuracy validation report — <DATE>

> Copy this file to `REPORT_<YYYY-MM-DD>.md`, fill it from a real `validate.py` run on a
> frozen holdout, and commit it as the evidence that justifies the pinned thresholds.
> Immutable once written (Rule 3); corrections go in a dated erratum.

## Run metadata
- Models + pins: buffalo_l `<sha256>`, anti_spoof `<sha256>` (from `MODELS.lock`).
- Holdout: `<frozen-split hash>`, sizes per `DATASETS.md`, provenance ref `<...>`.
- Commit / image: `<git sha>` / `<image digest>`.
- Operator + reviewer: `<names>`.

## Results vs. ADR-AV-1 targets (the exit gate)

| Metric | Threshold | Target (ADR-AV-1) | Measured | Pass? |
|---|---|---|---|---|
| FMR (impostor accepted) | `KYC_MATCH_THRESHOLD=<v>` | ≤ 1e-4 | `<...>` | ☐ |
| FNMR (genuine → review) | same | ≤ 5% | `<...>` | ☐ |
| APCER — print | `KYC_PAD_THRESHOLD=<v>` | ≤ 5% @ BPCER ≤ 3% | `<...>` | ☐ |
| APCER — replay | same | ≤ 5% | `<...>` | ☐ |
| APCER — mask | same | ≤ 5% | `<...>` | ☐ |
| APCER — deepfake | same | (residual — see ADR-AV-3) | `<...>` | ☐ |
| BPCER (genuine → spoof) | same | ≤ 3% | `<...>` | ☐ |
| Tamper forged-accept | `tamperThreshold=<v>` | ≤ 2% @ genuine-pass ≥ 95% | `<...>` (AV-S4) | ☐ |

## DET curves
`<attach or link DET/ROC plots for match and PAD>`

## Decision
- [ ] All rows meet target on the holdout → thresholds promoted CALIBRATED in
      `THRESHOLDS.md`, pinned in deploy env with a pointer to this report.
- [ ] Any row fails → threshold stays PROVISIONAL; engine stays manual-review; remediate
      (better data / certified PAD per ADR-AV-3 / dedicated tamper model per AV-S4).

## Sign-off
- Owner (thresholds accepted): `<name / date>`
- Counsel (IAL2 assertion, per ADR-AV-1 / D8 / HAR-258): `<name / date>`
