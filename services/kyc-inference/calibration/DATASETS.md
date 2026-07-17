---
created: 2026-07-17T00:00:00Z
branch: sprint/kyc-autoverify-av-s0-s1-2026-07-16
author: Larry Klosowski (@SaulBuilds) + Claude Opus 4.8
status: checklist — datasets NOT yet procured (AV-S2 blocker)
planset: 2026-07-16-kyc-autoverify
---

# VERI validation datasets — what AV-S2/S3/S4 need (and the provenance rules)

> None of these ship in the repo. Procuring them is an **external, counsel-gated**
> action (planset §6 dataset-provenance): attack/bona-fide sets carry their own PII,
> licensing, and export-control (ITAR/EAR) considerations. This file is the checklist
> for whoever assembles them. Until they exist, AV-S2 cannot run and auto-verify cannot
> ship.

## Required sets

| Set | Purpose | Metric it feeds | Minimum size (pilot) | Notes |
|---|---|---|---|---|
| Bona-fide live selfies | genuine PAD negatives + match genuines | BPCER, FNMR | ~500 subjects, varied device/lighting/skin-tone | must mirror the real capture channel |
| Selfie↔ID genuine pairs | true 1:1 matches | FNMR | ~500 pairs | live selfie vs *photographed physical ID* (cross-domain) |
| Selfie↔ID impostor pairs | false 1:1 matches | FMR | ~5,000 pairs (for a 1e-4 estimate) | different-person pairs; enough to estimate FMR ≤ 1e-4 |
| Print attacks | printed-photo spoofs | APCER (print) | ~300 | CASIA-FASD / Replay-Attack style |
| Replay attacks | screen-replay spoofs | APCER (replay) | ~300 | phone/monitor replays |
| Mask / cutout attacks | 3D/2D mask spoofs | APCER (mask) | ~200 | higher-effort artefacts |
| **Deepfake / synthetic** | injected synthetic faces | APCER (deepfake) | ~300 | **critical for 2026**; note OSS PAD does NOT cover injection (ADR-AV-3 residual) |
| Genuine documents | authentic ID images | tamper genuine-pass | ~300 across the launch doc mix | passports + driver licenses |
| Forged / tampered documents | manipulated IDs | tamper forged-accept | ~200 | photo-swap, field edits, synthetic |

**FMR statistics note:** estimating FMR ≤ 1e-4 with confidence needs on the order of
10⁴–10⁵ impostor comparisons. ~500 identities cross-paired yields ~10⁵ impostor pairs —
size the genuine set with the impostor-pair count in mind, not just subject count.

## Provenance / licensing / export checklist (every set)
- [ ] Source + license recorded; redistribution terms compatible with our use.
- [ ] Consent basis for any real biometric data (BIPA/CUBI — `ADR-2026-07-01-biometric-bipa`).
- [ ] PII handling: stored on US infra only; access-controlled; deletion schedule set.
- [ ] Export-control (ITAR/EAR) review with counsel before import/use.
- [ ] Holdout split frozen and hashed so AV-S2 results are reproducible (no train/test leak).
- [ ] Demographic coverage documented (skin tone, age, device) to check for bias in FNMR.

## Handoff
When assembled, place under a host-local (never-committed) path and record only the
frozen-split hash + provenance notes here. Then AV-S2 runs `validate.py` per
`THRESHOLDS.md` and lands the numbers in `REPORT_TEMPLATE.md`.
