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
>
> **Sourcing status (2026-07-17):** a cited catalog of real candidate datasets is in
> `DATASET_RESEARCH_2026-07-17.md`; the selfie↔ID gap is addressed by
> `INHOUSE_CAPTURE_PROGRAM.md`. The acquire-first plan below is the actionable summary.

## Acquire-first plan (verified 2026-07-17 — re-confirm licenses at download)

Owner posture: **research licenses OK for calibration R&D** (must NOT ship in a
commercial pipeline), **free/open first + scope paid to harden**, **in-house capture on**.

| # | Category → metric | Acquire first (free/open) | Commercial-friendly option | Gap / paid hardening |
|---|---|---|---|---|
| 1 | Bona-fide selfies → BPCER | CelebA-Spoof, SiW-Mv2 (live subsets) | — (real biometric) | in-house capture adds real-channel coverage |
| 2 | Genuine selfie↔ID pairs → FNMR | **none public** | — | **in-house capture** (primary) or paid KYC-vendor corpus |
| 3 | Impostor selfie↔ID pairs → FMR ≤1e-4 | **none public** | — | **in-house cross-pairing** (~150–350 people → 10⁴–10⁵ pairs) or paid corpus |
| 4 | Print attacks → APCER | SiW-Mv2, CelebA-Spoof, OULU-NPU | — | iBeta ISO 30107-3 test service (paid; pricing TBD) |
| 5 | Replay attacks → APCER | SiW-Mv2, CelebA-Spoof, OULU-NPU | — | iBeta (paid) |
| 6 | Mask/3D → APCER | **SiW-Mv2** (14 spoof types incl. masks) | — | iBeta (paid) |
| 7 | Deepfake/injection → APCER | **DF40** (40 techniques, 2026-relevant) | — | DeepFakeFace / Deepfake-Eval-2024 *(licenses UNRESOLVED — re-verify)* |
| 8 | Genuine ID docs → genuine-pass | MIDV-Holo | **MIDV-Holo (CC BY-SA 2.5)** | genuine passport/DL corpus is an OPEN gap (in-house or paid) |
| 9 | Forged/tampered docs → forged-accept | **IDNet**, SIDTD *(license unresolved)* | **IDNet (CC0)** | — |

**The two hard rules from the research:**
1. **Only IDNet (CC0) and MIDV-Holo (CC BY-SA 2.5) are commercial-usable.** Everything else
   free is research-only — fine for calibrating (R&D), but the model shipped to production
   must not be trained/tuned on a research-only set without a commercial license.
2. **SiW-Mv2 carries IARPA/ODIN provenance → export-control (ITAR/EAR).**

**Acquisition posture (2026-07-17 — ADR-AV-5, owner executive decision):** research-license
calibration and SiW-Mv2 use are **blessed to proceed** for internal R&D. **Guardrail on
SiW-Mv2:** keep it **US-person-access-only, no re-export** (export exposure is foreign-person
access / re-export, not domestic US-person research use). If any non-US-person will access
it, stop and get an export-control read first; else default to the non-IARPA sets
(CelebA-Spoof, OULU-NPU, DF40).

**License-UNRESOLVED (do not use until re-verified):** SIDTD, DeepFakeFace, Deepfake-Eval-2024.
**Open procurement items:** iBeta/ISO 30107-3 pricing; a commercial genuine-passport corpus.

### Acquisition helpers (2026-07-17)
- `download_doc_datasets.sh` — fetch + SHA-pin the commercial-safe doc sets (IDNet CC0 +
  MIDV-Holo CC BY-SA 2.5), fail-closed, writes `DOC_DATASETS.lock`. **Start here** — no
  license/PII blocker; feeds AV-S4 document authenticity.
- `VENDOR_OUTREACH_iBeta.md` — draft email to resolve iBeta/ISO 30107-3 pricing + whether
  they license attack corpora (owner sends).
- `CALIBRATION_CONSENT_DRAFT.md` — draft retention-consent + intake protocol for the
  in-house capture (counsel finalizes — packet ask #7). Unblocks the FMR ≤ 1e-4 gap.
- Research-only PAD sets (SiW-Mv2, CelebA-Spoof, DF40) need their own EULA/DRA + counsel's
  research-license blessing (ask #8) before download — no auto-fetch script for those.

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
