---
created: 2026-07-17T03:00:00Z
branch: sprint/kyc-autoverify-datasets-2026-07-17
author: deep-research harness (wf_1807c429-9e8) + Claude Opus 4.8
status: research artifact — verify licenses AT ACQUISITION TIME (they change)
planset: 2026-07-16-kyc-autoverify (AV-S2/S3/S4)
---

# VERI calibration dataset research (cited) — 2026-07-17

> Produced by a fan-out/verify/synthesize research pass (111 agents, 3-vote adversarial
> verification). Every finding below is `high` confidence (3-0 vote) unless noted.
> **Three license claims were REFUTED and are marked UNRESOLVED — do not treat those as
> commercial-usable until re-verified.** Licenses and access terms change; re-confirm at
> acquisition (Rule 11 applies to procurement too).

## Verified catalog

| Dataset | Category → metric | Size | License / commercial | Access | Flags |
|---|---|---|---|---|---|
| **SiW-Mv2** (MSU) | 4/5/6 print+replay+mask APCER; BPCER | 785 live/493 subj + 915 spoof/600 subj, 14 IARPA-verified spoof types | Research-only (MSU); commercial prohibited w/o MSU approval | Signed Dataset Release Agreement | **ITAR/EAR: IARPA/ODIN provenance — export review.** Real biometric → BIPA/GDPR. Best single free source for physical PAD. |
| **CelebA-Spoof** (CUHK) | 4/5/1 print+replay APCER; BPCER | 625,537 imgs / 10,177 subj, 10 spoof types | Research-only; commercial reproduce/sell/exploit prohibited | Registration + EULA | Real biometric → BIPA/GDPR. Largest free PAD set. |
| **OULU-NPU** | 4/5 print+replay APCER; BPCER | 4,950 videos / 55 subj | Academic EULA (no free-domain email; permanent-position signatory) | Signed institutional EULA | Real biometric → BIPA/GDPR. Well-benchmarked supplement. |
| **DF40** | 7 deepfake APCER | 40 generation techniques (swap/reenact/synthesis/edit), incl. HeyGen/InSwapper/SimSwap | CC BY-NC 4.0 — commercial PROHIBITED | Open (research) | Best 2026-relevant deepfake benchmark. Synthetic. |
| **DeepFakeFace (DFF)** | 7 deepfake APCER | 120,000 imgs (4×30k: SD-Inpaint/InsightFace/SD1.5/real IMDB-WIKI) | ⚠️ Apache-2.0 claim **REFUTED → UNRESOLVED** | HuggingFace | Contains real IMDB-WIKI faces → BIPA/GDPR. |
| **Deepfake-Eval-2024** | 7 in-the-wild deepfake eval | 45h video / 56.5h audio / 1,975 imgs, 88 sites/52 langs | ⚠️ CC BY-SA 4.0 + open-download claim **REFUTED → UNRESOLVED** | Unconfirmed | Best in-the-wild 2024 eval — resolve access before relying on it. |
| **IDNet** | 9 forged-doc forged-accept | 837,060 synthetic imgs / 20 doc types (10 US states + 10 EU), ~490GB, 6 forgery patterns | **CC0 — commercial OK** | Zenodo (open) | Fully synthetic, no real PII (sidesteps BIPA/GDPR). Top commercial-friendly pick. |
| **MIDV-Holo** (Smart Engines) | 8/9 doc authenticity + hologram/OVD | 700 clips artificial passports/IDs; 1 genuine (300) + 4 attack (400) | **CC BY-SA 2.5 — commercial OK (attribution + share-alike)** | Open | Artificial "Utopia" docs. Only verified OVD/hologram set. |
| **SIDTD** | 9 forged-doc forged-accept | Synthetic forgeries on MIDV2020, 10 EU nationalities | ⚠️ CC-BY-4.0 claim **REFUTED → UNRESOLVED** | GitHub | Purpose-built genuine-vs-forged classifier data. |
| **DocXPand-25k** (QuickSign) | 8 doc localization/OCR ONLY | 24,994 synthetic imgs / 9 EU designs | CC BY-NC-SA 4.0 — commercial PROHIBITED | GitHub | Authors state NOT for forgery detection — do not use for forged-accept. |
| **(none found)** | **2 genuine selfie↔ID pairs (FNMR); 3 impostor selfie↔ID pairs (FMR ≤1e-4)** | — | — | — | **No usable public dataset verified.** Gap → in-house capture (`INHOUSE_CAPTURE_PROGRAM.md`) or paid vendor corpus. |

## Key takeaways

- **Commercial-friendly (usable in a shipped pipeline): only IDNet (CC0) and MIDV-Holo
  (CC BY-SA 2.5)** — both document-side, both synthetic.
- **Research-only (calibration R&D acceptable per owner; MUST NOT ship in a commercial
  pipeline): CelebA-Spoof, SiW-Mv2, OULU-NPU, DF40, DocXPand.**
- **License UNRESOLVED (refuted claims — re-verify before ANY use): SIDTD, DeepFakeFace,
  Deepfake-Eval-2024.**
- **Export control:** SiW-Mv2 carries IARPA/ODIN provenance → ITAR/EAR review with counsel.
- **PII/BIPA:** real-biometric sets (CelebA-Spoof, SiW-Mv2, OULU-NPU real, DFF's IMDB-WIKI)
  are subject to BIPA/GDPR; fully-synthetic sets (IDNet, DocXPand, MIDV-Holo, DF40) largely avoid it.
- **The FMR/FNMR gap is real:** selfie-to-ID pairs (categories 2, 3) have no public source →
  in-house consented capture or a paid vendor corpus is the ONLY path to FMR ≤ 1e-4 evidence.

## Open items (not resolved by the evidence — need direct vendor/counsel follow-up)

- iBeta / ISO 30107-3 Level 1/2 PAD test **pricing + whether they license attack corpora
  or only certify** — no pricing verified; source directly from the vendor.
- Definitive current licenses of **SIDTD, DeepFakeFace, Deepfake-Eval-2024** (3 refuted).
- A commercially-licensable **genuine passport / driver-license** corpus for category 8
  (beyond MIDV-Holo's hologram focus) — likely in-house-captured real docs or a paid vendor.

## Sources (primary)
- SiW-Mv2: cvlab.cse.msu.edu/siw-mv2-dataset.html · arxiv.org/abs/2208.11148
- CelebA-Spoof: mmlab.ie.cuhk.edu.hk/projects/CelebA/CelebA_Spoof.html · arxiv.org/abs/2007.12342
- OULU-NPU: sites.google.com/site/oulunpudatabase/
- DF40: github.com/YZY-stack/DF40
- DeepFakeFace: huggingface.co/datasets/OpenRL/DeepFakeFace · arxiv.org/abs/2309.02218
- Deepfake-Eval-2024: arxiv.org/pdf/2503.02857 · github.com/nuriachandra/Deepfake-Eval-2024
- IDNet: arxiv.org/html/2408.01690v1 · zenodo.org/record/10570622
- MIDV-Holo: github.com/SmartEngines/midv-holo
- SIDTD: github.com/Oriolrt/SIDTD_Dataset · arxiv.org/abs/2401.01858
- DocXPand-25k: github.com/QuickSign/docxpand · arxiv.org/abs/2407.20662
