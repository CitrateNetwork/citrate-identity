---
created: 2026-07-17T02:45:00Z
branch: main
author: Larry Klosowski (@SaulBuilds) + Claude Opus 4.8
status: design — pending counsel review of the retention consent basis
planset: 2026-07-16-kyc-autoverify (AV-S2 / AV-S3)
---

# In-house consented capture program — genuine selfie↔ID pairs

> Our answer to the hardest sourcing gap: public data of *live-selfie-to-photographed-ID*
> pairs, from the real capture channel, at the scale needed to estimate **FMR ≤ 1e-4**
> (ADR-AV-1), barely exists. A small consented internal capture is the most
> representative source. This is a design; it does not run until counsel clears the
> retention consent basis (below).

## ⚠️ The load-bearing legal distinction (do not skip)

Production VERI **destroys** the biometric immediately after the 1:1 match
(`ADR-2026-07-01-biometric-bipa` point 2). A **calibration dataset must RETAIN** the
images to be re-runnable. These are two different consent bases:

- **Production consent** — capture + immediate destruction, no retention. (Already built.)
- **Calibration consent (NEW)** — explicit, separate written consent to **retain** a
  participant's selfie + ID-portrait for **model validation**, with a stated retention
  window, access control, and deletion. This is NOT covered by the production consent and
  MUST be its own BIPA/CUBI-compliant written release. **Counsel co-signs this before any
  capture.** (Ties to the `COUNSEL_REVIEW_PACKET.md` — add as ask #7 if capture proceeds.)

## Design that minimizes PII / legal exposure

**Do NOT collect participants' real government IDs for a retained set.** For the *face
match* metric (FMR/FNMR), what matters is the domain gap between a live selfie and a
portrait printed on a card. So:

- **Selfie:** live capture via the real VERI capture UI (same channel → representative).
- **"ID portrait":** the participant's selfie printed onto a mock ID-style card
  (portrait-on-card), photographed. This reproduces the print/photo-of-a-photo domain gap
  that makes selfie-to-ID matching hard, WITHOUT retaining a real government document.
- Real/forged **document authenticity** data (categories 8–9) comes from public synthetic
  ID datasets (MIDV / DocXPand / SIDTD family), NOT staff IDs — safer and more varied.

This splits cleanly: in-house capture earns the **match** pairs; public synthetic sets
earn the **document-authenticity** signal.

## Scale + composition (to support FMR ≤ 1e-4)

- **Participants:** target ~150–350 consenting people. N people cross-paired yields
  N·(N−1) impostor pairs → ~10⁴–10⁵ comparisons, enough to *estimate* FMR ≤ 1e-4 (a point
  estimate at 1e-4 wants ≥10⁴ impostor pairs; a confidence bound wants more).
- **Genuine pairs:** each participant provides ≥2 sessions (varied lighting/device) → their
  selfie(s) × their portrait-card = genuine pairs for FNMR.
- **Impostor pairs:** every participant's selfie × every *other* participant's card.
- **Coverage (bias control):** deliberately span skin tone (Fitzpatrick I–VI), age bands,
  and device classes (iOS/Android, front-camera range). Record these so FNMR can be
  reported per-cohort (a uniform FNMR that hides a per-cohort spike is a fairness problem).

## Handling + governance

- **US-hosted only** (ITAR/EAR + biometric residency, per the sanctions/biometric ADRs).
  The set never leaves US infra and never touches a third party.
- **Access-controlled**, encrypted at rest, dual-control for export — mirror the
  production KYC custody posture.
- **Frozen holdout:** split once, hash the split (per `DATASETS.md`), never let a
  calibration image leak into a threshold-tuning fold and then be reported as holdout.
- **Retention + deletion:** a stated window (e.g. the validation campaign + a fixed tail),
  then destruction; a participant can withdraw and have their data deleted at any time.
  Publish the schedule (mirrors the production destruction-schedule discipline).

## Suitability + honest limits

- Strong for **match FMR/FNMR** on the real channel; this is its whole point.
- Portrait-on-card is a *proxy* for a real ID portrait — it approximates the print domain
  gap but not real ID security features. Good enough for the *face-match* metric; NOT a
  substitute for real document-authenticity data (use public sets for that).
- Not a spoof set: presentation-attack (print/replay/mask/deepfake) data comes from the
  external catalog (AV-S3), not from this program.

## Gate

No capture begins until: (1) counsel clears the retention consent basis; (2) the written
calibration release is drafted; (3) the participant intake + deletion workflow exists.
Until then this is a design, tracked under AV-S2, not an active collection.
