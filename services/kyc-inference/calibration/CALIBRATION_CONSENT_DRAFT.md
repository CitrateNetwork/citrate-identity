---
created: 2026-07-17T02:45:00Z
updated: 2026-07-17T04:00:00Z
branch: sprint/kyc-autoverify-compliance-2026-07-17
author: Larry Klosowski (@SaulBuilds) + Claude Opus 4.8
status: FINAL DRAFT — complete, ready for legal review (ADR-AV-5); NOT legal advice
planset: 2026-07-16-kyc-autoverify (AV-S2); counsel packet ask #7
---

# Calibration capture — consent form + intake protocol (FINAL DRAFT for legal review)

> ⚠️ **Complete draft with concrete proposed values — NOT legal advice, and NOT for use
> until counsel reviews it.** Per ADR-AV-5 the owner blessed finalizing it; counsel reads
> this finished form **before the first live capture session**. Bracketed items marked
> `[CONFIRM: …]` are proposed values counsel/owner confirms. The load-bearing rule
> (BIPA §15(b)): **a signed release must precede any capture** — order of operations.

## A. Written consent / release — Citrate VERI calibration

**Biometric data collection + retention consent**

Citrate Inc. ("Citrate") is developing an in-house identity-verification system. To
**measure and improve the accuracy** of its face-matching and anti-spoofing models, Citrate
is collecting a small internal validation dataset. Because a face image is a **biometric
identifier**, your written consent is required before anything is collected.

By signing below, I acknowledge and agree that:

1. **What is collected.** A live selfie image and short video frames of my face, and a
   photograph of a portrait card bearing my likeness. **No government ID is collected or
   retained** for this program.
2. **Purpose.** Solely to measure and calibrate the accuracy of Citrate's face-matching and
   presentation-attack-detection (anti-spoofing) models. It is used for **no other purpose**.
3. **Retention — and how this differs from live verification.** Unlike Citrate's production
   identity check, which **destroys the biometric immediately after the match**, this
   validation program **retains** my images for **the shorter of (a) 12 months from capture
   or (b) completion of the validation campaign** `[CONFIRM window]`, after which they are
   **permanently destroyed**. This is well within BIPA's 3-year ceiling.
4. **No sale, no profit, no reuse.** My biometric data will **not** be sold, leased, traded,
   disclosed, or profited from, and will **not** be used to train a production model without
   a further separate written consent.
5. **Storage + security.** Stored **encrypted (AES-256-GCM)** on **US-based** infrastructure,
   access-controlled, and **never transferred to a third party or outside the United States**.
6. **Access.** Only authorized Citrate personnel (all US persons) may access the data.
7. **Withdrawal + deletion.** I may withdraw at any time and request deletion by emailing
   **`[CONFIRM: privacy@citrate.ai]`**; my data will be deleted within **30 days** `[CONFIRM]`.
8. **Voluntary.** Participation is entirely voluntary. For staff: declining or withdrawing
   has **no effect on my employment**.

I have read this disclosure, I understand it, and I voluntarily consent to the collection,
storage, and retention of my biometric data as described.

Signature: ____________________  Printed name: ____________________  Date: __________
Email (for deletion requests): ____________________

## B. Intake protocol (operational)

- **Recruitment:** consenting Citrate staff/volunteers (all US persons). Deliberately span
  skin tone (Fitzpatrick I–VI), age bands, and device classes — record each (needed for
  per-cohort FNMR / bias analysis).
- **Consent FIRST:** the signed form (§A) is captured and stored **before** any biometric is
  collected. No capture without a countersigned release on file (BIPA §15(b) order of ops).
- **Capture:** live selfie via the real VERI capture UI (representative channel) + a
  photographed portrait-on-card (proxy for an ID portrait; no real government ID retained).
- **Sessions:** ≥2 per participant (varied lighting/device) for genuine-pair coverage.
- **Storage:** encrypted at rest (AES-256-GCM), US-hosted, dual-control for export — mirror
  the production KYC custody posture.
- **Split:** freeze the holdout once, hash it (per `DATASETS.md`); no leakage into tuning folds.
- **Registers:** maintain (1) a consent register (signed form, pseudonymous participant id,
  cohort attributes) and (2) a deletion-request log.
- **Deletion:** on withdrawal or at the retention deadline, destroy images + derived
  templates and record the destruction.

## C. Counsel review checklist (confirm before first live capture)
- [ ] BIPA (740 ILCS 14) §15(b) written-release elements complete (what / purpose / term).
- [ ] BIPA §15(a) published retention + destruction schedule matches §A.3.
- [ ] BIPA §15(c) no-sale/no-profit affirmed (§A.4).
- [ ] BIPA §15(e) reasonable security (AES-256-GCM, US-hosted, access control) adequate.
- [ ] Texas CUBI / Washington / other applicable state biometric law satisfied.
- [ ] GDPR Art. 9 — N/A if no EU data subjects (participants are US staff/volunteers). Confirm.
- [ ] Staff voluntariness (no coercion / employment consequence) — §A.8.
- [ ] Confirm `[bracketed]` values (retention window, deletion SLA, privacy contact).
- [ ] Sign-off recorded in `COUNSEL_REVIEW_PACKET.md` ask #7.
