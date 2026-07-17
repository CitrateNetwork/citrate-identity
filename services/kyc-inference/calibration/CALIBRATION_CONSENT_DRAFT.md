---
created: 2026-07-17T03:20:00Z
branch: sprint/kyc-autoverify-data-acquisition-2026-07-17
author: Larry Klosowski (@SaulBuilds) + Claude Opus 4.8
status: DRAFT — owner-blessed to finalize (ADR-AV-5); counsel reads finished form before first live capture
planset: 2026-07-16-kyc-autoverify (AV-S2); counsel packet ask #7
---

# Calibration capture — consent form + intake protocol (DRAFT)

> ⚠️ **This is a starting point, not legal advice, and NOT for use as-is.** Outside counsel
> must review and finalize it before any capture (counsel packet ask #7). It exists so
> counsel edits a concrete draft instead of starting from a blank page. The load-bearing
> difference from production: this capture **RETAINS** biometric data for validation, which
> production does not — so it needs this separate written release (BIPA/CUBI, and GDPR if
> any EU participant). See `INHOUSE_CAPTURE_PROGRAM.md`.

## A. Written consent / release (draft language)

**Biometric data collection + retention consent — Citrate VERI calibration**

I, the undersigned, voluntarily agree to participate in Citrate's identity-verification
model **validation** program. I understand and consent to the following:

1. **What is collected.** A live selfie image (and short video frames) of my face, and a
   photograph of a portrait card bearing my likeness. *(No government ID is collected or
   retained for this program.)*
2. **Why.** Solely to **measure and calibrate** the accuracy of Citrate's face-matching and
   anti-spoofing models (a face image is a biometric identifier).
3. **Retention — and how this differs from live verification.** Unlike Citrate's production
   identity check, which destroys the biometric immediately, **this program retains** my
   images for up to **[retention window, e.g. 12 months / end of the validation campaign]**,
   after which they are permanently destroyed.
4. **No sale, no reuse.** My biometric data will **not** be sold, leased, traded, or used for
   any purpose other than this validation. It will not train a production model without a
   further, separate consent. *(BIPA prohibits profiting from biometric data.)*
5. **Storage + access.** Stored encrypted on **US-based** infrastructure, access-controlled,
   never transferred to a third party or outside the US.
6. **Withdrawal.** I may withdraw at any time and request deletion of my data by contacting
   **[privacy contact]**; my data will be deleted within **[e.g. 30 days]**.
7. **Voluntary.** Participation is voluntary; [for staff: declining has no employment effect].

Signature: ____________________  Printed name: ____________________  Date: __________
Email (for deletion requests): ____________________

## B. Intake protocol (operational)

- **Recruitment:** consenting staff/volunteers; deliberately span skin tone (Fitzpatrick
  I–VI), age bands, and device classes (record each — needed for per-cohort FNMR / bias check).
- **Capture:** live selfie via the real VERI capture UI (representative channel) + a
  photographed portrait-on-card (proxy for an ID portrait; no real government ID retained).
- **Sessions:** ≥2 per participant (varied lighting/device) for genuine-pair coverage.
- **Storage:** encrypted at rest, US-hosted, dual-control for export — mirror production custody.
- **Split:** freeze the holdout once, hash it (per `DATASETS.md`), no leakage into tuning folds.
- **Register:** log consent form, participant id (pseudonymous), cohort attributes, and the
  deletion-request channel. Maintain a deletion log.
- **Deletion:** on withdrawal or at the retention deadline, destroy images + derived
  templates and record it.

## C. Counsel checklist (what to confirm before capture)
- [ ] BIPA (740 ILCS 14) written-release elements present (notice + purpose + retention + no-sale).
- [ ] Texas CUBI / Washington + any other applicable state biometric law.
- [ ] GDPR Art. 9 basis if any participant is in the EU (or exclude EU participants).
- [ ] Staff-participant voluntariness (no coercion / employment consequence).
- [ ] Retention window + deletion SLA are lawful and match the published schedule.
- [ ] Sign-off recorded in `COUNSEL_REVIEW_PACKET.md` ask #7.
