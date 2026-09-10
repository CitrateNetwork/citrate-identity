---
created: 2026-07-17T03:45:00Z
branch: sprint/kyc-autoverify-data-acquisition-2026-07-17
author: Larry Klosowski (@SaulBuilds) + Claude Opus 4.8
status: owner-executive-decision — counsel reviews finished work
adr: AV-5
planset: 2026-07-16-kyc-autoverify (VERI-AV)
supersedes: none
relates: COUNSEL_REVIEW_PACKET.md asks #7 and #8
---

# ADR-AV-5 — Executive decision to proceed on calibration data (asks #7 & #8)

> **This is an OWNER executive risk-acceptance, NOT a counsel sign-off.** Recorded so the
> record stays honest: counsel has delegated iterative judgment to the owner/AI and will
> **review finished work**, not gate each step. Nothing here is legal advice, and the
> residual risks below are **not waived** — they are accepted-to-proceed and preserved for
> counsel's review of the finished artifacts.

## Context

The counsel packet's asks #7 (calibration retention consent) and #8 (research-licensed
calibration data + SiW-Mv2 ITAR/EAR) were blocking dataset acquisition pending counsel
input. On 2026-07-17 the owner (Larry Klosowski) made an **executive decision to proceed**
on both, on the stated basis that counsel prefers to **review finished work rather than
iterate**, and delegated the judgment.

## Decision (owner-executive, 2026-07-17)

Proceed to produce **finished** calibration artifacts without waiting for per-step counsel
input, specifically:

1. **Ask #7 — retention consent:** finalize `CALIBRATION_CONSENT_DRAFT.md` into a complete
   consent form + intake protocol, and prepare the in-house capture program to run.
2. **Ask #8 — research-licensed data:** use academic-research-licensed datasets
   (CelebA-Spoof, SiW-Mv2, DF40, OULU-NPU) for **internal calibration R&D**, and stage the
   commercial-safe sets (IDNet, MIDV-Holo).

Counsel reviews the finished artifacts (consent form, provenance log, validation report).

## Material facts (owner-confirmed 2026-07-17)

- **The entire team is US persons; no foreign national has access to any of the data.**
- All data is **US-hosted**; there is **no re-export**.

These facts **materially resolve the export-control concern** below: ITAR "deemed export"
and EAR foreign-person-release exposure arise from **releasing controlled data to foreign
persons or re-exporting it** — neither occurs here. Domestic use of a US-origin research
dataset by US persons on US infrastructure is the low-risk path, and that is our posture.

## Residual risks — status after the material facts (preserved for counsel)

An internal blessing does not change external law, so these are recorded for counsel's
review of the finished work — but the owner-confirmed facts above change their status:

1. **Export control on SiW-Mv2 (IARPA/ODIN provenance).** **Substantially resolved** by the
   all-US-person / no-re-export facts. Standing guardrail: if that ever changes — any
   non-US-person access or any re-export — **stop and get an export-control read first.**
   (Note: whether SiW-Mv2 is export-controlled *at all* is itself unconfirmed; most academic
   face datasets are not. The all-US-person posture makes it a non-issue in practice either way.)
2. **Live biometric capture (BIPA/CUBI) — order of operations, not a blocker.** Per BIPA
   §15(b), the violation is **capturing biometrics without a prior written release**; a
   **signed consent BEFORE capture makes the capture lawful.** So this is an ordering
   requirement: consent-then-capture is compliant. Guardrail retained: the *finished* consent
   form (now complete in `CALIBRATION_CONSENT_DRAFT.md`) gets a **counsel read before the
   first live session**, and consent is captured **before** any biometric — the AI
   checkpoints with the owner before initiating live capture. The other BIPA duties
   (§15(a) published retention/destruction schedule, §15(c) no sale/profit, §15(e)
   reasonable security) are satisfied by the program design + existing architecture — see
   `COMPLIANCE_MAPPING.md`.
3. **Research-license bleed.** Research-only datasets are for **calibration measurement**,
   not for training/tuning the **shipped** production model. Keep that boundary; a model
   shipped commercially must not be trained on a research-only set without a commercial
   license.

## Consequences

- Unblocks dataset acquisition and the capture-program preparation immediately.
- Keeps the record honest: `COUNSEL_REVIEW_PACKET.md` shows asks #7/#8 as **owner-blessed
  to proceed (executive)**, counsel box still open, to be checked when counsel reviews the
  finished work.
- The two irreversible/legal-exposure steps (SiW-Mv2 foreign-person access or re-export;
  first live biometric capture) retain explicit guardrails; the AI will checkpoint with the
  owner before performing either rather than doing them silently.

## Sign-off

| Role | Name | Date | Status |
|------|------|------|--------|
| Engineering/security owner (executive) | Larry Klosowski (@SaulBuilds) | 2026-07-17 | ✅ proceed |
| Outside counsel | — | — | ☐ reviews finished work |
