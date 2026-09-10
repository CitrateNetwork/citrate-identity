---
created: 2026-07-17T04:10:00Z
branch: sprint/kyc-autoverify-compliance-2026-07-17
author: Larry Klosowski (@SaulBuilds) + Claude Opus 4.8
status: engineering compliance map — NOT legal advice; counsel confirms
planset: 2026-07-16-kyc-autoverify (VERI-AV)
---

# Biometric / privacy law → Citrate VERI code & architecture

> **What this is:** an engineering map from each legal requirement to the exact place in
> our code/architecture that satisfies it, so "compliant in every way" is *inspectable*.
> **What this is NOT:** legal advice. It is my best-effort mapping to inform the
> architecture; **outside counsel confirms** (packet asks #6–#8). Illinois **BIPA** is the
> strictest regime and the only one with a private right of action, so it is the spine.

## Two distinct subjects (they have different rules)

| | Production verification (live customers) | Calibration capture (internal validation set) |
|---|---|---|
| Biometric lifetime | **Destroyed immediately after the 1:1 match** | **Retained** under a separate written consent |
| Consent | Production capture-UI release (step 1) | `CALIBRATION_CONSENT_DRAFT.md` (retains) |
| Governing ADR | `ADR-2026-07-01-biometric-bipa` | ADR-AV-5 + the consent form |

The retention difference is *the* reason the calibration set needs its own consent basis.

## BIPA (740 ILCS 14) → where we satisfy it

| BIPA section | Requirement | Where satisfied (code / architecture) | Status |
|---|---|---|---|
| **§15(a)** | Written, public retention + destruction schedule; destroy at purpose-satisfied or ≤3 yrs | Production: destroy-after-match (`kyc-engine.ts:147` `runCase` → `store.destroyBiometricsForCase`, impl `kyc-cases-pg.ts:373`) + retention window on the case record (`kyc-engine.ts:154` `retentionUntil`) + deletion scheduler (`kyc-retention.ts`). Calibration: schedule in consent §A.3 (≤12 mo). **Public schedule text drafted: `docs/BIOMETRIC_RETENTION_SCHEDULE.md`.** | ✅ code + policy drafted; ⚠️ counsel confirm → publish |
| **§15(b)** | No capture without written notice + purpose + **written release** | Production: capture-UI step-1 plain-language notice + affirmative e-release (`ADR-2026-07-01-biometric-bipa` §1). Calibration: signed release **before** capture (consent §A + intake §B "consent FIRST"). | ✅ (order-of-operations enforced) |
| **§15(c)** | No sale / lease / trade / **profit** from biometrics | No code path sells or exposes biometrics; biometric is destroyed post-match (nothing to sell). Consent §A.4 affirms. Public/compliance copy must not monetize it. | ✅ by design |
| **§15(d)** | No disclosure without consent | Biometric never leaves US infra, never sent to a third party; admin access is allowlisted (`admin-kyc-routes.ts` `KYC_ADMIN_SUBS`) + dual-control unlock. | ✅ |
| **§15(e)** | Reasonable standard of care; store/transmit securely | AES-256-GCM envelope encryption (`kyc-crypto.ts`), per-case DEKs, server-blind DB, US-hosted; key-custody hardening tracked (ADR-AV-4 / AV-S7 seam). | ✅ (KMS is a hardening upgrade, not a §15(e) gap) |

**Net:** with **consent-before-capture** enforced, §15(b) — the private-right-of-action
trigger — is met; §15(a)/(c)/(d)/(e) are met by the existing architecture. The only
paperwork to finish is the **public** retention-schedule text (§15(a)).

## Other regimes (counsel confirms applicability)

| Regime | Applies? | Posture |
|---|---|---|
| **Texas CUBI** | Yes (no private action; AG enforces) | Same consent + destruction posture as BIPA covers it. |
| **Washington (RCW 19.375)** | Yes | Consent + no-sale posture covers it. |
| **CCPA/CPRA (California)** | Likely (biometric = sensitive PI) | Consent + disclosure + deletion rights → DSAR route (`admin-kyc-routes.ts` `/admin/kyc/dsar`, `/admin/kyc/delete`). |
| **GDPR Art. 9 (EU)** | Calibration: **N/A** (participants are US staff/volunteers). Production: only if EU customers | Flagged for counsel on the production side; out of scope for the calibration set. |
| **Illinois GIPA / genetic** | N/A | No genetic data collected. |

## Identity-assurance + financial-crime (not privacy law, but part of "compliant")

| Concern | Standard / rule | Where |
|---|---|---|
| Identity proofing assurance | NIST 800-63A **IAL2** target | ADR-AV-1; `kyc-engine.ts` decision |
| Sanctions / OFAC screening | OFAC SDN + CSL; embargo | `kyc-screening.ts` (+ AV-S5 DOB precision) |
| Export control (datasets) | ITAR/EAR | ADR-AV-5: all-US-person, US-hosted, no re-export → resolved |
| Audit / recordkeeping | Immutable, hash-chained | `kyc-audit-pg.ts`; dual-control (`admin-kyc-routes.ts`) |

## Open items (paperwork, not code gaps)
1. **Publish the §15(a) retention/destruction schedule** — drafted in
   `docs/BIOMETRIC_RETENTION_SCHEDULE.md`; counsel confirms the 12-month window + contact,
   then Part 1 publishes into the public data-handling terms (citrate-landing / dataroom).
2. **Counsel review** of: the finished consent form (§15(b), ask #7), the IAL2 assertion
   (ask #1), and the embargo list (ask #5).
3. Keep public/compliance copy **honest about the KMS residual** until AV-S7 WP-2 lands
   (server still holds the master key — ADR-AV-4).

**Bottom line for the architecture:** the code already implements the substantive biometric
duties (destroy-after-match, encryption, access control, deletion, audit). The remaining
work to be "compliant in every way" is **procedural** — consent-before-capture (enforced by
design), the published retention schedule, and counsel's confirmation — not new code.
