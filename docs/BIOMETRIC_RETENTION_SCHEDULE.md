---
created: 2026-07-18T00:00:00Z
branch: sprint/kyc-autoverify-retention-schedule-2026-07-18
author: Larry Klosowski (@SaulBuilds) + Claude Opus 4.8
status: draft for legal review — publish to the public data-handling terms once counsel confirms
planset: 2026-07-16-kyc-autoverify; satisfies BIPA §15(a); counsel packet
relates: ADR-2026-07-01-biometric-bipa, ADR-2026-07-01-kyc-not-msb-retention-erasure, COMPLIANCE_MAPPING.md
---

# Citrate biometric data retention & destruction schedule

> **This is the §15(a) public policy text** (Illinois BIPA 740 ILCS 14/15(a) requires a
> *written, publicly available* retention schedule + destruction guidelines). It is a draft
> for legal review; once counsel confirms, **Part 1** publishes into the public
> data-handling terms (citrate-landing / dataroom). **Part 2** is the internal
> enforcement map (not public). Not legal advice.

---

## Part 1 — Public policy text (publish this)

**Effective date:** [CONFIRM on publication] · **Contact:** [CONFIRM: privacy@citrate.ai]

Citrate Inc. ("Citrate") collects a **face image** (a biometric identifier) when you
complete identity verification, solely to confirm you are a live person and that you match
your identity document. This policy states how long we keep biometric data and how we
destroy it.

**We retain biometric data for the shortest time necessary, and in every case destroy it
when the purpose is satisfied or within 3 years of your last interaction, whichever comes
first** (the BIPA ceiling). In practice we act far faster than that ceiling:

| Data | Retained for | Destroyed |
|---|---|---|
| **Your face image + any derived face template** (verification) | **Only as long as the identity match takes** — seconds | **Immediately upon completion of the match, and in all cases within 24 hours of capture.** We keep only the pass/fail decision, never the biometric. |
| **Your verification decision + identity record** (name, DOB, nationality — *not* biometric) | **Up to 12 months** | Permanently deleted after 12 months, unless a legal hold or an active account requires otherwise. |
| **Biometric data you separately consent to for model validation** (internal calibration program only) | The shorter of **12 months** or completion of that validation program | Permanently deleted at that deadline, or within 30 days of your withdrawal request. |

**How we destroy it.** Biometric data is encrypted; we destroy it by deleting the
ciphertext and its encryption key, rendering it permanently unrecoverable, and by
hard-deleting the record. Destruction is automatic and logged.

**We never sell, lease, trade, or profit from your biometric data, and never disclose it to
a third party** except as required by law. It is stored encrypted on United States
infrastructure and is never transferred outside the United States.

**Your rights.** You may request a copy of, or the deletion of, the personal data we hold
about you by contacting [CONFIRM: privacy@citrate.ai]; we honor deletion requests within
30 days. (Because your biometric is destroyed at the moment of verification, there is
normally no biometric left to return or delete after your session.)

---

## Part 2 — Internal enforcement map (do NOT publish; for audit/traceability)

Each public line above is enforced by code, not just policy:

| Public commitment | Enforced by |
|---|---|
| Face biometric destroyed immediately on match | `kyc-engine.ts:147` `runCase` → `store.destroyBiometricsForCase` (impl `kyc-cases-pg.ts:373`) — runs for every case regardless of decision |
| …and in all cases within 24 h of capture (backstop) | biometric evidence sealed with `destroyAfter = now + 24h` (`verify-routes.ts:183`); retention sweep wipes expired tier-2 ciphertext (`kyc-retention.ts`) |
| Only the decision is kept, never the biometric | manual review operates on decision + non-biometric evidence (`ADR-2026-07-01-biometric-bipa`); no template stored |
| Identity record deleted after 12 months | `retention_until = now + 365 days` (`kyc-engine.ts:154`); retention sweep hard-deletes tier-1 records past `retention_until` with no legal hold (`kyc-retention.ts`) |
| Calibration set ≤12 months / 30-day withdrawal | `CALIBRATION_CONSENT_DRAFT.md` §A.3, §A.7 (separate program) |
| Cryptographic destruction | per-case DEK + AES-256-GCM (`kyc-crypto.ts:38`); deleting ciphertext/key renders data unrecoverable |
| No sale / no third-party disclosure | BIPA §15(c)/(d) — no code path sells or exports biometrics; admin access allowlisted (`admin-kyc-routes.ts` `KYC_ADMIN_SUBS`) + dual-control |
| Deletion / DSAR within 30 days | `admin-kyc-routes.ts` `/admin/kyc/delete`, `/admin/kyc/dsar` |
| Legal-hold exception | retention sweep skips records under legal hold (`kyc-retention.ts`) |

**Open before publishing (counsel):** confirm the 12-month identity-record window and the
[bracketed] contact/effective-date; then publish Part 1 into the public data-handling terms
and check the §15(a) box in `COMPLIANCE_MAPPING.md` + `COUNSEL_REVIEW_PACKET.md`.
