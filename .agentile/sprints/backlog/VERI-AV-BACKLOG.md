---
created: 2026-07-19T00:00:00Z
branch: sprint/kyc-autoverify-close-backlog-2026-07-19
author: Larry Klosowski (@SaulBuilds) + Claude Opus 4.8
status: active-backlog
planset: 2026-07-16-kyc-autoverify (VERI-AV)
register: AUDIT_READINESS register (HAR-048, HAR-244, HAR-258, HAR-139)
---

# VERI Auto-Verify — remaining-work backlog (session close 2026-07-19)

> Everything still standing between today and auto-verify going live. The engine hardening
> is essentially complete; what remains is **externally gated** (deploy, datasets, KMS
> provider, counsel, real traffic) — captured here so nothing is lost. Sync'd to the
> readiness register's HAR items. **Nothing is live**: auto-verify OFF (deployment-gated),
> auto-reject OFF (flag-gated), KMS gate OFF (env-key path unchanged).

## Done this program (merged to main)
AV-S0 ADRs · AV-S1 model-pinning + deploy runbook · AV-S2 scaffolding + turnkey doc-staging ·
AV-S5 sanctions DOB precision · AV-S6 three-tier decide (auto-reject gated off) · AV-S7 KMS
seam · consent form + compliance map + §15(a) retention schedule (all drafted for counsel).
Test baseline 443 → 465.

## Remaining backlog

| ID | Item | Blocked on | HAR / ref | Effort |
|----|------|-----------|-----------|--------|
| AV-BL-1 | **Deploy the inference service** (AV-S1 WP-3) on US host; set `KYC_INFERENCE_URL`/`_TOKEN` | host + secrets (**DEFERRAL D-1**) | HAR-048 | M |
| AV-BL-2 | **Stage doc datasets + run `validate.py`** for AV-S4 (public doc-dataset staging is turnkey) | run on host w/ disk | HAR-048 | M |
| AV-BL-3 | **Procure PAD/attack + selfie↔ID data**; in-house capture for FMR ≤ 1e-4 | counsel consent read before live capture; research-set US-person-only | HAR-048 | L |
| AV-BL-4 | **AV-S2 accuracy validation** — DET curves, calibrate `MATCH`/`PAD`/`tamper` thresholds to ADR-AV-1 | AV-BL-2/3 data | HAR-048 | L |
| AV-BL-5 | **AV-S3 PAD enforcement** — validate APCER, procure certified PAD if OSS insufficient, flip `KYC_PAD_ENFORCE=true` | PAD-cert lab pricing; attack data | HAR-048 | M |
| AV-BL-6 | **AV-S6 WP-2** — tier-1 auto-verify tightening to calibrated thresholds + projected queue-split replay | AV-BL-4 | — | M |
| AV-BL-7 | **AV-S7 WP-2** — concrete AWS/GCP KMS backend, wire into `inhouse.ts` boot, staging-verify, flip `KYC_MASTER_KEY_SOURCE=kms`+`KYC_REQUIRE_KMS` | KMS provider choice (**DEFERRAL D-2**) | HAR-244 | L |
| AV-BL-8 | **AV-S5 WP-2** — dedicated PEP list (separate from OFAC SDN) | PEP data feed | — | M |
| AV-BL-9 | **AV-S8 shadow → canary → full** — measure machine-vs-human agreement; validate auto-reject before flipping the flag; kill-switch | AV-BL-1 deploy + real traffic | — | L |
| AV-BL-10 | **Counsel sign-off** — packet asks (IAL2, decision matrix, PAD, KMS, embargo O4, engagement, consent, research-license/ITAR) | outside counsel | HAR-258 | L |
| AV-BL-11 | **Publish §15(a) retention schedule** (drafted) into public data-handling terms | counsel confirm | HAR-258 | S |
| AV-BL-12 | **Provision ≥2 KYC admins** (`KYC_ADMIN_SUBS`) — clear DUAL-CONTROL DEGRADED | the system owner | HAR-139 | S |
| AV-BL-13 | **SOC 2 operating evidence** for the in-house KYC control (identity-proofing procedure + IAL/AAL assertion) | a 3PAO engagement | HAR-258 | M |
| AV-BL-14 | **Send ISO 30107-3 PAD-cert lab outreach** (drafted) → resolve PAD cert cost + attack-corpus licensing | owner sends | — | S |
| AV-BL-15 | **Reconcile/retire legacy KYC-vendor references** (district-registration, HAR-204; in-house stub HAR-049) | owner/counsel | HAR-204/049 | M |

## Budget

A separate incremental budget line covers VERI Auto-Verify through third-party
audit — ISO 30107-3 PAD certification + attack-corpus licensing (AV-BL-5/14), the
in-house capture program (AV-BL-3), KYC-specific counsel sign-offs (AV-BL-10), and
the KYC slice of the SOC 2 3PAO operating-evidence prep (AV-BL-13). Figures are
tracked separately from this engineering backlog and confirmed against vendor and
counsel replies.

## Exit
Auto-verify flips ON only when all eight planset §5 exit criteria are green (measured
accuracy, PAD enforced, doc authenticity, sanctions precision, tiered decisioning,
KMS custody, shadow-mode agreement, counsel sign-off). Until then, manual review is the
correct and shippable posture.
