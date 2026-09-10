---
created: 2026-07-17T01:30:00Z
branch: sprint/kyc-autoverify-av-s0-s1-2026-07-16
author: Larry Klosowski (@SaulBuilds) + Claude Opus 4.8
sprint: AV-S5 / AV-S6
status: session-journal
---

# Journal — AV-S5 sanctions precision + AV-S6 tiered decisioning

## What this session did
Two red-green engine-hardening sprints, both fully autonomous (no datasets needed):
AV-S5 added DOB secondary-identifier disambiguation to the sanctions matcher; AV-S6
implemented the ADR-AV-2 three-tier `decide`. Suite 447 → 457, green, typecheck clean.

## The non-obvious things

1. **AV-S5 unblocks AV-S6.** The screener accepted `dob` but never used it. Making it
   suppress a DOB-conflicting name match (fewer false hits) AND expose a `corroboration`
   field is what lets AV-S6's auto-reject fire *only* on a corroborated hit. The two
   sprints are a dependency chain, not independent — doing S5 first made S6's tier-3
   condition a one-liner (`result === 'hit' && corroboration === 'dob-match'`).

2. **Auto-reject had to ship OFF.** The planset is explicit: auto-reject is the highest-
   stakes change (a wrong reject harms a real member) and must be gated behind shadow
   mode (AV-S8), shipping *after* auto-verify proves itself. So AV-S6 implements the full
   matrix but gates the reject path behind `KYC_AUTO_REJECT_ENABLE` (default off → falls
   through to needs-review, the existing lenient behavior). Default behavior is
   byte-identical to before; the new path is red-tested but dormant. This is the honest
   way to "introduce" a behavior without "trusting" it yet.

3. **Tier-1 auto-verify was deliberately NOT expanded.** ADR-AV-2 tightens tier-1 with
   *calibrated* thresholds — which don't exist until AV-S2/S3/S4 (blocked on datasets).
   Fail-closed-on-unmeasured means tier-1 stays exactly as strict as today. Expanding it
   now, with uncalibrated thresholds, would be the exact leap the planset forbids.

4. **A security gate needs its env wiring tested.** Added an E2E test that
   `KYC_AUTO_REJECT_ENABLE` actually flows through `buildVerificationEngine` — a typo in
   the var name would silently disable the gate. It fails safe (off), but "silently off"
   is still a bug worth a test.

## Honest state
- AV-S5, AV-S6 engineering done + green. Auto-reject is implemented but OFF by default;
  it only becomes live when a corroborated-hit decision is validated in AV-S8 shadow mode
  and someone sets the flag. Tier-1 auto-verify unchanged (still deployment-gated by
  `KYC_INFERENCE_URL`).
- Still blocked-on-external: AV-S2/S3/S4 (datasets), AV-S1 host deploy (secrets), AV-S7
  KMS (cloud creds), AV-S8 shadow traffic, AV-S9 counsel sign-off. The autonomous engine
  hardening surface is now essentially exhausted for this session.

## Next agent
Owner + counsel review the ADRs → deploy inference (AV-S1 WP-3) → procure datasets →
AV-S2/S3/S4 calibrate → AV-S8 shadow mode measures agreement AND the auto-reject
decisions before `KYC_AUTO_REJECT_ENABLE` is ever set true in prod.
