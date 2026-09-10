---
created: 2026-07-17T00:15:00Z
branch: sprint/kyc-autoverify-av-s0-s1-2026-07-16
author: Larry Klosowski (@SaulBuilds) + Claude Opus 4.8
sprint: AV-S0 / AV-S1 / AV-S2
status: session-journal
---

# Journal — KYC auto-verify kickoff (AV-S0 → AV-S1 → AV-S2 scaffold)

## What this session did
Executed the `2026-07-16-kyc-autoverify` planset from the top: wrote the four ADRs
(AV-S0), closed the model supply-chain hole and produced the deploy runbook (AV-S1),
and scaffolded the accuracy-validation harness + dataset checklist (AV-S2). Suite went
443 → 447, green.

## The non-obvious things (worth remembering)

1. **"90% certainty" is a *low* bar for identity matching, not a high one.** The owner
   framed the requirement as ">90% the person and ID are real." Taken literally that's
   FMR ~10% — one impostor in ten auto-approved. Encoded it as a *floor* and anchored
   the real target to NIST 800-63A **IAL2** with **FMR ≤ 1e-4** (ADR-AV-1). The AND of
   match + PAD + doc + screening yields >99% joint certainty. The lesson: translate a
   human confidence number into the standard's operating point; don't pin a threshold
   at the number.

2. **The planset's AV-S1 "wire buildVerificationEngine in prod boot" was already done.**
   `verify-routes.ts:197` already builds the engine with real analyzers when
   `KYC_INFERENCE_URL` is set, and the E2E "bona-fide → verified" proof already lives in
   `test/kyc-inference-client.test.ts:124-155`. Verified it instead of rewriting it
   (Rule 9). The *actual* AV-S1 gap was elsewhere.

3. **The real AV-S1 hole was model integrity.** `buffalo_l` was auto-downloaded by
   insightface with **no hash check**, and the anti-spoof SHA was optional
   (warn-and-continue). Rewrote `download_models.sh` to REQUIRE every SHA (fail-closed),
   added `verify_models.sh` as a boot-time gate wired into the Dockerfile, and pinned
   the behavior with 4 CI tests that run the real shell script. A supply-chain
   substitution now cannot serve.

4. **citrate-memories MCP was down, and saying so mattered.** It's configured but the
   `mcp_connect` binary wasn't built (stale socket, intact data). Built the binary
   (restores on next restart) but did not pretend the MCP was live — worked on
   file-memory as the owner chose. Confirm dependencies by probing, not by assuming.

## Honest state at session end
- ADRs are `proposed`, not `accepted` — they need owner number-review + counsel co-sign
  (D8 / HAR-258). That is the correct status, not a gap.
- Auto-verify is NOT on and must not be: thresholds are provisional, PAD is advisory-off,
  no holdout has been measured, key custody is still env-var. The engine remains in the
  correct manual-review posture. AV-S1 made a machine decision *possible*; AV-S2..S9 are
  what make it *trustworthy*.
- Blocked-on-external: host deploy (secrets), datasets (procurement + export review),
  counsel sign-off, KMS (AV-S7). All flagged in their sprint files, none silently
  skipped.

## Next agent starts here
Owner reviews the ADR-AV-1 numbers → counsel co-signs → run the AV-S1 deploy runbook on
the US host → procure datasets per `calibration/DATASETS.md` → AV-S2 `validate.py` on a
holdout. Do not promote any threshold or flip auto-verify until the planset §5 gate is
all-green.
