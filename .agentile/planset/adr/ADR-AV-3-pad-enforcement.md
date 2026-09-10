---
created: 2026-07-17T00:00:00Z
branch: sprint/kyc-autoverify-av-s0-s1-2026-07-16
author: Larry Klosowski (@SaulBuilds) + Claude Opus 4.8
status: owner-approved — pending counsel co-sign
adr: AV-3
planset: 2026-07-16-kyc-autoverify (VERI-AV)
co-sign-required: outside counsel, a compliance lead (compliance)
---

# ADR-AV-3 — PAD (anti-spoofing) enforcement: when and with what

> Implements planset §3 ADR-AV-3 and the §5.2 exit criterion. Governs the flip of
> `KYC_PAD_ENFORCE` from `false` to `true`.

## Context

PAD is **advisory-off by default**. In `services/kyc-inference/inference.py:131-138`:

```python
pad_enforce = os.environ.get("KYC_PAD_ENFORCE", "false").strip().lower() in ("1","true","yes")
passed = bool(matched and (live or not pad_enforce))
```

So with the default, a confident 1:1 face match yields `pass: true` **even if the
anti-spoof model flags a spoof** — a printed photo, a screen replay, or a mask that
matches the ID portrait would pass liveness. The PAD model is OSS **Silent-Face
MiniFASNet** (`anti_spoof.onnx`), which is **not ISO 30107-3 certified**, and it does
**not** address injection / deepfake (virtual-camera) attacks at all — those are a
different threat class from physical presentation attacks. This is why enforcement is
off: an unvalidated model that false-rejects real selfies would block honest members.

Auto-verify (ADR-AV-1/AV-2 tier 1) is meaningless without enforced liveness: without
it, "the person is really here, live" is unproven and the >90% floor is not met.

## Decision (proposed 2026-07-17)

1. **Enforcement is a gated flip, not a default.** `KYC_PAD_ENFORCE=true` ships **only
   after** AV-S3 validation on a labeled attack set shows **APCER ≤ 5% at BPCER ≤ 3%**
   (ADR-AV-1) at the chosen `KYC_PAD_THRESHOLD`, with the `validate.py pad` report on
   file. Until then it stays `false` and every case stays in manual review (tier 2).

2. **OSS-first, certified-if-insufficient.** Validate MiniFASNet on the AV-S3 attack
   set first. If it cannot hit APCER ≤ 5% @ BPCER ≤ 3% across the attack types we
   accept (print, screen-replay, cutout/mask), **procure an ISO 30107-3 Level 1
   certified PAD** (Level 2 if we must cover higher-effort artefacts) and re-validate.
   The go-live PAD must carry either our own passing `validate.py` evidence or a vendor
   ISO 30107-3 certificate — no un-evidenced anti-spoof gates a paying member.

3. **Deepfake / injection is out of scope for tier-1 auto-verify at launch, and named
   as such.** MiniFASNet detects *presentation* attacks, not *injected* video. Until a
   certified injection-attack / virtual-camera defense is in place, deepfake-vector risk
   is a **known, logged residual** (planset §6) — auto-verify's liveness guarantee
   covers presentation attacks only, and public/compliance copy must not overstate it.
   A capture-integrity signal (attested camera / SDK) is the follow-up path.

4. **Optional active-liveness challenge** (blink / head-turn / random prompt) MAY be
   added as defense-in-depth. If added, challenge frames are **destroyed with the rest
   of the biometric immediately after the decision** (`ADR-2026-07-01-biometric-bipa`
   point 2) — no challenge media is retained.

5. **Enforced-spoof routing** follows ADR-AV-2: a high-confidence enforced spoof with a
   face present → tier 3 (`auto-reject`); an ambiguous or low-confidence spoof → tier 2
   (`review-band`). A red test proves an enforced spoof does **not** reach tier 1.

## Consequences

- Auto-verify cannot ship before this flip (it is exit criterion §5.2). AV-S3 blocks
  AV-S6's tier-1 path.
- The flip is one env var (`KYC_PAD_ENFORCE`) *plus* the calibrated `KYC_PAD_THRESHOLD`
  pinned in prod config with its validation report — both change together or neither.
- Choosing OSS-first keeps cost down but explicitly accepts that we may have to procure
  certified PAD; the budget/timeline owner is warned now, not at go-live.
- Naming the deepfake residual keeps the "server-blind, live-human" claim honest
  (planset §6, server-blindness/overstatement watch-item).

## Related

- ADR-AV-1 (APCER/BPCER targets), ADR-AV-2 (spoof → tier 3 vs tier 2),
  `ADR-2026-07-01-biometric-bipa` (destroy challenge media),
  `services/kyc-inference/inference.py:131-138`, `services/kyc-inference/validate.py`.
- Planset §5.2 exit criterion, §6 threshold-drift + server-blindness watch-items.
