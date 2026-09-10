---
created: 2026-07-17T02:30:00Z
branch: sprint/kyc-autoverify-av-s0-s1-2026-07-16
author: Larry Klosowski (@SaulBuilds) + Claude Opus 4.8
status: active-ledger
planset: 2026-07-16-kyc-autoverify (VERI-AV)
---

# VERI-AV deferrals ledger — explicitly deferred, NOT resolved

> Open decisions the owner **consciously deferred** on 2026-07-17. Recorded here so they
> are visible and cannot be quietly papered over. Each is a §5 exit-gate dependency: none
> of these being done means auto-verify does not go live. Review dates are hard prompts,
> not soft suggestions.

| # | Deferred item | Owner call (2026-07-17) | Blocks | Revisit | Status |
|---|---------------|--------------------------|--------|---------|--------|
| D-1 | **Inference host deploy** (AV-S1 WP-3) — stand up `services/kyc-inference` on a US host, set `KYC_INFERENCE_URL`/`KYC_INFERENCE_TOKEN` | Deferred to later; runbook is ready | AV-S1 completion, AV-S2 (can't validate without a running service), all downstream | Not date-boxed — flag stays until scheduled | ⏸ DEFERRED |
| D-2 | **KMS provider choice** (AV-S7 WP-2) — AWS KMS vs GCP KMS vs HSM, then wire the backend into boot | Deferred until **week of 2026-07-21** | AV-S7 completion, §5.6 exit criterion, full "server-blind" claim | **Week of 2026-07-21** | ⏸ DEFERRED |

## Why this file exists
The seam/scaffolding for both items is DONE (D-1: SHA-pinned models + runbook; D-2: the
fail-closed `MasterKeySource` seam + opt-in gate). Because the hard part is scaffolded,
it is easy to mistake "seam done" for "done." It is not: until D-1 deploys and D-2 wires
a real KMS, the engine stays in manual-review posture and "server-blind" stays only
partially true (planset §6). Do not close the AV-S1 or AV-S7 sprints while these are open.

## On close
When an item is executed, move its row to a `## Resolved` section below with the date and
the commit/deploy log reference, and update the owning sprint file.
