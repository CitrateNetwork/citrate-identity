---
created: 2026-07-17T00:00:00Z
branch: sprint/kyc-autoverify-av-s0-s1-2026-07-16
author: Larry Klosowski (@SaulBuilds) + Claude Opus 4.8
sprint: AV-S1
status: active
---

# Sprint AV-S1: Deploy D5 (a machine decision exists at all)

## Sprint Metadata

| Field | Value |
|-------|-------|
| **Sprint ID** | `AV-S1` |
| **Sprint Name** | Stand up the inference service, pinned + fail-closed, so the engine can decide |
| **Goal** | Make a machine decision *possible* — inference wiring proven E2E, models fetched under REQUIRED SHA pins with a boot-time integrity gate, and a deploy runbook the host operator can execute. |
| **Branch** | `sprint/kyc-autoverify-av-s0-s1-2026-07-16` |
| **Start Date** | 2026-07-17 |
| **End Date (target)** | 2026-07-17 (engineering); host deploy is an operator action |
| **Status** | `IN PROGRESS` |
| **Planset** | `.agentile/planset/2026-07-16-kyc-autoverify.md` (AV-S1 row) |
| **Predecessors** | AV-S0 (ADRs), VERI in-house KYC (shipped) |

## Why this sprint

`decide` is hard-stuck at `needs-review` (100% manual) because `KYC_INFERENCE_URL` is
unset and the model service is not deployed (planset §1, `HAR-048`). AV-S1 is the
single highest-leverage unblock (planset §8): once the service is up and pointed at,
the engine produces a real decision. The wiring itself is already correct and
CI-proven; the missing pieces are **model integrity** and the **host deploy**.

## Deliverables

- `services/kyc-inference/download_models.sh` — rewritten: ALL models SHA-pinned,
  REQUIRED (fail-closed), writes `MODELS.lock`.
- `services/kyc-inference/verify_models.sh` — NEW boot-time integrity gate (fail-closed).
- `services/kyc-inference/Dockerfile` — entrypoint verifies `MODELS.lock` before uvicorn.
- `test/kyc-inference-models-pin.test.ts` — NEW, 4 tests pinning the fail-closed gate.
- `services/kyc-inference/README.md` — updated pinning + `buffalo_l` hash instructions.
- `.agentile/deploys/2026-07-17-veri-inference-d5/DEPLOY_RUNBOOK.md` — operator steps + env.

## Test Baseline (start of sprint)

| Metric | Count | Captured | Canonical command |
|--------|-------|----------|-------------------|
| **Tests** | 443 → **447** passed (58 files) | 2026-07-17 | `npm test` (vitest run) |
| **Formal specs** | 0 | 2026-07-17 | n/a |
| **CI tripwires** | `.semgrep/` | 2026-07-17 | `ls .semgrep/` |
| **Frontmatter coverage** | all `.agentile/` docs | 2026-07-17 | Rule-12 |

Rule 2: +4 tests (443 → 447), suite green. No test removed.

## Method

WP-1 (model gate) touches shell/Docker, not `decide` — its "red test" is the CI test
that the gate rejects a mismatch (`kyc-inference-models-pin.test.ts`), written and made
to pass against the real script. WP-2 (E2E proof) already exists — verified, not
rewritten (Rule 9). WP-3 (deploy) is an operator runbook, not agent-executable.

## Work Packages

### WP-1: Model SHA-pinning + fail-closed boot verification

| Field | Value |
|-------|-------|
| **Status** | `[x] COMPLETE` |
| **Order step** | red test → code |
| **Estimated effort** | M |
| **Commit(s)** | — (uncommitted; awaiting owner review) |

**Scope:** Close the supply-chain hole where `buffalo_l` was auto-fetched with no
integrity check and the anti-spoof SHA was optional (warn-and-continue). Make every
model hash REQUIRED at fetch and RE-VERIFIED at boot. Does NOT change the models or the
inference logic.

**Acceptance Criteria** *(Rule 11 — data source named)*
- [x] `download_models.sh` aborts if `KYC_BUFFALO_L_SHA256` or `KYC_ANTISPOOF_SHA256`
      is unset, and on any hash mismatch (`set -euo pipefail` + `require_sha`); verified
      by `bash -n` syntax check and code review of the `:?`-guards.
- [x] `verify_models.sh` exits non-zero on missing lock / missing file / hash mismatch,
      proven by `test/kyc-inference-models-pin.test.ts` (4 tests, run against the real
      script in a temp `$KYC_MODELS_DIR`).
- [x] `Dockerfile` CMD runs `verify_models.sh && exec uvicorn …` — service cannot serve
      against unverified weights.

**Tests added:**
- `verify_models.sh — exits 0 when every file matches MODELS.lock`
- `FAIL-CLOSED: non-zero on hash mismatch (tampered weights)`
- `FAIL-CLOSED: non-zero when MODELS.lock is absent`
- `FAIL-CLOSED: non-zero when a locked file is missing from the volume`

---

### WP-2: E2E wiring proof (a bona-fide case reaches `verified`)

| Field | Value |
|-------|-------|
| **Status** | `[x] COMPLETE` (pre-existing — verified, not rewritten) |
| **Order step** | verification |
| **Estimated effort** | S |
| **Commit(s)** | pre-existing in `test/kyc-inference-client.test.ts` |

**Scope:** The planset's AV-S1 Rule-11 acceptance ("a seeded bona-fide case reaches
engine `verified`, not stuck `needs-review`") — confirm it is already proven in CI so
we do not duplicate it (Rule 9).

**Acceptance Criteria**
- [x] `test/kyc-inference-client.test.ts:124-155` ("buildVerificationEngine — THE
      WIRING") proves a seeded bona-fide case → `verified` end-to-end via
      `buildVerificationEngine` against a test HTTP inference server, AND fail-closes to
      `needs-review` when `KYC_INFERENCE_URL` is unset. Runs green in `npm test`.

**Tests added:** none (Rule 9 — the proof already exists).

---

### WP-3: Host deploy + runbook (operator action)

| Field | Value |
|-------|-------|
| **Status** | `[!] BLOCKED / ⏸ DEFERRED` (owner deferred the deploy 2026-07-17 — deferral D-1 in `../../../planset/DEFERRALS.md`) |
| **Order step** | code → deploy |
| **Estimated effort** | M |
| **Commit(s)** | runbook committed; execution DEFERRED by owner (not scheduled) |

**Scope:** Actually stand up `services/kyc-inference` on the US host, run
`download_models.sh` with pinned hashes, set `KYC_INFERENCE_URL`/`KYC_INFERENCE_TOKEN`
on the identity service, and capture the staging `/health` 200 + a bona-fide staging
run reaching `verified`. Requires infra + secrets an agent must not hold.

**Acceptance Criteria** *(the planset's Rule-11 gate — earned on the host)*
- [ ] `GET /health` → 200 `{ok:true}` with models loaded (staging run log).
- [ ] A seeded bona-fide staging case reaches engine `verified` on the deployed host
      (staging run log) — the live counterpart of WP-2's CI proof.
- [x] Runbook with exact env + pinning steps exists
      (`.agentile/deploys/2026-07-17-veri-inference-d5/DEPLOY_RUNBOOK.md`).

**Tests added:** none (deploy verification is a run log, not a unit test).

## Dependencies

| Dependency | Status | Impact if blocked |
|------------|--------|-------------------|
| US inference host + secrets (`KYC_INFERENCE_TOKEN`, model URLs/hashes) | Blocked (operator) | WP-3 execution; WP-1/WP-2 done without it |
| Chosen anti-spoof model + its pinned SHA | Open | WP-3; also feeds AV-S3 PAD validation |

## Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| `buffalo_l.zip` layout differs from assumed (nested dir) | Low | Med | README documents expected layout; functional smoke on host catches it before serve |
| Operator skips SHA pinning under time pressure | Med | High | Script is fail-closed — it *cannot* run without the pins; no bypass path |
| Deployed thresholds mistaken for validated | Med | High | Thresholds remain PROVISIONAL until AV-S2; engine stays advisory (manual review) until §5 gate |

## Notes

Engineering portion complete: the model supply-chain is now fail-closed at fetch AND
boot, proven by 4 CI tests, suite green at 447. The remaining work (WP-3) is a host
deploy an operator must run with real secrets — the runbook makes it turnkey. Deploying
the service does NOT flip auto-verify on: the engine stays in advisor/manual-review mode
until the AV-S2..S9 §5 exit criteria are green. AV-S1 only makes a machine decision
*exist*; AV-S2 is what makes it *trustworthy*.
