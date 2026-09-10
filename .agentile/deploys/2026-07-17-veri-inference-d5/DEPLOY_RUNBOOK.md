---
created: 2026-07-17T00:00:00Z
deployed: PENDING (operator action)
branch: sprint/kyc-autoverify-av-s0-s1-2026-07-16
author: Larry Klosowski (@SaulBuilds) + Claude Opus 4.8
status: runbook-ready
repo: citrate-identity
target: <US inference host> + auth.citrate.ai (identity service env)
planset: 2026-07-16-kyc-autoverify (AV-S1 / D5)
---

# Deploy runbook — VERI inference service (D5 / AV-S1)

> ⏸ **DEFERRED (owner, 2026-07-17) — deferral D-1 in `../../planset/DEFERRALS.md`.**
> The owner consciously deferred this deploy to later. It is **not done and not
> scheduled**. The runbook below is ready to execute, but until it runs, AV-S1 is
> incomplete and AV-S2 (accuracy validation) cannot proceed — there is no running service
> to validate. Do not let "runbook ready" read as "deployed."

> This is a **runbook**, not a completed deploy. An operator with the US host + secrets
> executes it. Standing this up makes a *machine decision possible*; it does **not**
> flip auto-verify on — the engine stays in advisor/manual-review mode until every
> planset §5 exit criterion is green (AV-S2..S9). See the AV-S1 sprint file.

## Preconditions
- A US-hosted VM/container host (ITAR/EAR posture: PII/biometric stays on US infra —
  `ADR-2026-07-01-biometric-bipa`, sanctions-screening data-residency ADR).
- A chosen anti-spoof (PAD) ONNX model + its download URL + SHA256.
- The `buffalo_l.zip` SHA256, pinned once from a trusted fetch (README "Pinning buffalo_l").
- A shared bearer token `KYC_INFERENCE_TOKEN` (generate: `openssl rand -hex 32`).

## Secrets / env — the exact set
| Var | Where | Purpose | Notes |
|---|---|---|---|
| `KYC_BUFFALO_L_SHA256` | inference build/fetch | pin buffalo_l.zip | REQUIRED — fetch aborts without it |
| `KYC_BUFFALO_L_URL` | inference (optional) | mirror override | defaults to upstream v0.7 release |
| `KYC_ANTISPOOF_URL` | inference build/fetch | anti-spoof .onnx source | REQUIRED |
| `KYC_ANTISPOOF_SHA256` | inference build/fetch | pin anti-spoof | REQUIRED (no longer optional) |
| `KYC_INFERENCE_TOKEN` | inference **and** identity | bearer auth (must match) | `openssl rand -hex 32` |
| `KYC_MODELS_DIR` | inference | model volume path | default `/models` |
| `KYC_MATCH_THRESHOLD` | inference | 1:1 match cutoff | PROVISIONAL 0.40 until AV-S2 calibrates |
| `KYC_PAD_THRESHOLD` | inference | PAD live-prob cutoff | PROVISIONAL 0.60 until AV-S3 calibrates |
| `KYC_PAD_ENFORCE` | inference | anti-spoof gates? | **leave `false`** until AV-S3 (ADR-AV-3) |
| `KYC_INFERENCE_URL` | **identity** service | points engine at the service | must be non-local HTTPS in prod (config TD-1) |

## Steps
```bash
# 1. Build the image
docker build -t veri-kyc-inference services/kyc-inference

# 2. Fetch + PIN models into a volume (fail-closed — refuses to run without the SHAs)
docker run --rm -v veri-models:/models \
  -e KYC_BUFFALO_L_SHA256="<pinned>" \
  -e KYC_ANTISPOOF_URL="<url>" -e KYC_ANTISPOOF_SHA256="<pinned>" \
  veri-kyc-inference bash download_models.sh
#    → writes /models/MODELS.lock

# 3. Run (boot verifies MODELS.lock before serving; a mismatch refuses to start)
docker run -d --name veri-infer -p 8000:8000 -v veri-models:/models \
  -e KYC_INFERENCE_TOKEN="<token>" \
  veri-kyc-inference

# 4. Functional smoke (on the host — this is the check an agent/sandbox CANNOT do)
curl -s localhost:8000/health          # → {"ok":true,...} only when models loaded
#    Then POST a known-good selfie+ID to /v1/liveness and a doc to /v1/document with the
#    bearer token; eyeball padScore/matchScore/tamperScore for sane values.

# 5. Point the identity service (auth.citrate.ai) at it, over HTTPS
#    KYC_INFERENCE_URL=https://<inference host>
#    KYC_INFERENCE_TOKEN=<same token as step 3>
#    Restart the identity service; config TD-1 rejects a local URL in prod.
```

## Verification (the AV-S1 Rule-11 gate — capture these as the run log)
- [ ] `GET /health` → 200 `{ok:true}` with models loaded.
- [ ] `verify_models.sh` logged "all N model file(s) verified against MODELS.lock" at boot.
- [ ] A seeded bona-fide staging case reaches engine `verified` (identity service log:
      `[kyc] engine decision for <case>: verified`) — the live counterpart of the CI
      proof in `test/kyc-inference-client.test.ts:124-155`.
- [ ] With `KYC_INFERENCE_URL` unset on a control run, the same case stays
      `needs-review` (fail-closed sanity).

## Rollback
Unset `KYC_INFERENCE_URL` on the identity service and restart → engine instantly reverts
to 100% manual review (fail-closed). No data migration. The inference container can be
stopped independently; in-flight cases stay `pending` → review.

## Do NOT, at this stage
- Do NOT set `KYC_PAD_ENFORCE=true` (that is AV-S3, gated on validated APCER — ADR-AV-3).
- Do NOT treat engine `verified` as an auto-grant. Until the §5 exit criteria are green,
  `verified` is a strong prior for a human approver, not an approval (planset §5, AV-S9).
