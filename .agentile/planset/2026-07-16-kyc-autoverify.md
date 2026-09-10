---
created: 2026-07-16
branch: docs/kyc-autoverify-planset-2026-07-16
author: Larry Klosowski (@SaulBuilds) + Claude Opus 4.8
status: proposed
planset: 2026-07-16-kyc-autoverify
program: VERI (Citrate in-house server-blind KYC/AML + liveness)
owners: SaulBuilds (engineering/security), a compliance lead (compliance evidence), outside counsel (proofing sign-off)
readiness_refs: HAR-048, HAR-244, HAR-258, HAR-139 (citrate-labs/reports/AUDIT_READINESS_2026-07-16)
---

# Planset — KYC Auto-Verify to Production Trust (VERI-AV)

> **One-line goal.** Take the in-house VERI verifier from "every case falls to manual
> review" to **confidence-tiered automated decisioning that is trustworthy enough to
> auto-approve a paying member**, with a *measured* accuracy + presentation-attack bar,
> enforced anti-spoofing, hardened key custody, and counsel + SOC 2 sign-off.

## 0. Launch decision this planset assumes (from the 2026-07-16 readiness review)

- **Launch now = manual-review KYC + counsel sign-off.** The money path can go live with
  every applicant cleared by a human admin (`/admin/kyc/*`), because the engine is already
  fail-closed and correct for that mode. Auto-verify is **not** a launch blocker.
- **Auto-verify = a fast-follow gated on this planset's exit criteria.** Turning the machine
  from "advisor to a human" into "the approver" is what AV-S0..S9 below earn.

This split is the answer to readiness decision #4. It de-risks revenue (manual review is
shippable) while making auto-verify a measured, reversible rollout rather than a leap.

## 1. Where we are today (code-grounded, 2026-07-16)

VERI is real and fail-closed. The gap to auto-verify is deployment + validation + hardening,
not a rewrite. Evidence (see `citrate-identity/src` and `services/kyc-inference`):

- **Decision engine is correct and lenient.** `kyc-engine.ts:163-184` (`decide`): with no
  model backend, or any negative signal (weak/failed match, failed PAD, unreadable/tampered
  doc, sanctions hit), the case returns `needs-review`. The engine **never auto-rejects**;
  `verified` requires a confident pass **and** clear screening **and** live models. Pinned by
  `kyc-engine.test.ts` ("FAIL-CLOSED: no model backend -> needs-review").
- **The D5 inference service exists but is not deployed.** `services/kyc-inference/`
  (`app.py`, `inference.py`) runs real ONNX: insightface SCRFD+ArcFace 1:1 face match,
  MiniFASNet PAD, passporteye MRZ, ELA tamper. Models are not fetched/pinned and
  `KYC_INFERENCE_URL` is unset, so `inferenceAnalyzersFromEnv` (`kyc-inference-client.ts:151`)
  returns `{}` and `decide` is hard-stuck at `needs-review` (100% manual).
- **Accuracy is unproven.** `services/kyc-inference/validate.py` (APCER/BPCER, FMR/FNMR) has
  never run; no labeled datasets ship; thresholds (`MATCH_THRESHOLD=0.40`, `PAD_THRESHOLD=0.60`,
  `tamperThreshold=0.5`) are uncalibrated defaults.
- **PAD is advisory-off by default.** `inference.py:131-138`: `KYC_PAD_ENFORCE=false` means a
  confident 1:1 match alone yields `pass:true` even if the anti-spoof model flags a spoof. The
  OSS PAD is not ISO 30107-3 certified; the tamper score is an ELA placeholder; no NFC ePassport.
- **Master key is a plain env var, not KMS/HSM.** `config.ts` requires `KYC_MASTER_KEY`;
  `kyc-crypto.ts:57` loads it raw. The server unwraps DEKs in the clear. The stronger O7 model
  (client-generated DEKs under an asymmetric KMS pubkey) is deferred (`inhouse.ts:242-254`).
  This is readiness item `HAR-244`.
- **Sanctions matching is name-only** (`kyc-screening.ts`, Sørensen–Dice; HIT 0.87 / REVIEW
  0.72), no DOB/secondary-identifier disambiguation, no dedicated PEP list; the embargo
  jurisdiction list is a default pending counsel (O4).
- **Manual-review surface is real.** `/admin/kyc/*` (`admin-kyc-routes.ts`, allowlisted by
  `KYC_ADMIN_SUBS`), dual-control unlock, hash-chained audit. Warns "DUAL-CONTROL DEGRADED" if
  fewer than 2 admins are provisioned (readiness item `HAR-139`).

## 2. The pathway in one picture

```
manual-review (today)
   -> AV-S0  define the assurance target + thresholds + decision matrix + counsel scope
   -> AV-S1  deploy D5 (models pinned, engine wired) so a machine decision exists at all
   -> AV-S2  measure accuracy on a holdout; calibrate thresholds to the AV-S0 bar
   -> AV-S3  validate + ENFORCE PAD (anti-spoof)
   -> AV-S4  strengthen document authenticity (tamper / NFC)
   -> AV-S5  sanctions/PEP precision + counsel-confirmed embargo list
   -> AV-S6  confidence-tiered decisioning (auto-verify / review-band / auto-reject)
   -> AV-S7  key custody to KMS/HSM (O7 / HAR-244)
   -> AV-S8  SHADOW mode -> canary % -> full, measuring real-world agreement
   -> AV-S9  compliance evidence + counsel go-live sign-off -> FLIP auto-verify ON
```

## 3. Locked decisions / ADRs to write at kickoff

- **ADR-AV-1 — Assurance target.** Map `BASIC_INDIVIDUAL` (`level-hints.ts`) to a concrete
  NIST 800-63A IAL-equivalent (document + biometric = IAL2-like) and state the target
  operating point: **max acceptable FMR (false match) and FNMR (false non-match)**, and **max
  acceptable APCER (attack presentation classification error)** at a fixed BPCER. Counsel co-signs.
- **ADR-AV-2 — Decision matrix.** Replace the current binary (`verified` | `needs-review`)
  with a **three-tier** policy: auto-verify (all signals above bar), review-band (any
  uncertainty), auto-reject (a clear, high-confidence fail such as a confirmed sanctions hit or
  enforced-PAD spoof). Fail-closed remains the default for anything unmeasured.
- **ADR-AV-3 — PAD enforcement.** When and how `KYC_PAD_ENFORCE=true` ships, and whether the
  OSS PAD is sufficient or a certified PAD (ISO 30107-3) must be procured.
- **ADR-AV-4 — Key custody (O7).** KMS/HSM for the master key and the client-generated-DEK
  model; the acceptable residual (does the server ever hold a DEK in the clear?).

## 4. Sprints + work packages

Each WP is red-test-first where it touches `decide`/engine code (Rule: test count never
decreases). Every acceptance criterion names the data source that proves it (Rule 11).

| Sprint | Goal | Key WPs | Rule-11 acceptance (data source) |
|---|---|---|---|
| **AV-S0** Assurance target + policy | Decide the bar before building to it | ADR-AV-1..4; embargo-list counsel scope (O4); counsel engagement letter on in-house proofing (D8) | ADRs committed with FMR/FNMR/APCER targets; counsel scope email/letter on file (`HAR-258`); decision matrix table in this planset |
| **AV-S1** Deploy D5 | A machine decision exists | Stand up `services/kyc-inference` on US host; `download_models.sh` fetch + **SHA-pin** models; set `KYC_INFERENCE_URL`/`KYC_INFERENCE_TOKEN`; wire `buildVerificationEngine` in prod boot | Staging capture runs end-to-end; `GET /health` 200 with models loaded; a seeded bona-fide case reaches engine `verified` (not stuck `needs-review`) in a staging run log |
| **AV-S2** Accuracy validation (the S6 gate) | Prove it before trusting it | Assemble labeled bona-fide + attack datasets; run `validate.py`; produce DET curves; calibrate `MATCH_THRESHOLD`/`PAD_THRESHOLD`/`tamperThreshold` to the AV-S0 bar; pin thresholds in config | `validate.py` report shows FMR/FNMR + APCER/BPCER on a **holdout** at or below ADR-AV-1 targets; thresholds committed to config with the report as evidence |
| **AV-S3** PAD hardening | Stop presentation/deepfake attacks | Validate anti-spoof on an attack set; procure certified PAD if OSS insufficient (ADR-AV-3); set `KYC_PAD_ENFORCE=true`; optional active-liveness challenge | APCER at the chosen threshold below target on the attack dataset; `KYC_PAD_ENFORCE=true` in prod config; test proves an enforced-spoof routes to reject/review per matrix |
| **AV-S4** Document authenticity | Non-MRZ IDs are the weak spot | Replace ELA placeholder with a real tamper model and/or NFC ePassport read; strengthen driver-license handling | Tamper detection measured on a labeled genuine/forged set; authenticity signal above bar for the target document mix; result table committed |
| **AV-S5** Sanctions/PEP precision | Reduce false-hits + missed hits | DOB/secondary-identifier disambiguation; dedicated PEP list; counsel-confirmed embargo list (O4) | Screening precision/recall on a labeled name set below the agreed false-hit rate; embargo list carries a counsel sign-off note (`kyc-screening.ts`) |
| **AV-S6** Tiered decisioning | Turn the advisor into the approver | Extend `decide` (`kyc-engine.ts`) to the ADR-AV-2 three-tier matrix (red tests first); keep fail-closed for unmeasured paths; projected manual-queue rate | New `decide` tests cover auto-verify / review-band / auto-reject cases; mutation-tested; projected auto-vs-manual split reported from a replay over AV-S2 data |
| **AV-S7** Key custody (O7 / HAR-244) | Close the server-blindness gap | Master key from KMS/HSM (fail-closed if unreachable); client-generated DEKs wrapped under an asymmetric KMS pubkey per `inhouse.ts:242-254` | `KYC_MASTER_KEY`-from-env path removed or gated to dev; prod sources key from KMS; test proves boot fails closed when KMS is unreachable |
| **AV-S8** Shadow -> canary -> full | Measure real-world agreement before trusting it | Shadow mode (engine decides, human still confirms) logging agreement; then canary % auto-verify; then full; **kill-switch** env flag | Shadow-mode machine-vs-human agreement over N real cases at or above the ADR-AV-1 target; canary error rate within bound; kill-switch flips auto-verify off in one env change |
| **AV-S9** Compliance evidence + go-live | Make it defensible + flip it on | Identity-proofing procedure doc; IAL/AAL assertion; PII retention + DPIA; SOC 2 operating evidence; **counsel go-live sign-off (D8, `HAR-258`)**; ensure >=2 admins in `KYC_ADMIN_SUBS` (`HAR-139`) | Procedure + assertion + DPIA committed; counsel go-live sign-off on file; dual-control non-degraded; **exit gate (below) all green -> auto-verify enabled in prod** |

## 5. Exit criteria — the "trustworthy" bar (all must hold to flip auto-verify ON)

1. **Measured accuracy** on a holdout at or below the ADR-AV-1 FMR/FNMR + APCER/BPCER targets
   (AV-S2), with the report on file.
2. **PAD enforced** (`KYC_PAD_ENFORCE=true`) and validated below the APCER target (AV-S3).
3. **Document authenticity** measured and above bar for the launch document mix (AV-S4).
4. **Sanctions/PEP** precision/recall within bounds; embargo list counsel-signed (AV-S5).
5. **Tiered decisioning** implemented, mutation-tested, fail-closed for unmeasured paths (AV-S6).
6. **Key custody** in KMS/HSM; no plaintext master key in prod (AV-S7 / `HAR-244`).
7. **Shadow-mode agreement** at or above target over a real sample; canary clean; kill-switch
   present (AV-S8).
8. **Counsel go-live sign-off** (D8 / `HAR-258`) + SOC 2 operating evidence + dual-control
   admin non-degraded (`HAR-139`) (AV-S9).

Until all eight hold, the engine stays in advisor mode (manual review), which is the launch
posture and is already correct.

## 6. Risks / watch-items

- **Dataset provenance.** Attack/bona-fide datasets carry their own PII + licensing +
  export-control considerations; source them with counsel (ties to ITAR/EAR posture).
- **Threshold drift.** Model/threshold changes must re-earn the AV-S2 evidence; pin and
  version thresholds with the validation report that justified them.
- **Lenient-policy inertia.** The current engine never auto-rejects; AV-S6 introduces
  auto-reject, which is a higher-stakes change than auto-verify (a wrong reject harms a real
  member). Red tests + shadow mode gate it.
- **Server-blindness claim.** Until AV-S7, the "server-blind" description is only partially
  true (the server holds the master key). Keep public/compliance copy honest until O7 lands.

## 7. Pointers

- Code: `citrate-identity/src/kyc-engine.ts`, `kyc-inference-client.ts`,
  `kyc-providers/inhouse.ts`, `kyc-crypto.ts`, `kyc-screening.ts`, `kyc-cases-pg.ts`,
  `admin-kyc-routes.ts`, `config.ts`; model service `services/kyc-inference/`.
- Existing VERI design IDs referenced in code: S3 (engine), S5 (a third-party KYC vendor scrub), S6 (validation
  gate), O4 (embargo counsel), O7 (KMS), D3 (data tiers), D8 (go-live counsel).
- Readiness register: `HAR-048` (D5 not deployed), `HAR-244` (master key not KMS),
  `HAR-258` (counsel go-live), `HAR-139` (dual-control admin) in
  `citrate-labs/reports/AUDIT_READINESS_2026-07-16/`.

## 8. For the picking-up agent

Start at **AV-S0** (write the four ADRs; you cannot calibrate to a bar that is not yet
decided). Then **AV-S1** (deploy D5) is the single highest-leverage unblock. Create a sprint
file per sprint under `.agentile/sprints/active/` at each kickoff, red-test-first for any
change to `decide`. Do not enable auto-verify in prod until every §5 exit criterion is green;
manual review is the correct posture until then.
