---
created: 2026-07-17T00:00:00Z
branch: sprint/kyc-autoverify-av-s0-s1-2026-07-16
author: Larry Klosowski (@SaulBuilds) + Claude Opus 4.8
sprint: AV-S0
status: active
---

# Sprint AV-S0: Assurance target + policy

## Sprint Metadata

| Field | Value |
|-------|-------|
| **Sprint ID** | `AV-S0` |
| **Sprint Name** | Decide the auto-verify bar before building to it |
| **Goal** | Lock the four ADRs (assurance target, decision matrix, PAD enforcement, key custody) so every downstream sprint has a concrete, standard-anchored bar to calibrate to. |
| **Branch** | `sprint/kyc-autoverify-av-s0-s1-2026-07-16` |
| **Start Date** | 2026-07-17 |
| **End Date (target)** | 2026-07-17 (engineering portion); counsel co-sign trails |
| **Status** | `IN PROGRESS` |
| **Planset** | `.agentile/planset/2026-07-16-kyc-autoverify.md` |
| **Predecessors** | VERI in-house KYC (shipped, fail-closed, manual-review launch posture) |

## Why this sprint

You cannot calibrate to a bar that has not been decided (planset §8). The engine is
already fail-closed and correct for manual review; AV-S0 writes down the *quantitative*
meaning of "trustworthy enough to auto-approve a paying member" — the owner's ">90%
certainty, treated as a floor, targeting IAL2-grade" — so AV-S2/S3/S4/S5 have a pass/fail
gate and AV-S6 has thresholds to implement. This is pure decision work; no engine code
changes here.

## Deliverables

- `.agentile/planset/adr/ADR-AV-1-assurance-target.md` — IAL2 target, FMR/FNMR/APCER/BPCER bar
- `.agentile/planset/adr/ADR-AV-2-decision-matrix.md` — three-tier auto-verify/review/auto-reject
- `.agentile/planset/adr/ADR-AV-3-pad-enforcement.md` — when/with-what `KYC_PAD_ENFORCE=true`
- `.agentile/planset/adr/ADR-AV-4-key-custody.md` — KMS/HSM master key + client-DEK end-state
- Counsel scope items (O4 embargo list, D8 proofing engagement) — **tracked, external**

## Test Baseline (start of sprint)

| Metric | Count | Captured | Canonical command |
|--------|-------|----------|-------------------|
| **Tests** | 443 passed (57 files) | 2026-07-17, branch tip | `npm test` (vitest run) |
| **Formal specs** | 0 (none in repo) | 2026-07-17 | n/a |
| **CI tripwires** | see `.semgrep/` | 2026-07-17 | `ls .semgrep/` |
| **Frontmatter coverage** | all `.agentile/` docs | 2026-07-17 | Rule-12 frontmatter present |

AV-S0 changes no source and no tests → baseline unchanged (Rule 2 holds trivially: 443 ≥ 443).

## Method

AV-S0 is decision/ADR work — no TLA+, no red-test (no engine code touched). The method
here is: ground each ADR in exact code (Rule 0/Rule 7), anchor targets to a recognized
standard (NIST 800-63A/B, ISO 30107-3), name counsel co-sign, and leave the numbers
`proposed` until AV-S2/S3/S4 earn them and counsel signs.

## Work Packages

### WP-1: ADR-AV-1 — Assurance target

| Field | Value |
|-------|-------|
| **Status** | `[x] COMPLETE` |
| **Order step** | Decision |
| **Estimated effort** | S |
| **Commit(s)** | — (uncommitted; awaiting owner review) |

**Scope:** Encode the owner's ">90% floor → IAL2-grade" into concrete FMR/FNMR/APCER/BPCER
targets and the joint ">99% certainty at auto-verify" interpretation. Does NOT measure
anything — sets the bar AV-S2/S3/S4 calibrate to.

**Acceptance Criteria** *(Rule 11 — data source named)*

- [x] ADR maps `BASIC_INDIVIDUAL` (`src/kyc-providers/level-hints.ts:16-39`) to NIST
      800-63A IAL2-equivalent with FMR ≤ 1e-4, FNMR ≤ 5%, APCER ≤ 5% @ BPCER ≤ 3%.
- [x] "90% floor" retained as a hard minimum; target stated as >99% joint certainty.
- [ ] **Counsel co-signs the IAL2 assertion + numbers** (D8 / `HAR-258`) — EXTERNAL, open.

**Tests added:** none (decision doc).

---

### WP-2: ADR-AV-2 — Three-tier decision matrix

| Field | Value |
|-------|-------|
| **Status** | `[x] COMPLETE` |
| **Order step** | Decision |
| **Estimated effort** | S |
| **Commit(s)** | — |

**Scope:** Replace the binary outcome with auto-verify / review-band / auto-reject,
fail-closed default, bounded high-confidence auto-reject. Implementation is AV-S6, not here.

**Acceptance Criteria**
- [x] Matrix defined against `src/kyc-engine.ts:163-184`; confirms the `'rejected'` type
      already exists (no signature change; policy + thresholds + red tests in AV-S6).
- [x] Auto-reject bounded to corroborated sanctions hit or high-confidence enforced-PAD spoof.

**Tests added:** none (implementation red-tests land in AV-S6).

---

### WP-3: ADR-AV-3 — PAD enforcement

| Field | Value |
|-------|-------|
| **Status** | `[x] COMPLETE` |
| **Order step** | Decision |
| **Estimated effort** | S |
| **Commit(s)** | — |

**Scope:** Govern the `KYC_PAD_ENFORCE=false → true` flip; OSS-first then certified-if-
insufficient; name the deepfake/injection residual.

**Acceptance Criteria**
- [x] ADR ties the flip to AV-S3 `validate.py pad` evidence (APCER ≤ 5% @ BPCER ≤ 3%),
      grounded in `services/kyc-inference/inference.py:131-138`.
- [x] Deepfake/injection named as an out-of-scope, logged residual (honesty gate).

**Tests added:** none.

---

### WP-4: ADR-AV-4 — Key custody (O7 / HAR-244)

| Field | Value |
|-------|-------|
| **Status** | `[x] COMPLETE` |
| **Order step** | Decision |
| **Estimated effort** | S |
| **Commit(s)** | — |

**Scope:** KMS/HSM master key (fail-closed) as the go-live gate; client-generated DEK as
the end-state; copy honesty until then.

**Acceptance Criteria**
- [x] ADR grounded in `src/kyc-crypto.ts:57` + `inhouse.ts:242-254`; Step 1 (KMS) is the
      §5.6 gate, Step 2 (client DEK) the end-state; residual stated honestly.

**Tests added:** none.

---

### WP-5: Counsel scope (O4 embargo list + D8 proofing engagement)

| Field | Value |
|-------|-------|
| **Status** | `[!] BLOCKED` (external — outside counsel) |
| **Order step** | Decision |
| **Estimated effort** | M |
| **Commit(s)** | — |

**Scope:** Counsel-confirmed embargo jurisdiction list (currently `DEFAULT_EMBARGOED` in
`src/kyc-screening.ts`, O4) and a counsel engagement letter on in-house identity proofing
(D8 / `HAR-258`). Cannot be completed by an agent.

**Acceptance Criteria**
- [ ] Embargo list carries a counsel sign-off note in `src/kyc-screening.ts` (AV-S5 uses it).
- [ ] Counsel engagement letter on file (`HAR-258`).

**Tests added:** none.

## Dependencies

| Dependency | Status | Impact if blocked |
|------------|--------|-------------------|
| Outside counsel sign-off (D8, O4) | Blocked (external) | WP-1 co-sign, WP-5; does not block AV-S1/S2 engineering |
| Owner review of proposed FMR/FNMR/APCER numbers | Open | Locks ADR-AV-1 from `proposed` → `accepted` |

## Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Numbers proposed by agent, not yet owner/counsel-approved | High | Med | ADRs stay `proposed`; §5 gate blocks go-live until signed |
| IAL2 mapping contested by counsel | Low | Med | ADR-AV-1 is explicit + revisable; targets re-earn on change |

## Notes

Engineering portion of AV-S0 is done: four ADRs written and grounded in exact code. The
two open items (counsel co-sign, owner number review) are external and do not block the
AV-S1 deploy or AV-S2 harness work — those proceed in parallel. ADRs remain `proposed`
until owner + counsel sign; that is the correct status, not a gap.
