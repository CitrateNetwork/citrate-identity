---
created: 2026-07-17T00:00:00Z
branch: sprint/kyc-autoverify-av-s0-s1-2026-07-16
author: Larry Klosowski (@SaulBuilds) + Claude Opus 4.8
status: owner-approved — pending counsel co-sign
adr: AV-4
planset: 2026-07-16-kyc-autoverify (VERI-AV)
readiness_ref: HAR-244
co-sign-required: outside counsel, a compliance lead (compliance)
---

# ADR-AV-4 — Key custody: KMS/HSM master key + client-generated DEKs (O7)

> Implements planset §3 ADR-AV-4 and §5.6 exit criterion. Closes readiness item
> `HAR-244` (master key is a plain env var, not KMS/HSM).

## Context

The KYC master key is a **plain environment variable**. `masterKeyFromEnv`
(`src/kyc-crypto.ts:57`) reads `KYC_MASTER_KEY` (base64, 32 bytes) raw from the
process env, and `config.ts` requires it when `KYC_PROVIDER=inhouse`. The server
unwraps case DEKs in the clear: `inhouse.ts:242-254` (`getCaseDek`) calls
`unwrapDek(c.wrappedDek, this.masterKey)` and hands the plaintext DEK back. The DB
holds only `{ wrapped_dek, ciphertext }`, so the store is server-blind *relative to
the DB* — but the **running server holds the master key and every unwrapped DEK in
memory**. The comment at `inhouse.ts:242-254` already names the stronger model as a
tracked follow-up (O7):

> client-generated DEKs wrapped under an asymmetric KMS public key so the server never
> holds the DEK in the clear.

Until that lands, the "server-blind" description is **only partially true** (planset
§6, server-blindness watch-item).

## Decision (proposed 2026-07-17)

**Two steps, the first mandatory for go-live, the second the true end-state.**

### Step 1 (required for AV-S9 exit) — master key from KMS/HSM, fail-closed
- The prod master key is sourced from a **KMS/HSM** (AWS KMS / GCP KMS / cloud HSM),
  not `KYC_MASTER_KEY` in env. Envelope encryption: the KMS holds the key-encryption
  key; the service requests unwrap operations.
- **Boot fails closed** if the KMS is unreachable or denies the key — mirrors the
  existing `config.ts` TD-1 fail-closed posture. A test proves boot aborts when KMS is
  unreachable.
- The plaintext-`KYC_MASTER_KEY`-from-env path is **removed in prod** (gated to dev/CI
  only behind an explicit non-prod flag). `config.ts` validation rejects a prod boot
  that still relies on the env key.
- **Acceptable residual (stated honestly):** in Step 1 the server still briefly holds
  an unwrapped DEK in memory during case processing (envelope decrypt server-side).
  This is the KMS-standard residual and is acceptable for go-live; it is *not* the
  end-state.

### Step 2 (the O7 end-state) — client-generated DEKs, server never holds plaintext
- The capture client generates the case DEK and wraps it under an **asymmetric KMS
  public key**; only the wrapped DEK is uploaded (`inhouse.ts:242-254`). Unwrap happens
  inside the KMS/HSM boundary (or on the client for its own re-seal), so the server
  never holds a DEK in the clear.
- This removes the Step-1 residual and makes "server-blind" fully accurate.

### Copy honesty (until Step 2 lands)
Public and compliance copy must say the server holds the master key (Step 1) and must
**not** claim full server-blindness until Step 2 ships (planset §6). One source of
truth for that claim lives in the compliance posture doc.

## Consequences

- Step 1 is a §5.6 hard gate for flipping auto-verify on; Step 2 may trail as a tracked
  hardening follow-up **provided** the Step-1 residual is documented and the copy is
  honest.
- Fail-closed-on-KMS-unreachable trades availability for confidentiality: a KMS outage
  halts new sealing rather than falling back to a plaintext key. That is the correct
  trade for PII custody and matches the repo's existing fail-closed stance.
- Removing the env-key path in prod eliminates the `HAR-244` finding and the "key in
  env / key in process list / key in a leaked `.env`" class of exposure.

## Related

- `src/kyc-crypto.ts:57` (`masterKeyFromEnv`), `src/kyc-providers/inhouse.ts:242-254`
  (`getCaseDek` + O7 note), `src/config.ts` (TD-1 fail-closed validation to extend).
- Planset §5.6 exit criterion, §6 server-blindness watch-item, readiness `HAR-244`.
- ADR-AV-1/2/3 (the decision path this protects the PII for).
