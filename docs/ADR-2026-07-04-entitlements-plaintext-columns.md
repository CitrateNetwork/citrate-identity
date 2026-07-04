---
created: 2026-07-04
branch: feat/encrypt-s1-wp10
author: Fable 5 (Claude Code)
status: accepted
sprint: ENCRYPT-S1
work-package: WP-10
inventory-row: A16
---

# ADR — `entitlements` table columns stay plaintext (accepted risk)

## Status

**Accepted.** No column encryption. This ADR is the ENCRYPT-S1 / WP-10 (inventory
A16) disposition for the plaintext role/tier columns in `src/entitlements.ts`. The
same disposition is inlined as a comment block at the top of that file.

## Context

`src/entitlements.ts` is the authority-side source for the
`https://citrate.ai/entitlement` OIDC claim. It maps a verified principal
(`sub` / `email` / `wallet`) to a Citrate access tier so relying parties (Atlas,
memrizz, …) receive one signed, centralized entitlement.

The whole schema lives in the file (`CREATE_TABLE_SQL`); there is **no separate
migrations directory**. Columns:

| column         | kind                       | used how                                                        |
| -------------- | -------------------------- | --------------------------------------------------------------- |
| `sub`          | opaque OIDC subject        | `WHERE sub = $1` (index `entitlements_sub_idx`)                  |
| `email`        | account identifier         | `WHERE lower(email) = lower($3)` (index on `lower(email)`)       |
| `wallet`       | public chain-40204 address | `WHERE lower(wallet) = lower($2)` (index on `lower(wallet)`)     |
| `tier`         | authorization fact         | selected + branched on in `resolveEntitlementClaim`             |
| `org_id`       | authorization fact         | selected, returned in claim                                     |
| `citrate_role` | authorization fact         | selected + branched on (role-bearing principals bypass KYC gate) |
| `milestone`    | authorization fact         | selected, returned in claim                                     |
| `expires_at`   | timestamp                  | expiry check in `resolveEntitlementClaim`                       |

Every column is a **query predicate or a returned/filtered authorization fact** —
`LOOKUP_SQL` does equality lookups on the three identity keys and the resolver
branches on `tier` and `citrate_role`.

## Decision

Keep all columns plaintext. Do not add column-level encryption.

### Rationale — queryability

You cannot `WHERE` / `ORDER BY` / index a ciphertext. Sealing any of these columns
breaks the equality-index lookups (`sub`, `lower(email)`, `lower(wallet)`) and the
authorization filter (`tier`, `citrate_role`). Making them queryable-while-sealed
would require the blind-index + client-decrypt scheme KYC uses — for effectively
zero confidentiality gain (see threat model).

### Rationale — low sensitivity (threat model: DB compromise)

A full DB exfil of this table yields "principal X holds tier/role Y" plus the
identity keys. That is:

- **Not PII and not a secret/credential.** `tier` / `org_id` / `citrate_role` /
  `milestone` are role/tier membership — authorization facts.
- **Already public.** This table is the authority-side **mirror** of the
  entitlement claim, which is derivable from **public on-chain entitlement
  claims**. `wallet` is a public chain-40204 address.
- **Identifiers already plaintext elsewhere.** `sub` is an opaque OIDC subject;
  `email` is the account identifier that is necessarily stored plaintext across the
  rest of the auth layer (OIDC account + session stores) and is looked up
  case-insensitively here. Sealing this one mirror copy protects nothing while
  breaking the lookup.
- **No key material and no KYC PII** live in this table.

### Contrast — where encryption *is* applied

Genuine KYC PII (legal name, DOB, ID/selfie images, document numbers) lives in
`src/kyc-cases-pg.ts`, sealed **server-blind** via `src/kyc-crypto.ts`
(AES-256-GCM DEK envelope wrapped by `KYC_MASTER_KEY`, plus an HMAC blind index for
lookup-without-storage). That bar is met there because the data is sensitive **and
not public**. Entitlements are the inverse: non-PII, already-public authorization
data that must stay queryable.

## Consequences

- Accepted risk: a DB compromise reveals tier/role membership — information already
  public on-chain — and the identity keys already plaintext elsewhere in the auth
  layer. No secrets, key material, or KYC PII are exposed by this table.
- **Optional future hardening (not warranted now):** a blind index (HMAC via
  `blindIndex()` in `kyc-crypto.ts`) over the `email` / `wallet` lookup keys would
  let those two identifier columns be sealed while preserving equality lookup. This
  is tracked here but declined at current sensitivity.
- **Re-open trigger:** if a genuinely sensitive value (a secret, or PII beyond
  these identifiers) is ever added to a column here, seal just that column with the
  `kyc-crypto` envelope, keeping the non-sensitive columns queryable.

## Disposition

**PATH A — assessed-and-accepted. Docs-only; no code/schema change.**
