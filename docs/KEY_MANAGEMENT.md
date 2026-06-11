---
created: 2026-06-11
branch: audit/secrem02-keysafe-k2
author: Fable 5 (Claude Code)
status: active
---

# Signing-Key Management (FUA-IDENTITY-06 / KEYSAFE K2)

## Current state: file-backed RS256 JWKS

The authority's RS256 signing key lives in `.keys/jwks.json` (override with
`JWKS_PATH`). It is gitignored, `.dockerignore`d, and **enforced to mode
`0600`**: `loadOrCreateJwks()` writes it `0600` and asserts/repairs the mode on
every load, throwing (refusing to boot) if the file cannot be restricted.

### Key layout invariant

- `keys[0]` — the ACTIVE signing key. panva `oidc-provider` signs with the
  first suitable key; the SIWE direct path is handed `keys[0]` explicitly.
- `keys[1]` (optional) — a **published-but-retiring** verify-only key. It is
  served by `/jwks` so outstanding tokens keep verifying, but never signs.

### Rotation procedure (zero forced re-login)

```sh
npm run rotate-key   # generate new signer, keep old key published
# restart the authority (new tokens now carry the new kid)
# ... wait >= the longest outstanding token TTL ...
npm run rotate-key   # second rotation drops the old key from /jwks
# restart again
```

The publish window is two keys deep, so each rotation gives an overlap window
in which tokens signed by the previous key still verify against `/jwks`.
Regression coverage: `test/jwks-keysafe.test.ts`.

## Upgrade path: KMS / HSM

The file-backed key is a dev/early-prod posture. The production end-state is
non-exportable key material:

1. **Seam.** All signing flows through two points: the `jwks` handed to panva
   (`buildConfiguration`) and the `signingJwk` handed to `mountSiweRoutes`.
   Both already treat `keys[0]` as opaque — swap-in point for a remote signer.
2. **KMS step.** Hold the private key in a cloud KMS (AWS KMS / GCP Cloud KMS
   asymmetric sign, `RSASSA_PKCS1_V1_5_SHA_256`). Replace local `jose`
   `SignJWT.sign(privateKey)` with a `KeyObject`-less remote sign call
   (jose supports `CryptoKey`-like wrappers; alternatively sign the JWS
   signing input via the KMS API and assemble the compact JWS). The public
   JWKS continues to be served from the exported public key only — no private
   material on disk at all.
3. **HSM step.** For the hardened end-state, a PKCS#11 HSM (CloudHSM, YubiHSM2,
   SoftHSMv2 for staging) behind the same seam; the key is generated inside
   the device and is non-exportable.
4. **Rotation in KMS/HSM mode** keeps the same two-deep publish window: create
   the new KMS key version, publish both public keys at `/jwks`, flip the
   signer, drop the old version after the overlap window.

Until then: the `0600` enforcement plus the two-key rotation above is the
accepted interim posture (audit finding FUA-IDENTITY-06, Low).
