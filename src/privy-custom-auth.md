---
created: 2026-06-03T00:00:00Z
branch: main
author: Saul Loveman + Claude Opus 4.8 (1M context)
status: poc-pending
planset: IDP
feature: IDP-S0-privy-custom-auth-poc
---

# IDP-S0 — Privy custom-auth PoC wiring

> This is **documentation**, not code. It tells you (the repo owner) the exact
> values you must provide in **your** Privy dashboard to run the IDP-S0 decision
> gate. The IDP issuer in this repo is the "minimal Citrate OIDC issuer that
> signs a JWT with a JWKS endpoint" referenced by the feature file.

## What this PoC decides (the gate)

`ADR-idp-privy-role` is **pending**. Today Privy is the PRIMARY issuer. The
inversion we must prove: **Privy can CONSUME a Citrate-issued JWT** and provision
an embedded wallet keyed on our `sub`.

- If Privy accepts the Citrate JWT and provisions a wallet →
  **Option 1 (Citrate issues, Privy consumes)** is adopted.
- If it cannot → **Option 3 (Citrate-only auth, Privy REST for wallets)**.
- **Option 2 (Privy issues)** is rejected up front — it fails non-Privy clients
  and SAML.

(See `citrate-federation/.agentile/gtm-spine/features/IDP-S0-privy-custom-auth-poc.feature`.)

## What THIS repo gives you

Run `npm run dev`. The authority then serves:

- **Issuer**: `${ISSUER_URL}` (default `http://localhost:3000`).
- **JWKS**: `${ISSUER_URL}/jwks` — Privy validates token signatures against this.
- **Discovery**: `${ISSUER_URL}/.well-known/openid-configuration`.

The signing key is RS256 and persisted under `.keys/jwks.json` so the `kid`
stays stable across restarts during the PoC.

> Privy custom auth requires a **publicly reachable** JWKS URL. `localhost` is
> not reachable from Privy's servers. For the PoC, expose your local issuer with
> a tunnel (e.g. `cloudflared tunnel --url http://localhost:3000` or `ngrok http
> 3000`) and set `ISSUER_URL` to the tunnel's HTTPS URL **before** starting the
> server, so the JWKS URL and the token `iss` match what Privy is configured with.

## What YOU must provide in the Privy dashboard

You hold the Privy account; the agent cannot do this for you. Provide:

1. **A Privy app.** Create one at https://dashboard.privy.io. Copy its **App ID**
   into `.env` as `PRIVY_APP_ID` (this is for your PoC harness/notes — the issuer
   itself does not consume it).
2. **Enable Custom Auth** for that app (Authentication → Custom auth / JWT-based
   auth).
3. **JWKS endpoint**: set it to your issuer's `{ISSUER_URL}/jwks`
   (the tunnel URL during local PoC).
4. **`iss` (issuer)**: set to exactly your `ISSUER_URL` — it must equal the `iss`
   claim in the minted token.
5. **`aud` (audience)**, if Privy asks: set to the value you mint into the token
   (use `citrate-explorer` to match the registered client, or whatever Privy's
   custom-auth config requires — keep token and dashboard in agreement).
6. **User identifier claim**: confirm Privy keys the user on the **`sub`** claim.
   `sub` is our durable identifier; the wallet must resolve to the same Privy
   user on repeat logins with the same `sub`.

## Running the acceptance (IDP-S0)

For each scenario in the feature file:

1. **JWT accepted** — mint a short-lived RS256 JWT signed by the issuer key,
   with `iss = ISSUER_URL`, `aud` per step 5, a stable `sub`, and a future `exp`.
   Present it to Privy via its custom-auth login. Expect: signature + expiry
   validate, session established.
2. **Wallet provisioned** — first login with that `sub` → Privy provisions an
   embedded wallet. Record the wallet address.
3. **Durable sub** — log in again with a **new** token sharing the same `sub` →
   Privy resolves the same user and returns the same wallet address.
4. **Decision** — record the outcome in `ADR-idp-privy-role` (Option 1 vs 3).

You can mint the PoC token with `jose` (already a dependency). Use the private
key from `.keys/jwks.json` and its `kid`. Keep `exp` short (a few minutes).

## After the PoC

Update `ADR-idp-privy-role` in `citrate-federation` with the result, then the
authority graduates to IDP-S1+ (this repo already passes the S1 discovery/JWKS
gate via `npm test`).
