---
created: 2026-07-23T00:00:00Z
branch: main
author: Saul Loveman + Claude Opus 4.8 (1M context)
sprint: XR-PRESS-1 (backlog / cross-repo request)
status: proposed
requested_by: citrate-press (PRESS-S0)
repo: citrate-identity (Tier-1)
---

# XR-PRESS-1 — Service-principal auth + RFC 8693 token exchange

> **Cross-repo request from `citrate-press`.** This is a spec for the identity track to
> schedule; it is not yet an active identity sprint. It grounds every claim in the current
> `citrate-identity` source so the work is concrete.

## The ask, in one line

Give the federation two OAuth grants it does not have today: **`client_credentials`** (so a
machine — the Hermes operator, background workers, CI — can authenticate as itself, with no
human and no wallet) and **RFC 8693 token exchange** (so a token minted for one relying party
can be exchanged for one audienced to another, preserving audience isolation).

## Why `citrate-press` needs it

Two blockers in `PRESS-S0`:

1. **Machine login.** citrate-press runs an autonomous Hermes operator and droplet workers
   (crawl / SMTP-probe / send). They must call the app's own API and the federation as
   *principals*, not by borrowing a human's session. There is no grant for that today.
2. **Calling `citrate-comms`.** comms deliberately rejects any token whose audience is not its
   own client id (`citrate-comms-web`) — the `FUA-EXPLORER-01` hardening in
   `citrate-comms/webapp/src/lib/auth/session.ts` (`requiredOidcConfig` enforces
   `OIDC_ISSUER` + `OIDC_AUDIENCE`; a token minted for another RP is refused, correctly).
   citrate-press must write contacts/notes into a comms workspace, so it needs a token with
   `aud = citrate-comms-web` **without** weakening that isolation. Token exchange is the
   standard, correct mechanism: present a citrate-press token, receive a short-lived, scoped
   comms-audienced token.

This is not press-specific plumbing — it is the **first service-to-service call in the
federation**, and every future one (dashboard→memories, comms→core-membership, any agent→any
app) reuses exactly this. Building it once, in the authority, is the right altitude.

## Current state (verified 2026-07-23)

- `src/config.ts` — every registered client uses
  `grant_types: ['authorization_code', 'refresh_token']`. **No `client_credentials`, no
  `urn:ietf:params:oauth:grant-type:token-exchange` anywhere.**
- The issuer is panva `oidc-provider`, which supports **both** grants natively:
  - `clientCredentials` is a first-class feature (`features.clientCredentials`).
  - token exchange ships as the configurable draft feature `features.resourceIndicators` +
    the `urn:ietf:params:oauth:grant-type:token-exchange` grant handler (panva documents it as
    an experimental/registerable grant type). It is enabled and validated in provider config,
    not hand-rolled.
- SIWE + Authorization-Code + PKCE + refresh rotation + revocation already work (per the repo
  README and IDP-S1.5/S5). This request adds two grants alongside them; it does not touch the
  human login path.

## Scope

### A. `client_credentials` grant for service principals
- Register a **service-principal client type** (confidential client, secret or, preferred,
  `private_key_jwt` client authentication so no shared secret sits in an env var).
- Enable `features.clientCredentials`; issue an access token whose `sub` is the service
  principal id and which carries a **scope** and, critically, an **audience** naming the
  resource it may call.
- Scope the principal per workspace where relevant (a claim the resource server can enforce),
  so a compromised worker token is blast-radius-limited.
- Principals are **revocable** through the same path as any other token (one revocation story).

### B. RFC 8693 token exchange
- Enable the token-exchange grant. Accept a valid subject token (a service-principal token from
  A, or a user's token) plus a requested `audience`/`resource`, and return a **short-lived,
  narrowed** token audienced to the target RP (e.g. `citrate-comms-web`).
- **Downscope only, never up.** The exchanged token's scope ⊆ the subject token's scope; it
  cannot grant a capability the caller did not already hold.
- Bind the exchanged token's `sub`/`act` so the resource server (and its audit log) can see
  *who* is acting and *on whose behalf* (the `act` actor claim).
- An allow-list of permitted `(client, target-audience)` pairs, so exchange is not an open
  audience-minting oracle.

## Security invariants (fail-closed, matching the house style)

- **No audience widening.** Exchange issues a token for exactly one requested, allow-listed
  audience. It never mints a multi-audience or wildcard token. This preserves the very
  isolation `FUA-EXPLORER-01` exists to enforce.
- **No scope escalation.** Output scope ⊆ input scope, always.
- **Short TTL** on exchanged tokens (minutes), and they are refresh-less.
- **`private_key_jwt`** preferred for service-principal auth so there is no long-lived shared
  secret; if a client secret is used, it is stored off-Vercel (the core-membership treasury
  precedent).
- **Every issuance audited** — client-credentials grants and exchanges both, with the actor
  chain, so "which machine acted, for whom, against what audience" is always answerable.
- **Unset/misconfigured → reject.** No permissive default; the allow-list empty means no
  exchange succeeds.

## Acceptance (BDD)

```gherkin
Scenario: A service principal authenticates with no human
  Given a registered service-principal client "citrate-press-worker"
  When it requests a client_credentials token with scope "press.worker"
  Then it receives an access token whose sub is the principal and whose audience is set
  And the issuance is recorded in the audit log

Scenario: A press token is exchanged for a comms-audienced token
  Given a valid citrate-press service-principal token
  And ("citrate-press", "citrate-comms-web") is on the exchange allow-list
  When it is exchanged requesting audience "citrate-comms-web"
  Then a short-lived token with aud="citrate-comms-web" is returned
  And its scope is a subset of the subject token's scope
  And its act claim names the original principal

Scenario: [GATE] Exchange cannot widen audience
  When a token is exchanged requesting an audience not on the allow-list
  Then the request is rejected

Scenario: [GATE] Exchange cannot escalate scope
  When a token is exchanged requesting a scope the subject token lacks
  Then the request is rejected

Scenario: [GATE] comms still rejects a non-exchanged press token
  Given a raw citrate-press token (aud="citrate-press")
  When it is presented to citrate-comms
  Then it is rejected (FUA-EXPLORER-01 unchanged)
```

## Dependencies / sequencing

- **Blocks:** `citrate-press` PRESS-S0 machine auth (S0-8 comms sync) and PRESS-S5 Hermes
  operator. Interim while this is in the backlog: citrate-press uses **operator-issued
  short-lived tokens** for the worker/Hermes and defers automated comms writes to manual/
  local-then-backfill, so PRESS-S0 is not hard-blocked — but the clean path is this grant.
- **Consumers, once shipped:** every service-to-service call in the federation. Worth a short
  ADR on the exchange allow-list governance (who may add a `(client, audience)` pair).

## Effort estimate

Small-to-medium. panva provides both grants; the work is configuration, a service-principal
client type, the exchange allow-list + downscope/audience guards, the audit wiring, and the
fail-closed tests. No new cryptography. Most of the risk is in getting the guards
(no-widen / no-escalate / allow-list) exactly right — which is why they are written as `[GATE]`
scenarios above.

---
Filed by `citrate-press` (`PLANSET/02_ARCHITECTURE.md` §5a-bis, `05` XR-1). Reciprocal request
XR-2 (`POST /contacts`) goes to `citrate-comms` as a PR from citrate-press.
