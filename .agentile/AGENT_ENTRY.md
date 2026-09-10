---
created: 2026-06-03T00:00:00Z
last_updated: 2026-07-16
branch: main
author: Saul Loveman + Claude Opus 4.8 (1M context)
status: active
planset: IDP
repo: citrate-identity (Tier-1)
---

# Agent Entry Point — citrate-identity

> Start here. This is the **GTM-spine IDP authority** — `auth.citrate.ai`, the
> Citrate OIDC/OAuth2 issuer. Read this before touching the repo.

## Where am I?

`CitrateNetwork/citrate-identity` — the deployed, live identity authority at
`auth.citrate.ai`. A real OIDC issuer (panva `oidc-provider`) plus SIWE
(EIP-4361) login, in-house KYC/AML, ERC-4337 account-abstraction (wallet
register/predict/guardians/bundler), and admin/compliance surfaces. This is a
running authority, not a bootstrap PoC. Not mainnet-ready and not audit-complete.

## Decisions (ADRs)

- **ADR-idp-stack** — Node/TS on panva `oidc-provider` (do NOT hand-roll OIDC;
  red-team + security). Locked at S1. _This repo implements it._
- **ADR-idp-privy-role** — Citrate is the issuer; this repo issues the tokens.
  The original PoC question (whether Privy consumes a Citrate JWT vs. Privy
  issues) is settled in favor of Citrate-issued. See `src/privy-custom-auth.md`
  for the historical harness.

## Canonical pointers

- Planset (in-house KYC/AML — replaces a third-party KYC vendor): `citrate-federation/.agentile/planset/2026-07-01-inhouse-kyc-aml.md` (program VERI; supersedes the prior third-party-KYC posture in `ADR-2026-06-03-kyc-flow.md`). The in-house provider is the shipped default (`src/kyc-providers/inhouse.ts`); the third-party KYC vendor is removed and the legacy-vendor adapter is a retired typed stub.
- Design: `citrate-federation/.agentile/gtm-spine/design/citrate-identity.md`
- Features: `citrate-federation/.agentile/gtm-spine/features/IDP-S0-*.feature`,
  `IDP-S1-*.feature`
- Federation rules: `citrate-federation/.agentile/rules/CORE_RULES.md`
  (Rule 1 no mocks · Rule 2 tests monotone · Rule 5 Rule-12 frontmatter ·
  Rule 11 manifest canonical · Rule 12 drift map).

## Status of stages

- **IDP-S1 bootstrap** — discovery + JWKS gate is GREEN (`npm test`).
- **Shipped and live** at `auth.citrate.ai`: SIWE login (`src/siwe-routes.ts`),
  identity registry (`src/identity-registry.ts`), wallet-link / ERC-4337 AA
  (`src/aa/`), logout/revocation (`src/logout-routes.ts`, `src/session-bus.ts`),
  in-house KYC/AML (`src/kyc-providers/inhouse.ts`, `src/kyc-*`), account and
  admin/compliance surfaces (`src/account-routes.ts`, `src/admin-kyc-routes.ts`,
  `src/admin-routes.ts`), plus password/WebAuthn/Google auth (`src/auth/`).
- Still open: broader RP wiring, device grant, SAML, hardening — and this
  authority is NOT mainnet-ready and has NOT completed a security audit.

## Run / test

```bash
npm install && npm test     # IDP-S1 gate
npm run dev                 # boot the authority
```
