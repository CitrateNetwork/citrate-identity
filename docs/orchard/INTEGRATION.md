---
created: 2026-11-03
branch: feat/orchard-web-identity
author: Codex
status: review-required
---
# Orchard web identity integration
Owner explicitly requested a dedicated auth.citrate.ai integration for the landing and four specialist sites. Adds five exact-origin public Authorization Code RPs. Global S256 PKCE policy applies. No offline access, KYC scope, secret, wildcard redirect, or consent bypass is added.

`POST /identity/:sub/orchard-proof/challenge` issues the existing one-time nonce and an audience/subject/chain-bound message. `POST /identity/:sub/orchard-proof` verifies an EIP-191 signature with the existing signature verifier. Both require an unexpired own-subject access token, the wallet scope, and an Orchard client ID. Existing shared Redis limiter applies in production. The proof never changes wallet links, canonical pay-to addresses, or chain state. The existing wallet mutation client allowlist is unchanged.

The landing backend holds the access token in an encrypted HttpOnly, Secure production, host-only cookie. It forwards signature proofs only to the configured HTTPS Citrate issuer, checks the returned subject/client, and seals a short-lived proof cookie bound to that same identity/client. Browser JS never receives the bearer token. Each specialist hostname uses its own client audience and host-only session cookies.

New email/OAuth users currently need an EIP-1193 browser wallet (or wallet browser) for this signature. Contract-wallet/EIP-1271 proofs are not implemented by the existing verifier. No embedded-wallet custody or private-key generation is introduced. Existing authority-confirmed wallet bindings and legacy SIWE proof remain accepted.

Validation: local real HTTP tests with actual signed messages cover proof success, replay, wrong audience, wrong RP/scope, cross-subject access, exact redirects, and unchanged mutation rejection. The original wallet-client regression suite also passes. Live production login and deployment have NOT been exercised. Deploy authority changes before enabling the new landing clients. Rollback removes the new RPs and proof route; no wallet data migration is needed.

2026-11-03 deployment preparation: owner confirmed this machine's existing DigitalOcean SSH access and requested the live auth connection. Verified /opt/citrate-identity is at the same eb2f179 baseline and healthy; unrelated Caddyfile edits are present and must be preserved. Added separate native citrate-orchard-preview registration for exact loopback callbacks at localhost:3100 and 127.0.0.1:3100; no wildcard domains, refresh grants, or registry mutation permission. Production web registrations remain exact-origin. Full Identity suite: 847 passed, 3 skipped; build/typecheck and the 13 focused proof/client tests passed. Live user sign-in remains to be exercised by the owner. Deployment must preserve the existing image for rollback and rebuild/recreate only the identity service; do not restart databases, replace environment files, change Caddy, or rotate signing keys.
