# citrate-identity

The **Citrate OIDC/OAuth2 authority** — `auth.citrate.ai`. Built on
[panva `oidc-provider`](https://github.com/panva/node-oidc-provider) (per
`ADR-idp-stack`: Node/TS, not hand-rolled). This repo is the **Stage-3 IDP-S0/S1
foundation**: a minimal but real, runnable OIDC issuer plus the harness/doc for
the Privy custom-auth proof-of-concept.

> Scope note: this is the S0/S1 floor. Refresh/revocation/logout-bus (S2),
> identity↔wallet registry (S3), device grant (S4), RP wiring (S5+), and SAML
> (S9) land in later stages per the design's build order. PKCE, refresh rotation
> and revocation are already wired here.

## What it does today

- Publishes OIDC **discovery** at `/.well-known/openid-configuration`.
- Serves a rotating-capable **JWKS** (RS256) at `/jwks`.
- Registers one reference relying party, **`citrate-explorer`** — a public client
  requiring **PKCE (S256)**, scopes `openid profile wallet`.
- Authorization Code + PKCE `/auth` + `/token`, refresh-token rotation, and
  token revocation are enabled.

## Run

```bash
cp .env.example .env        # adjust ISSUER_URL / PORT if needed
npm install
npm run dev                 # tsx src/server.ts
```

Then:

```bash
curl http://localhost:3000/.well-known/openid-configuration
curl http://localhost:3000/jwks
```

## Test

```bash
npm install
npm test                    # vitest run
```

`test/discovery.test.ts` is the **automated IDP-S1 bootstrap gate**: it boots the
provider on an ephemeral port, asserts discovery exposes `issuer`,
`authorization_endpoint`, `token_endpoint`, and `jwks_uri`, and asserts the JWKS
has at least one signing key (with no private material leaked).

## Build

```bash
npm run build               # tsc → dist/
```

## Design + acceptance criteria

- Design: [`citrate-identity.md`](../citrate-federation/.agentile/gtm-spine/design/citrate-identity.md)
  (in `citrate-federation`).
- IDP-S0 (Privy custom-auth PoC):
  [`IDP-S0-privy-custom-auth-poc.feature`](../citrate-federation/.agentile/gtm-spine/features/IDP-S0-privy-custom-auth-poc.feature).
- IDP-S1 (authority bootstrap):
  [`IDP-S1-authority-bootstrap.feature`](../citrate-federation/.agentile/gtm-spine/features/IDP-S1-authority-bootstrap.feature).

## What YOU (the owner) must provide to run the Privy PoC

The IDP issuer here runs with zero external accounts. The **IDP-S0 PoC** needs
things only you (Privy account holder) can supply. Full step-by-step in
[`src/privy-custom-auth.md`](src/privy-custom-auth.md). In short:

1. **A Privy app** (https://dashboard.privy.io) → put its **App ID** in `.env` as
   `PRIVY_APP_ID`.
2. **Enable Custom Auth** on that app.
3. Point Privy's **JWKS URL** at this issuer's `{ISSUER_URL}/jwks`.
4. Set Privy's **`iss`** to your `ISSUER_URL` and **`aud`** to match the token
   you mint (`citrate-explorer`).
5. Confirm Privy keys users on the **`sub`** claim.
6. Because Privy's servers must reach the JWKS, expose your local issuer over a
   public HTTPS tunnel (cloudflared/ngrok) and set `ISSUER_URL` to that URL
   before starting the server.

Then run the four IDP-S0 scenarios and record the result in
`ADR-idp-privy-role` (Option 1 = Citrate-issues/Privy-consumes, vs Option 3 =
Citrate-only auth + Privy REST for wallets).

## License

Part of the Citrate federation. See org-level `SECURITY.md` / `LICENSE`.
