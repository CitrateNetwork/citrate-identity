# citrate-identity

> The Citrate Network's OIDC/OAuth2 authority — SIWE wallet login, passkeys, and OIDC single sign-on for every Citrate app.

## What it is

`citrate-identity` is the identity provider (IdP) behind `auth.citrate.ai`. It is a
real, runnable OpenID Connect issuer built on
[panva `oidc-provider`](https://github.com/panva/node-oidc-provider): it publishes
OIDC discovery + JWKS, runs Authorization Code + PKCE with refresh-token rotation
and revocation, and adds a custom **Sign-In With Ethereum (SIWE / EIP-4361)**
interaction bound to Citrate chain **40204**. Every other Citrate front-end
(explorer, comms-web, memrizz, dashboard) authenticates against it as a registered
relying party.

See the concept docs at https://docs.citrate.ai/identity. Consumed by
[citrate-explorer](https://github.com/CitrateNetwork/citrate-explorer),
[citrate-comms](https://github.com/CitrateNetwork/citrate-comms) (web client), and
[citrate-memories](https://github.com/CitrateNetwork/citrate-memories) (Memrizz + gateway).

## Prerequisites

```bash
# Node 20+ and npm. Nothing else is required to run the authority locally
# (Postgres + Redis are optional in dev — see "Configuration").
node --version      # must be >= 20
npm --version
```

- OS: Linux or macOS (developed on both).
- Optional for the SIWE EIP-1271 (smart-contract wallet) path: a reachable Citrate
  JSON-RPC endpoint (public `https://rpc.citrate.ai`, or a local devnet node).
- Optional for HA / restart-safe state: Postgres and Redis (Docker is fine).

## Build from source

```bash
git clone https://github.com/CitrateNetwork/citrate-identity.git
cd citrate-identity
npm install
npm run build           # tsc -p tsconfig.build.json  →  dist/
```

Expected artifact: compiled JS in `dist/` (entry `dist/server.js`). Build is fast
(< 30s) and light on RAM. `npm test` runs the vitest suite, including the IDP-S1
bootstrap gate (`test/discovery.test.ts`) which boots the provider on an ephemeral
port and asserts discovery + JWKS are well-formed.

## Run locally

```bash
cp .env.example .env     # defaults are dev-ready (ISSUER_URL=http://localhost:3000)
npm install
npm run dev              # tsx src/server.ts  — listens on PORT (default 3000)
```

Default port: **3000**. Verify it's up:

```bash
curl -s http://localhost:3000/.well-known/openid-configuration | jq '{issuer, authorization_endpoint, token_endpoint, jwks_uri}'
curl -s http://localhost:3000/jwks | jq '.keys | length'   # >= 1 signing key
```

You should get a discovery document with `issuer=http://localhost:3000` and a JWKS
with at least one RS256 key (no private material). In dev, Postgres/Redis are
unset and the provider falls back to in-memory stores (with a warning) — fine for a
single instance; state is lost on restart.

Production start (after `npm run build`): `npm start` (`node dist/server.js`).

## Connect it locally  ← the differentiator

`citrate-identity` is an **upstream** — other apps point at it. To run the minimal
identity + relying-party loop on one box:

1. **Start the authority** on `:3000` (above). This is the issuer.
2. **(Optional) Enable EIP-1271** for Safe / smart-contract-wallet SIWE by pointing
   the authority at a chain RPC:
   ```bash
   # in .env — enables on-chain isValidSignature checks against chain 40204
   CITRATE_RPC_URL=https://rpc.citrate.ai      # or a local devnet node's RPC
   ```
   Without it, EOA (externally-owned-account) signatures still log in fine.
3. **Point a relying party at it.** The reference RP is `citrate-explorer`,
   pre-registered with redirect URI `${EXPLORER_ORIGIN}/auth/callback`
   (`EXPLORER_ORIGIN` defaults to `http://localhost:3001`). In the explorer's
   `.env.local` set `NEXT_PUBLIC_AUTH_MODE=oidc`,
   `NEXT_PUBLIC_OIDC_ISSUER=http://localhost:3000`, `OIDC_ISSUER=http://localhost:3000`,
   `OIDC_JWKS_URL=http://localhost:3000/jwks`, `OIDC_AUDIENCE=citrate-explorer`, and
   run the explorer on **:3001** (`pnpm dev -p 3001`). comms-web (`:3004`) and Memrizz
   register the same way under their own `client_id`s.
4. **End-to-end SIWE check** (headless):
   ```bash
   curl -s http://localhost:3000/siwe/challenge          # → {"nonce":"..."}
   # build + sign an EIP-4361 message (domain=localhost:3000, chainId 40204,
   # that nonce, a future expirationTime), then:
   curl -s -X POST http://localhost:3000/siwe/verify \
     -H 'content-type: application/json' \
     -d '{"message":"<eip-4361 message>","signature":"0x..."}'
   ```

For the full multi-repo bring-up (chain → identity → apps), see the federation
`LOCAL_STACK` at https://docs.citrate.ai/local-stack.

## Configuration

Key env vars (full annotations in `.env.example`):

| Var | Default (dev) | Purpose |
|-----|---------------|---------|
| `ISSUER_URL` | `http://localhost:3000` | Public issuer URL; host must match `PORT`. |
| `PORT` | `3000` | Listen port. |
| `EXPLORER_ORIGIN` | `http://localhost:3001` | Registered redirect base for the explorer RP. |
| `DASHBOARD_ORIGIN` | `http://localhost:3002` | Redirect base for the dashboard RP. |
| `COOKIE_KEYS` | dev default | Comma-separated cookie-signing secrets (prepend to rotate). |
| `DATABASE_URL` | unset → in-memory | Postgres for the KYC claim store (persists across restarts). **Required in production.** |
| `REDIS_URL` | unset → in-memory | Redis backing the panva adapter, SIWE nonce store, and logout bus. **Required in production.** |
| `CITRATE_RPC_URL` | unset | Chain 40204 RPC; enables SIWE EIP-1271 smart-contract-wallet verification. |
| `WALLETCONNECT_PROJECT_ID` | unset | Optional; adds the WalletConnect connector to the SIWE page. |

In production the authority refuses to boot unless `DATABASE_URL`, `REDIS_URL`, and
`COOKIE_KEYS` are set (`assertProductionConfig`).

## Links

- Docs: https://docs.citrate.ai/identity
- Depends on: [citrate-chain](https://github.com/CitrateNetwork/citrate-chain) (optional, for EIP-1271 SIWE)
- Consumed by: [citrate-explorer](https://github.com/CitrateNetwork/citrate-explorer) · [citrate-comms](https://github.com/CitrateNetwork/citrate-comms) · [citrate-memories](https://github.com/CitrateNetwork/citrate-memories)
- Contributing (DCO): CONTRIBUTING.md · Security: SECURITY.md · License: LICENSE

## License

Source-available (BUSL-1.1) — free for personal/non-commercial; commercial = membership.
