# DevOps Request — Deploy `citrate-identity` (auth.citrate.ai)

> **Audience:** the DevOps engineer who owns the droplets + SSH. This is a request +
> runbook to stand up the **Citrate OIDC authority** on a Docker VPS. It is the
> **identity root for every Citrate app** (explorer, dashboard, studio) and is
> currently **blocking client demos** — once it's live at a public HTTPS URL, the
> app team can point their apps at it and demo immediately.
>
> The app is **feature-complete and tested (100 passing tests)**. The only thing
> left is this deployment. You retain full ownership of the droplet, DNS, secrets,
> and backups.

---

## 1. What you're deploying
A long-running **Node.js** service (panva `oidc-provider` + SIWE wallet login). It is
**stateful**, so it is NOT serverless — it runs as a container with **Redis**
(authority state: sessions/grants, SIWE nonces, logout bus) and **Postgres** (KYC
claims). `docker-compose.yml` wires all of it, with **Caddy** terminating TLS.

```
            ┌───────── Caddy (80/443, auto Let's Encrypt) ─────────┐
 client ───▶│  https://auth.citrate.ai  ──▶  identity:3000 (Node)  │
            └──────────────────────────────────┬───────────────────┘
                                   ┌────────────┴────────────┐
                              redis:6379                 postgres:5432
                         (state, nonces, bus)            (KYC claims)
```

Everything is in this repo: `Dockerfile`, `docker-compose.yml`, `Caddyfile`,
`.env.production.example`.

---

## 2. What we need from you (prereqs)
1. **A droplet** — Ubuntu 22.04+ with **Docker + Docker Compose v2**. Sizing: **2
   vCPU / 4 GB RAM / 40 GB disk** is comfortable for demos (it's light; Postgres +
   Redis + Node). 1 GB works but 4 GB is safer.
2. **DNS** — an **A record** `auth.citrate.ai` → the droplet's public IP. (A staging
   host like `auth-staging.citrate.ai` is fine for first demos.) **Set this BEFORE
   `docker compose up`** so Caddy can obtain the TLS cert.
3. **Firewall** — allow **inbound 80 + 443 only**. Do **not** expose Postgres (5432)
   or Redis (6379) publicly — they stay on the internal compose network.
4. **Repo access** — a GitHub deploy key or PAT for `CitrateNetwork/citrate-identity`
   (private).
5. **(Optional) WalletConnect project id** — a free id from https://cloud.reown.com
   enables the mobile/QR wallet connector on the login page (injected wallets work
   without it).

---

## 3. Runbook (≈15 min after DNS propagates)
```bash
# 0) On the droplet, as a deploy user with docker access:
git clone git@github.com:CitrateNetwork/citrate-identity.git
cd citrate-identity

# 1) Create the env file from the template and fill it in (see §4):
cp .env.production.example .env
#    Generate each secret with:  openssl rand -hex 32
#    Required: COOKIE_KEYS, POSTGRES_PASSWORD, REDIS_PASSWORD, KYC_WEBHOOK_SECRET
#    Set: ISSUER_URL + ISSUER_HOST (auth.citrate.ai), EXPLORER_ORIGIN, DASHBOARD_ORIGIN
$EDITOR .env

# 2) Bring it up (builds the image, starts postgres+redis+identity+caddy):
docker compose up -d --build

# 3) Watch it become healthy:
docker compose ps
docker compose logs -f identity   # should log a clean boot (no fail-closed throw)

# 4) Verify (after Caddy gets the cert — give it ~30s on first boot):
curl -s https://auth.citrate.ai/health                              # {"status":"ok"}
curl -s https://auth.citrate.ai/.well-known/openid-configuration    # issuer = https://auth.citrate.ai
curl -s https://auth.citrate.ai/jwks                                # RS256 public keys
```
If `identity` refuses to boot, that's **by design** — `assertProductionConfig`
fail-closes on missing/unsafe `COOKIE_KEYS` / `ISSUER_URL` / `DATABASE_URL` /
`REDIS_URL`. The log line names exactly which one. Fix `.env`, `docker compose up -d`
again.

---

## 4. Environment reference (`.env`)
| Var | Required? | Notes |
|---|---|---|
| `NODE_ENV` | yes | `production` (triggers fail-closed checks) |
| `PORT` | yes | `3000` (matches Dockerfile/healthcheck/compose) |
| `ISSUER_URL` | **yes** | `https://auth.citrate.ai` — public HTTPS, no localhost |
| `ISSUER_HOST` | **yes** | `auth.citrate.ai` — the host Caddy gets a cert for |
| `COOKIE_KEYS` | **yes** | comma-separated, each **≥32 chars**; `openssl rand -hex 32`. Rotate by **prepending** a new key |
| `EXPLORER_ORIGIN` | **yes** | `https://explorer.citrate.ai` (CORS + redirect_uri) |
| `DASHBOARD_ORIGIN` | **yes** | `https://dashboard.citrate.ai` |
| `STUDIO_ORIGIN` | optional | only if studio runs as a hosted web origin |
| `POSTGRES_USER`/`POSTGRES_PASSWORD`/`POSTGRES_DB` | **yes** | compose builds `DATABASE_URL` from these. (Or set `DATABASE_URL` directly for an external DB.) |
| `REDIS_PASSWORD` | **yes** | compose builds `REDIS_URL` from it. (Or set `REDIS_URL` directly.) |
| `KYC_WEBHOOK_SECRET` | **yes**\* | shared secret for `POST /kyc/_set`,`/kyc/_revoke`; unset = those endpoints disabled |
| `CITRATE_RPC_URL` | optional | chain-40204 RPC; enables EIP-1271 (Safe/contract-wallet) logins. EOA + WalletConnect work without it |
| `WALLETCONNECT_PROJECT_ID` | optional | enables the login-page QR/mobile connector (not fail-closed) |

\*`KYC_WEBHOOK_SECRET` is only needed when the KYC vendor webhook is wired; safe to
set now so it's ready.

---

## 5. Persistence, backups, security
- **JWKS signing keys** — persisted in the `identity_keys` volume
  (`/app/.keys/jwks.json`, generated on first boot). **Back this volume up.** If it's
  lost, all issued tokens stop verifying and every RP must refetch `/jwks` — a forced
  re-login for everyone. (Future: move to a secrets manager — TD-7.)
- **Postgres** — KYC claims (no PII; only `{status, verified_at, expires_at,
  vendor_ref}`). Back up the `postgres_data` volume (or `pg_dump`).
- **Redis** — AOF persistence is on (`appendonly yes`), password-protected. Holds
  sessions/nonces (ephemeral); a loss just logs users out.
- **Secrets** — the filled `.env` is git-ignored; keep it on the droplet only (or
  your secrets manager). Never commit it.
- **Network** — only 80/443 public; Postgres/Redis are internal to the compose
  network. The app trusts `X-Forwarded-*` (`provider.proxy=true`) so it issues
  correct `https` URLs + Secure cookies behind Caddy/any TLS terminator.

---

## 6. If the droplet already has ingress
If you front services with your own nginx/Caddy/Traefik, **delete the `caddy`
service** from `docker-compose.yml`, publish `identity`'s port internally, and point
your proxy at it — forwarding `X-Forwarded-Proto/Host`. The app already trusts those
headers.

---

## 7. App-team coordination (not your task, for context)
Once live, the app team sets, in explorer/dashboard/studio:
`NEXT_PUBLIC_OIDC_ISSUER=https://auth.citrate.ai`, `OIDC_ISSUER`, `OIDC_JWKS_URL=
https://auth.citrate.ai/jwks`, client_id, scopes. Their redirect URIs
(`${origin}/auth/callback`) are already registered via `EXPLORER_ORIGIN` /
`DASHBOARD_ORIGIN`. See `citrate-explorer/AUTH_HANDOFF.md`.

---

## 8. Ops
- **Health/uptime:** point your monitor at `GET /health` (200 `{status:"ok"}`; also
  reports `redis`/`db` booleans).
- **Logs:** `docker compose logs -f identity` (and `caddy`).
- **Update:** `git pull && docker compose up -d --build`.
- **Rollback:** `git checkout <prev> && docker compose up -d --build` (or redeploy a
  pinned image).
- **Scaling (later):** it's HA-ready — Redis-backed state means you can run multiple
  `identity` replicas behind Caddy/an LB. Single instance is fine for demos.

---

**Bottom line:** provision the droplet + DNS + firewall, fill `.env` (4 secrets +
the issuer/origins), `docker compose up -d --build`, verify `/health` + discovery
over HTTPS. Then the demos are unblocked. Ping the app team with the live issuer URL.
