---
created: 2026-07-15T05:30:00Z
branch: main
author: Larry Klosowski (@SaulBuilds) + Claude Fable 5
status: deployed
---

# citrate-treasury-signer (Phase-D D2.4 / CORE-S5.5, @rule8)

The **droplet signing path** for the membership money flow. core-membership's grant
orchestrator runs on Vercel and MUST NOT hold the vault/SBT owner key (@rule8); it
POSTs grant/mint requests here, and this worker — holding the deterministic
**treasury/grant signer** key on an operator droplet — signs the `onlyOwner` calls,
broadcasts to chain 40204, and returns tx hashes.

## Why it's isolated
- Separate process, separate port (`127.0.0.1:8790`), separate key from the identity
  service. The key lives ONLY in this unit's env (`TREASURY_SIGNER_KEY`), never in the
  repo, never on Vercel.
- Bearer auth (`TREASURY_SIGNER_TOKEN`) on every signing call.
- Per-UTC-day SALT cap (`TREASURY_DAILY_CAP_WEI`), persisted to
  `/var/lib/citrate-treasury-signer/state.json` (survives restart) → bounded blast radius.
- The key can only reach a fixed allow-list of `onlyOwner` methods on the two pinned
  contracts (vault + SBT). No arbitrary calldata, no balance transfer-out.

## The key is DETERMINISTIC (survives reroll)
`TREASURY_SIGNER_KEY` = the treasury/grant signer = `keccak256(DEPLOYER_PRIVATE_KEY ++
utf8("citrate/treasury-grant-signer/v1"))`, regenerable via
`citrate-chain/scripts/ops/derive-operator-keys.sh`. It owns `MembershipStakeVault` +
`CitrateMemberSBT`. On a reroll the reroll runbook re-derives it, re-funds it, and
redeploys the contracts owned by it — see the reroll master checklist.

## HTTP contract (membership team's Phase-D appendix)
One endpoint does BOTH `onlyOwner` legs of a membership grant, idempotent by
`orderId` and by on-chain state; the service hashes the raw `sub` itself and
clamps `amountWei` to the policy grant. It never fabricates a hash — a skipped
leg returns `null`.
```
GET  /health   -> { status, signer, day, spentToday, dailyCap, grantWei, vault, sbt }
POST /grant   (Authorization: Bearer <TREASURY_SIGNER_TOKEN>)
  body: { orderId, sub, member, amountWei, termStart, termEnd, chainId, contracts:{vault,sbt} }
    leg 1  vault.grant(member, amount){value:amount}   — skipped if attributedShares(member) > 0
    leg 2  sbt.mintMember(member, keccak256(sub), termStart, termEnd) — skipped if isSubBound(subHash)
  200 -> { orderId, vaultTxHash|null, sbtTxHash|null, sbtTokenId|null, status:"granted"|"already_granted" }
  401 bad/absent bearer · 403 daily cap · 409 orderId in-flight · 422 validation/allowlist
  502 broadcast/revert · (503 reserved for not-ready)
```
Idempotency is layered: a completed `orderId` replays its stored result; an
in-flight `orderId` gets 409; and even a fresh `orderId` is a no-op per-leg if
the member is already attributed / the sub already bound (`already_granted`).

## Env
| var | meaning |
|---|---|
| `TREASURY_SIGNER_KEY` | the deterministic treasury/grant signer private key (owns vault+SBT) |
| `TREASURY_SIGNER_TOKEN` | bearer token core-membership authenticates with (constant-time checked) |
| `TREASURY_SIGNER_TOKEN_PREV` | OPTIONAL — during a rotation, the OLD token; both it and `TREASURY_SIGNER_TOKEN` authorize until every caller has redeployed with the new token, then unset it. Removes the brief 401 window. |
| `CITRATE_RPC_URL` | `https://rpc.citrate.ai` |
| `CITRATE_CHAIN_ID` | `40204` |
| `MEMBERSHIP_STAKE_VAULT_ADDRESS` / `CITRATE_MEMBER_SBT_ADDRESS` | pinned contracts |
| `TREASURY_DAILY_CAP_WEI` | per-UTC-day SALT ceiling (default 96k SALT = 3 grants) |
| `PORT` | default 8790 (bound to 127.0.0.1; Caddy terminates TLS) |

core-membership side: set `TREASURY_SIGNER_URL=https://<host>/v1/sign` (or the base, per
its client) and the matching bearer token; leave `TREASURY_SIGNER_KEY` UNSET on Vercel.

## Deploy (identity droplet)
```
# on the droplet, as root
install -d /opt/citrate-treasury-signer /var/lib/citrate-treasury-signer
# copy server.mjs + package.json, then:
cd /opt/citrate-treasury-signer && npm i --omit=dev
# /etc/citrate-treasury-signer.env holds the secrets (chmod 600)
systemctl enable --now citrate-treasury-signer
# Caddy: reverse_proxy the public route to 127.0.0.1:8790
```

## Dual-control (documented follow-up)
Beta runs single-operator with the daily cap. To require a second approver, extend
`/v1/sign` to demand an `X-Approval` HMAC from a second operator key before broadcasting
grants over a threshold. Tracked as the D2.4 hardening item.
