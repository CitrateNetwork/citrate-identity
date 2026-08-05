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

## Staking model — bond-clone (canonical, owner decision 2026-08-05)
The 32k bond does **not** go to the member's EOA (that was ADR-2026-07-27, now
reversed). It is placed into the member's per-member `MemberBond` clone via
`MembershipStakeVault.grant(member, amount, memberTokenId){value: amount}`, which
deploys **and** funds the clone in one call. The clone — not the member — becomes the
`ValidatorRegistry` staker later, when the member calls `MemberBond.activate(pubkey, sig)`
app-side once their node is synced. This avoids the permanent `StakerHasValidator()`
lock the EOA path hit, and keeps the principal in a real, member-only-withdrawable
contract. See `citrate-core/.agentile/sprints/active/sprint-validator-bond-clone` WI-1.

## HTTP contract (membership team's Phase-D appendix)
One endpoint does the `onlyOwner` legs of a membership grant, idempotent by
`orderId` and by on-chain state; the service hashes the raw `sub` itself and
clamps `amountWei` to the policy grant. It never fabricates a hash — a skipped
leg returns `null`. The leg order is mint-first because `grant` needs the SBT
`tokenId` (`ownerOf(memberTokenId) == member`).
```
GET  /health   -> { status, signer, day, spentToday, dailyCap, grantWei, gasHeadroomWei, vault, sbt, model }
POST /grant   (Authorization: Bearer <TREASURY_SIGNER_TOKEN>)
  body: { orderId, sub, member, amountWei, termStart, termEnd, chainId, contracts:{vault,sbt} }
    leg 1  sbt.mintMember(member, keccak256(sub), termStart, termEnd) — skipped if isSubBound(subHash)
    leg 2  vault.grant(member, amount, memberTokenId){value:amount}   — deploy+fund the clone; skipped if bondOf(member) has code (BondExists)
    leg 3  gas top-up: native SALT to member EOA for its activate tx  — GAS ONLY, skipped if balance >= GAS_HEADROOM
  200 -> { orderId, fundTxHash|null, vaultTxHash|null, sbtTxHash|null, sbtTokenId|null, status:"granted"|"already_granted" }
  401 bad/absent bearer · 403 daily cap · 409 orderId in-flight · 422 validation/allowlist
  502 broadcast/revert · (503 reserved for not-ready)
```
(`vaultTxHash` = the vault.grant that deploys+funds the clone; `fundTxHash` = the
gas-only top-up. core-membership validates `vaultTxHash`/`sbtTxHash`/`sbtTokenId`/`status`.)
Idempotency is layered: a completed `orderId` replays its stored result; an
in-flight `orderId` gets 409; and even a fresh `orderId` is a no-op per-leg if the
clone already exists (`bondOf` has code) / the sub already bound (`already_granted`).

## Env
| var | meaning |
|---|---|
| `TREASURY_SIGNER_KEY` | the deterministic treasury/grant signer private key (owns vault+SBT) |
| `TREASURY_SIGNER_TOKEN` | bearer token core-membership authenticates with (constant-time checked) |
| `TREASURY_SIGNER_TOKEN_PREV` | OPTIONAL — during a rotation, the OLD token; both it and `TREASURY_SIGNER_TOKEN` authorize until every caller has redeployed with the new token, then unset it. Removes the brief 401 window. |
| `CITRATE_RPC_URL` | `https://rpc.citrate.ai` |
| `CITRATE_CHAIN_ID` | `40204` |
| `MEMBERSHIP_STAKE_VAULT_ADDRESS` / `CITRATE_MEMBER_SBT_ADDRESS` | pinned contracts |
| `TREASURY_GAS_HEADROOM_WEI` | gas-only top-up to the member EOA so it can pay for its own `MemberBond.activate` tx (default 0.05 SALT). This is NOT the bond — the 32k lives in the clone. |
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

## Rekey at a deployer rotation (reroll PHASE 3.5)

When the deployer key rotates (e.g. the 2026-07-20 reroll — the old deployer was
exposed by a `bash -x` trace), the grant signer rotates with it because it is
`keccak256(DEPLOYER_PRIVATE_KEY ‖ "citrate/treasury-grant-signer/v1")`. The new
signer is **`0xF42a19194fee89E71dC4b8631a71a9CeCf42B483`** and it owns the NEW
CREATE2 SBT/vault (`DeployCoreMembership.FROZEN_OWNER`):

| | OLD | NEW |
|---|---|---|
| grant signer (`TREASURY_SIGNER_KEY`) | `0x9aFFF274…8A50` | `0xF42a1919…B483` |
| `MEMBERSHIP_STAKE_VAULT_ADDRESS` | `0x0aceb7B4…267e` | `0x61E324cFd6B7Cb106AC0AD1dF163bdFef2b74268` |
| `CITRATE_MEMBER_SBT_ADDRESS` | `0x149E85A3…4578` | `0x3e0c2B1cD29a615E4eA2E263C8e7df3Aef243E42` |

**This rekey is off-chain and address-neutral** — it swaps a credential + two
pinned-contract env vars in `--env-file`; it changes NO on-chain address, NO
genesis, NO CREATE2 projection, NO node sync. The addresses are fixed by the
build (`FROZEN_OWNER`), not by this service. Verified: the signer derived from the
new key == `FROZEN_OWNER` == the new SBT/vault owner.

**Timing:** run AFTER `post-reroll-membership.sh` deploys the new SBT+vault (they
must have code on-chain first) and AFTER the new signer is funded. Use `rekey.sh`
(reads the private key on STDIN only — never argv/log):

```bash
# from the DGX — key never touches a terminal/log:
grep -m1 '^GRANT_SIGNER_PRIVATE_KEY=' /home/saul/Projects/Citrate-Labs/.env.testnet \
  | cut -d= -f2 \
  | ssh root@<droplet> \
      'NEW_VAULT=0x61E324cFd6B7Cb106AC0AD1dF163bdFef2b74268 \
       NEW_SBT=0x3e0c2B1cD29a615E4eA2E263C8e7df3Aef243E42 \
       bash /opt/citrate-treasury-signer/rekey.sh'
```

`rekey.sh` patches the env-file atomically, **recreates** the docker container
(a plain `docker restart` does NOT re-read `--env-file`), and asserts `/health`
reports the new signer + both new contracts.

## Dual-control (documented follow-up)
Beta runs single-operator with the daily cap. To require a second approver, extend
`/v1/sign` to demand an `X-Approval` HMAC from a second operator key before broadcasting
grants over a threshold. Tracked as the D2.4 hardening item.
