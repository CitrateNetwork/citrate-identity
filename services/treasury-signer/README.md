# citrate-treasury-signer (Phase-D D2.4 / CORE-S5.5, @rule8)

The **isolated signing path** for the membership money flow. core-membership's grant
orchestrator runs on Vercel and MUST NOT hold the vault/SBT owner key (@rule8); it
POSTs grant/mint requests here. This worker holds the deterministic
**treasury/grant signer** key on an operator host, signs the `onlyOwner` calls,
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

## The signer key
`TREASURY_SIGNER_KEY` is the treasury/grant signer. It owns `MembershipStakeVault` and
`CitrateMemberSBT`. The operator key ceremony provisions it; how it is derived, stored and
rotated is kept in the private operator runbook, not in this public repository. On a re-roll
the ceremony re-provisions and re-funds it, and redeploys the contracts it owns.

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

## Deploy (operator host)
```
# on the signer host, as an administrator
install -d /opt/citrate-treasury-signer /var/lib/citrate-treasury-signer
# copy server.mjs + package.json, then:
cd /opt/citrate-treasury-signer && npm i --omit=dev
# /etc/citrate-treasury-signer.env holds the secrets (chmod 600)
systemctl enable --now citrate-treasury-signer
# Caddy: reverse_proxy the public route to 127.0.0.1:8790
```

## Rekey after a re-roll

A re-roll can move the vault and SBT addresses and rotate the signer. The rekey is off-chain: it swaps
the signer credential and the two pinned-contract env vars (`MEMBERSHIP_STAKE_VAULT_ADDRESS`,
`CITRATE_MEMBER_SBT_ADDRESS`) in the service env file. It changes no on-chain address.

Do not copy addresses from this README or from chat. Take them from the address book, which is the
single source of truth:

- `citrate-chain/contracts/addresses/40204.json`, top-level keys `MembershipStakeVault` and
  `CitrateMemberSBT`, also rendered at [docs.citrate.ai/chain/addresses](https://docs.citrate.ai/chain/addresses).

Before you rekey, confirm both addresses have code and are owned by the new signer:

```bash
BOOK=citrate-chain/contracts/addresses/40204.json
VAULT=$(jq -r '.MembershipStakeVault' $BOOK)
SBT=$(jq -r '.CitrateMemberSBT' $BOOK)
cast code  $VAULT --rpc-url https://rpc.citrate.ai          # must not be "0x"
cast code  $SBT   --rpc-url https://rpc.citrate.ai          # must not be "0x"
cast call  $VAULT "owner()(address)" --rpc-url https://rpc.citrate.ai
cast call  $SBT   "owner()(address)" --rpc-url https://rpc.citrate.ai   # both == the new signer
```

Then run `rekey.sh` on the signer host with `NEW_VAULT` and `NEW_SBT` set to those values. It reads
the new private key on STDIN only (never argv or a log), patches the env file atomically, recreates the
container (a plain `docker restart` does not re-read `--env-file`), and asserts that `/health` reports
the new signer and both contracts. Run it only after the new contracts have code and the new signer is
funded. Key handling for the STDIN pipe is covered in the private operator runbook.

## Dual-control (documented follow-up)
Beta runs single-operator with the daily cap. To require a second approver, extend
`/v1/sign` to demand an `X-Approval` HMAC from a second operator key before broadcasting
grants over a threshold. Tracked as the D2.4 hardening item.
