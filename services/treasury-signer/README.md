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
  contracts (vault + SBT): `mintMember` and `grant` (via `/grant`) and
  `setKycVerified(tokenId, true)` (via `/kyc-attest`). No arbitrary calldata, no
  balance transfer-out.

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
GET  /health   -> { genesis, status, signer, day, spentToday, dailyCap, grantWei, gasHeadroomWei, vault, sbt, model, kycAttest:{enabled,dailyCap,attestedToday} }
POST /grant   (Authorization: Bearer <TREASURY_SIGNER_TOKEN>)
  body: { orderId, sub, member, amountWei, termStart, termEnd, chainId, contracts:{vault,sbt}, expectedGenesis }
    leg 1  sbt.mintMember(member, keccak256(sub), termStart, termEnd) — skipped if isSubBound(subHash)
    leg 2  vault.grant(member, amount, memberTokenId){value:amount}   — deploy+fund the clone; skipped if bondOf(member) has code (BondExists)
    leg 3  gas top-up: native SALT to member EOA for its activate tx  — GAS ONLY, skipped if balance >= GAS_HEADROOM
  200 -> { orderId, fundTxHash|null, vaultTxHash|null, sbtTxHash|null, sbtTokenId|null, status:"granted"|"already_granted", genesis }
  401 bad/absent bearer · 403 daily cap · 409 orderId in-flight · 412 genesis mismatch
  422 validation/allowlist (incl. missing/malformed expectedGenesis)
  502 broadcast/revert · 503 genesis lookup failed
```
(`vaultTxHash` = the vault.grant that deploys+funds the clone; `fundTxHash` = the
gas-only top-up. core-membership validates `vaultTxHash`/`sbtTxHash`/`sbtTokenId`/`status`.)
**Chain-generation pin.** A reroll keeps chainId 40204 (r1005 and r1006 both answer it),
so `chainId` cannot tell generations apart. Every request carries `expectedGenesis`, the
caller's pinned block-0 hash (core-membership: `CITRATE_GENESIS_HASH`). The signer
compares it with `eth_getBlockByNumber("0x0")` on its OWN RPC before it reads any grant
state, again before every broadcast, again after every receipt, and once more after all
grant-state reads before success is recorded (so an all-legs-skipped replay decided on
another generation's state is refused, not cached). A flip after a
broadcast cannot be undone: the signer logs `ALARM genesis_changed_after_broadcast`,
answers 502, and does not record the order done. Missing or malformed is 422, a different hash is
412, a failed lookup is 503; on any refusal nothing is read or sent, and the log line
carries only a reason code and the order id. Block 0 is fetched per check, not cached.
The 200 echoes `genesis`, and core-membership refuses a 200 without the matching echo.

**State file.** The caps and ledger live in `TREASURY_STATE_FILE`, written atomically
(temp file, fsync, rename). A missing file is a fresh signer. An unreadable one makes
the signer **refuse to start** rather than reset its caps and forget completed orders.

Idempotency is layered: a completed `orderId` replays its stored result **only within the
same chain generation** (the ledger key is `<genesis>/<orderId>`, so a result recorded on
an earlier generation is never handed back as a grant on this one); an
in-flight `orderId` gets 409; and even a fresh `orderId` is a no-op per-leg if the
clone already exists (`bondOf` has code) / the sub already bound (`already_granted`).

## Scoped KYC attestation (`POST /kyc-attest`)
A re-roll re-mints the member SBTs, and a fresh mint starts with `kycVerified = false`.
Only the SBT owner (this key) can set it again. `/kyc-attest` restores it from the
member's **stored** verification record. It does not run KYC and it takes no verdict from
the caller.
```
POST /kyc-attest   (Authorization: Bearer <TREASURY_SIGNER_TOKEN>, the same token as /grant)
  body: { member, sub, chainId, contracts:{sbt}, expectedGenesis }   (any other field: 422)
  200 -> { status:"attested"|"already_attested", txHash|null, tokenId, subHash, genesis }
  401 bad/absent bearer · 403 kyc_record_not_verified · 409 kyc_attest_in_flight
  412 genesis mismatch · 422 validation, allowlist, sub_not_bound, member_mismatch,
  member_revoked, member_quarantined · 429 kyc_attest_daily_cap
  500 audit_unavailable (nothing sent) · 502 broadcast/revert/event missing
  503 kyc_attest_unconfigured, kyc_record_lookup_failed, genesis lookup failed
```
In order, the signer:
1. checks the body shape and the pinned SBT address, then the generation pin (as `/grant`);
2. reads `GET <KYC_STATUS_URL>/kyc/status?sub=<sub>` itself, with `KYC_STATUS_SECRET`.
   Only a 200 that names this subject with `kyc_status: "verified"` continues. Expired,
   pending, revoked and none are 403. Any failure, timeout or mismatched answer is 503;
3. reads the SBT: `tokenIdForSub(keccak256(sub))`, `getMember`, `ownerOf`. The token must
   be owned by `member`, and not revoked or quarantined;
4. if the flag is already set, answers `already_attested` and sends nothing (no cap);
5. charges its own per-UTC-day count cap, writes a durable audit "intent" record (if that
   write fails, nothing is sent), and sends `setKycVerified(tokenId, true)` with value 0.
   The generation is re-checked before the broadcast and after the receipt (`ALARM` on a
   flip), and the receipt must carry `KycVerifiedSet(tokenId, true)` from the pinned SBT.

**One key, one queue.** `/grant`'s legs and `/kyc-attest` sign with the same key. Every
send waits in one process-wide queue, which it holds from its pre-send generation check
until its receipt, so two requests never read the same nonce. The receipt must be for
the signer's own hash; when a same-nonce tx replaced it, the request fails with
`ALARM tx_replaced` and 502 (never `granted` or `attested`), even if the replacement
mined.

**Caps and refunds.** The cap is charged before the broadcast and refunded only when the
tx certainly never reached the chain (the pre-send generation check refused, or the RPC
explicitly rejected it). A transport error or timeout during the send keeps the charge,
since the tx may have landed. Otherwise a refusal after the charge uses up a slot
without sending. That errs on the safe side, as `/grant` does.

**Audit.** Each authorized request appends one JSON line to `KYC_ATTEST_AUDIT_FILE`
(an `intent` line before any broadcast, then a `result` line) and mirrors it to stdout.
Records hold the subject hash (`keccak256(sub)`, the value the SBT already stores), the
token id, the tx hash, the generation and the outcome or reason. They never hold the sub,
the wallet, a token or a secret. Error responses don't echo them either.

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
| `KYC_STATUS_URL` | OPTIONAL. Base URL of the identity authority whose `GET /kyc/status` the signer re-checks, e.g. the public issuer `https://auth.citrate.ai`. Must be https; plain http only to loopback or a single-label in-network host (a compose service name). Unset, or with no secret, `/kyc-attest` answers 503 and `/grant` is unaffected. |
| `KYC_STATUS_SECRET` | OPTIONAL. The signer's **own** status secret: the value of its entry in identity's `KYC_STATUS_SECRETS` (e.g. `treasury-signer:<secret>`), distinct from core-membership's. It must never be identity's `KYC_WEBHOOK_SECRET`, which also authorizes `POST /kyc/_set` (a record write); identity refuses to serve `/kyc/status` when the two match and no longer falls back to the webhook secret. |
| `TREASURY_RECEIPT_TIMEOUT_MS` | how long one send waits for its receipt (default 120000). Sends are serialized, so this also bounds how long a stuck tx holds the queue. |
| `KYC_ATTEST_DAILY_CAP` | attestations per UTC day (a count; default 20). An unparsable value is 0, which refuses all. Persisted in the state file. |
| `KYC_STATUS_TIMEOUT_MS` | identity lookup timeout (default 10000) |
| `KYC_ATTEST_AUDIT_FILE` | append-only audit JSONL (default: `kyc-attest-audit.jsonl` next to the state file) |

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

Then run `rekey.sh` on the signer host with `NEW_VAULT` and `NEW_SBT` set to those values and
`NEW_SIGNER` set to the new grant-signer address (the `owner()` you just checked). It reads
the new private key on STDIN only (never argv or a log), patches the env file atomically, recreates the
container (a plain `docker restart` does not re-read `--env-file`), and asserts that `/health` reports
the new signer and both contracts. Run it only after the new contracts have code and the new signer is
funded. Key handling for the STDIN pipe is covered in the private operator runbook.

## Dual-control (documented follow-up)
Beta runs single-operator with the daily cap. To require a second approver, extend
`/v1/sign` to demand an `X-Approval` HMAC from a second operator key before broadcasting
grants over a threshold. Tracked as the D2.4 hardening item.
