/**
 * Treasury signer worker — the DROPLET signing path for the Phase-D money flow
 * (CORE-S5.5 / D2.4, @rule8). Holds the vault/SBT OWNER key (the deterministic
 * treasury/grant signer) and performs the two onlyOwner grant writes the
 * core-membership orchestrator cannot make from Vercel (key NEVER on Vercel).
 *
 * Implements the membership team's API contract (handoffs/PHASE_D_DGX_OPERATOR_HANDOFF
 * appendix 2026-07-15). ONE endpoint does the legs, idempotent by orderId +
 * on-chain guards; the service hashes the raw sub itself and clamps the amount.
 *
 * ## Staking model (bond-clone — canonical, owner decision 2026-08-05)
 * This REVERSES ADR-2026-07-27 (EOA-direct self-bond). The 32k does NOT go to the
 * member's EOA. It is placed into the member's per-member `MemberBond` clone via
 * `MembershipStakeVault.grant(member, amount, memberTokenId)` (payable; the clone is
 * deployed + funded in that one call). The clone — not the member — later becomes the
 * `ValidatorRegistry` staker when the member calls `MemberBond.activate(pubkey, sig)`
 * app-side once their node is synced. This structurally avoids the permanent
 * `StakerHasValidator()` lock the old EOA path hit, and keeps the principal in a
 * real, member-only-withdrawable contract rather than an unspendable predicted EOA.
 * See .agentile/sprints/active/sprint-validator-bond-clone (citrate-core) WI-1.
 *
 * Legs (leg order flipped — grant needs the SBT tokenId, so mint first):
 *   1. sbt.mintMember(member, subHash, termStart, termEnd)  — skip if sub already bound.
 *   2. vault.grant{value: amount}(member, amount, memberTokenId) — deploy + FUND the
 *      MemberBond clone. Skip if the clone already has code (`BondExists`).
 *   3. gas top-up: native SALT to the member EOA so it can pay for its own
 *      `MemberBond.activate` tx (the clone is `onlyMember`, sent FROM the EOA). This
 *      is GAS ONLY (GAS_HEADROOM) — never the bond, which already lives in the clone.
 *
 * Security posture (@rule8):
 *   - Signing key only in this process env (TREASURY_SIGNER_KEY), on an operator
 *     droplet, never in the repo/Vercel. Bearer auth on every call.
 *   - Hard allowlist: only the two pinned contracts (vault + sbt).
 *   - amountWei CLAMPED to TREASURY_GRANT_WEI (never trust the caller).
 *   - Per-UTC-day SALT cap + orderId idempotency ledger, persisted to disk.
 *   - Signs → broadcasts → waits for inclusion → returns the REAL hash. Never a
 *     fabricated hash; a skipped leg returns null.
 *
 * HTTP:
 *   GET  /health                         -> { status, signer, day, spentToday, dailyCap, vault, sbt }
 *   POST /grant   (Authorization: Bearer <TREASURY_SIGNER_TOKEN>)
 *     body { orderId, sub, member, amountWei, termStart, termEnd, chainId, contracts:{vault,sbt} }
 *     200  { orderId, fundTxHash|null, vaultTxHash|null, sbtTxHash|null, sbtTokenId|null, status:"granted"|"already_granted" }
 *          (vaultTxHash = the vault.grant that deploys+funds the MemberBond clone;
 *           fundTxHash  = the gas-only top-up to the member EOA for its activate tx.)
 *     401 auth · 403 cap · 409 orderId in-flight · 422 validation/allowlist · 503 not ready · 5xx broadcast
 */
import { createServer } from "node:http";
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import {
  createWalletClient, createPublicClient, http, defineChain,
  encodeFunctionData, getAddress, isAddress, keccak256, toHex, toEventSelector, hexToBigInt,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { timingSafeEqual, createHash } from "node:crypto";

const need = (k) => { const v = process.env[k]; if (!v || !v.trim()) throw new Error(`${k} is required`); return v.trim(); };

const RPC_URL = need("CITRATE_RPC_URL");
const CHAIN_ID = Number(process.env.CITRATE_CHAIN_ID ?? "40204");
const VAULT = getAddress(need("MEMBERSHIP_STAKE_VAULT_ADDRESS"));
const SBT = getAddress(need("CITRATE_MEMBER_SBT_ADDRESS"));
const TOKEN = need("TREASURY_SIGNER_TOKEN");
// Zero-downtime rotation: during a rotation, set TREASURY_SIGNER_TOKEN to the NEW
// value and TREASURY_SIGNER_TOKEN_PREV to the OLD one; BOTH authorize until every
// caller (core-membership on Vercel) has redeployed with the new token, then clear
// _PREV. Optional — unset means only the current token is accepted.
const TOKEN_PREV = (process.env.TREASURY_SIGNER_TOKEN_PREV ?? "").trim();
// Pre-hash the accepted `Bearer <token>` header values to a FIXED 32-byte digest.
// The compare is then constant-time (timingSafeEqual on equal-length buffers, which
// also avoids the length-mismatch throw that a raw compare would leak) and does not
// reveal token length or WHICH token matched (all candidates are always checked).
const sha256 = (s) => createHash("sha256").update(String(s), "utf8").digest();
const ACCEPTED = [TOKEN, TOKEN_PREV].filter((t) => t.length > 0).map((t) => sha256(`Bearer ${t}`));
function authorized(header) {
  const got = sha256(String(header ?? ""));
  let ok = false;
  for (const exp of ACCEPTED) { if (timingSafeEqual(got, exp)) ok = true; } // no early break — constant work
  return ok;
}
const GRANT_WEI = BigInt(process.env.TREASURY_GRANT_WEI ?? String(32_000n * 10n ** 18n)); // policy grant / clamp ceiling
const DAILY_CAP = BigInt(process.env.TREASURY_DAILY_CAP_WEI ?? String(96_000n * 10n ** 18n));
// Bond-clone model (2026-08-05): the 32k bond goes INTO the member's MemberBond clone
// via vault.grant{value: 32k}. The member still sends their own `MemberBond.activate`
// tx (the clone is onlyMember), which needs a little native SALT for gas. GAS_HEADROOM
// is that gas-only cushion to the member EOA (default 0.05 SALT). It is NOT the bond.
const GAS_HEADROOM = BigInt(process.env.TREASURY_GAS_HEADROOM_WEI ?? String(5n * 10n ** 16n));
const ZERO_BYTECODE = "0x";
const PORT = Number(process.env.PORT ?? "8790");
const STATE_FILE = process.env.TREASURY_STATE_FILE ?? "/var/lib/citrate-treasury-signer/state.json";

const account = privateKeyToAccount((need("TREASURY_SIGNER_KEY").startsWith("0x") ? "" : "0x") + need("TREASURY_SIGNER_KEY"));
const chain = defineChain({ id: CHAIN_ID, name: "Citrate", nativeCurrency: { name: "SALT", symbol: "SALT", decimals: 18 }, rpcUrls: { default: { http: [RPC_URL] } } });
const publicClient = createPublicClient({ chain, transport: http(RPC_URL) });
const walletClient = createWalletClient({ account, chain, transport: http(RPC_URL) });

const VAULT_ABI = [
  // Bond-clone grant: payable, msg.value == amount, deploys + funds the member's
  // MemberBond clone (does NOT stake — MemberBond.activate does, member-side).
  { type: "function", name: "grant", stateMutability: "payable", inputs: [{ name: "member", type: "address" }, { name: "amount", type: "uint256" }, { name: "memberTokenId", type: "uint256" }], outputs: [{ name: "grantId", type: "uint256" }] },
  // Predicted (CREATE2) address of the member's bond clone. Non-empty code at this
  // address == the clone is deployed == already granted (the durable idempotency guard).
  { type: "function", name: "bondOf", stateMutability: "view", inputs: [{ name: "member", type: "address" }], outputs: [{ name: "", type: "address" }] },
];
const SBT_ABI = [
  { type: "function", name: "mintMember", stateMutability: "nonpayable", inputs: [{ name: "to", type: "address" }, { name: "subHash", type: "bytes32" }, { name: "termStart", type: "uint64" }, { name: "termEnd", type: "uint64" }], outputs: [{ name: "tokenId", type: "uint256" }] },
  { type: "function", name: "isSubBound", stateMutability: "view", inputs: [{ name: "subHash", type: "bytes32" }], outputs: [{ name: "", type: "bool" }] },
  // Look up the tokenId bound to a subHash (reverts UnknownSub for unbound). Used on a
  // retry where the SBT was already minted so we can still pass grant's memberTokenId.
  { type: "function", name: "tokenIdForSub", stateMutability: "view", inputs: [{ name: "subHash", type: "bytes32" }], outputs: [{ name: "", type: "uint256" }] },
];
const TRANSFER_TOPIC = toEventSelector("Transfer(address,address,uint256)");

// ---- persisted daily-cap + orderId idempotency ledger ------------------------
function loadState() { try { if (existsSync(STATE_FILE)) return JSON.parse(readFileSync(STATE_FILE, "utf8")); } catch {} return { day: "", spentToday: "0", orders: {} }; }
function saveState(s) { mkdirSync(dirname(STATE_FILE), { recursive: true }); writeFileSync(STATE_FILE, JSON.stringify(s), "utf8"); }
let state = loadState();
const utcDay = () => new Date().toISOString().slice(0, 10);
function rollDay() { const d = utcDay(); if (state.day !== d) { state.day = d; state.spentToday = "0"; saveState(state); } }
// Charge `wei` against the per-UTC-day cap, or throw 403. Callers roll the day first.
function chargeDailyCap(wei) {
  const spent = BigInt(state.spentToday);
  if (spent + wei > DAILY_CAP) throw new HttpError(403, `daily cap exceeded: ${spent + wei} > ${DAILY_CAP}`);
  state.spentToday = String(spent + wei); saveState(state);
}

function json(res, code, obj) { const b = JSON.stringify(obj); res.writeHead(code, { "content-type": "application/json", "content-length": Buffer.byteLength(b) }); res.end(b); }
function readBody(req) { return new Promise((resolve, reject) => { let b = "", n = 0; req.on("data", (c) => { n += c.length; if (n > 16_384) { reject(new Error("body too large")); req.destroy(); } b += c; }); req.on("end", () => resolve(b)); req.on("error", reject); }); }

class HttpError extends Error { constructor(code, msg) { super(msg); this.code = code; } }

async function handleGrant(body) {
  const { orderId, sub, member, amountWei, termStart, termEnd, chainId, contracts } = body ?? {};
  // ---- validation (422) ----
  if (!orderId || typeof orderId !== "string") throw new HttpError(422, "orderId required");
  if (!sub || typeof sub !== "string") throw new HttpError(422, "sub required");
  if (!isAddress(member, { strict: false })) throw new HttpError(422, "member must be an address");
  if (Number(chainId) !== CHAIN_ID) throw new HttpError(422, `chainId must be ${CHAIN_ID}`);
  const ts = BigInt(termStart ?? 0), te = BigInt(termEnd ?? 0);
  if (te <= ts) throw new HttpError(422, "termEnd must be > termStart");
  if (!contracts || getAddress(contracts.vault) !== VAULT || getAddress(contracts.sbt) !== SBT) throw new HttpError(422, "contracts not on allowlist");
  // clamp amount to policy (never trust the caller)
  let amount = GRANT_WEI;
  try { if (amountWei != null) amount = BigInt(amountWei) < GRANT_WEI ? BigInt(amountWei) : GRANT_WEI; } catch { throw new HttpError(422, "amountWei invalid"); }
  if (amount <= 0n) throw new HttpError(422, "amountWei must be > 0");

  // ---- idempotency by orderId (409 in-flight, replay returns prior) ----
  const prior = state.orders[orderId];
  if (prior?.done) return prior.result;
  if (prior?.inflight) throw new HttpError(409, "orderId in-flight");
  state.orders[orderId] = { inflight: true }; saveState(state);

  try {
    const m = getAddress(member);
    const subHash = keccak256(toHex(sub));
    let fundTxHash = null, vaultTxHash = null, sbtTxHash = null, sbtTokenId = null;

    // ---- Leg 1: sbt.mintMember (FIRST — vault.grant needs the tokenId) ----
    // The SBT enforces uniqueness per subHash, so isSubBound is the durable guard.
    const bound = await publicClient.readContract({ address: SBT, abi: SBT_ABI, functionName: "isSubBound", args: [subHash] });
    if (!bound) {
      const data = encodeFunctionData({ abi: SBT_ABI, functionName: "mintMember", args: [m, subHash, ts, te] });
      const hash = await walletClient.sendTransaction({ to: SBT, data });
      const rcpt = await publicClient.waitForTransactionReceipt({ hash });
      if (rcpt.status !== "success") throw new HttpError(502, `sbt.mintMember reverted in ${hash}`);
      sbtTxHash = hash;
      // real tokenId from the ERC-721 Transfer(from=0x0, to=member) log
      const log = rcpt.logs.find((l) => getAddress(l.address) === SBT && l.topics[0] === TRANSFER_TOPIC);
      if (log && log.topics[3]) sbtTokenId = hexToBigInt(log.topics[3]).toString();
    }
    // Resolve the tokenId whether we just minted or the sub was already bound (retry).
    // grant reverts NotTheMembersToken() unless sbt.ownerOf(memberTokenId) == member,
    // so we MUST pass the real token id.
    if (sbtTokenId == null) {
      const tid = await publicClient.readContract({ address: SBT, abi: SBT_ABI, functionName: "tokenIdForSub", args: [subHash] });
      sbtTokenId = tid.toString();
    }
    const memberTokenId = BigInt(sbtTokenId);

    // ---- Leg 2: vault.grant (deploy + FUND the member's MemberBond clone) ----
    // The 32k goes into the clone as msg.value; it does NOT stake yet (the member's
    // own MemberBond.activate does that once the node is synced). Durable idempotency:
    // bondOf(member) has non-empty code == BondExists == already granted.
    const bond = await publicClient.readContract({ address: VAULT, abi: VAULT_ABI, functionName: "bondOf", args: [m] });
    const bondCode = await publicClient.getBytecode({ address: bond });
    const bondExists = bondCode != null && bondCode !== ZERO_BYTECODE;
    if (!bondExists) {
      rollDay();
      chargeDailyCap(amount);
      const data = encodeFunctionData({ abi: VAULT_ABI, functionName: "grant", args: [m, amount, memberTokenId] });
      const hash = await walletClient.sendTransaction({ to: VAULT, data, value: amount });
      const rcpt = await publicClient.waitForTransactionReceipt({ hash });
      if (rcpt.status !== "success") throw new HttpError(502, `vault.grant reverted in ${hash}`);
      vaultTxHash = hash;
    }

    // ---- Leg 3: gas top-up (member sends MemberBond.activate itself) ----
    // The clone is onlyMember, so activate is sent FROM the member EOA, which needs a
    // little native SALT for gas. The 32k already lives in the clone, so this is GAS
    // ONLY — never the bond. Balance-gated, idempotent, bounded by GAS_HEADROOM.
    const bal = await publicClient.getBalance({ address: m });
    if (bal < GAS_HEADROOM) {
      rollDay();
      const topUp = GAS_HEADROOM - bal;   // top up only the shortfall
      chargeDailyCap(topUp);
      const hash = await walletClient.sendTransaction({ to: m, value: topUp });
      const rcpt = await publicClient.waitForTransactionReceipt({ hash });
      if (rcpt.status !== "success") throw new HttpError(502, `gas top-up reverted in ${hash}`);
      fundTxHash = hash;
    }

    // "granted" iff a money leg (grant or SBT mint) actually broadcast this call; a
    // gas-only top-up on an otherwise-complete order is still an idempotent replay.
    const result = { orderId, fundTxHash, vaultTxHash, sbtTxHash, sbtTokenId, status: (vaultTxHash || sbtTxHash) ? "granted" : "already_granted" };
    state.orders[orderId] = { done: true, result }; saveState(state);
    return result;
  } catch (err) {
    delete state.orders[orderId]; saveState(state); // release so the order stays re-triable
    throw err;
  }
}

const server = createServer(async (req, res) => {
  try {
    if (req.method === "GET" && req.url === "/health") {
      rollDay();
      return json(res, 200, { status: "ok", signer: account.address, day: state.day, spentToday: state.spentToday, dailyCap: String(DAILY_CAP), grantWei: String(GRANT_WEI), gasHeadroomWei: String(GAS_HEADROOM), vault: VAULT, sbt: SBT,
      // Bond-clone model: idempotency for the grant leg is the durable on-chain
      // BondExists check (bondOf(member) has code), so there is no weaker fallback
      // mode to surface — the SBT (isSubBound) and bond (code) guards are both durable.
      model: "bond-clone" });
    }
    if (req.method === "POST" && req.url === "/grant") {
      if (!authorized(req.headers["authorization"])) return json(res, 401, { error: "unauthorized" });
      let body; try { body = JSON.parse((await readBody(req)) || "{}"); } catch { return json(res, 422, { error: "invalid json" }); }
      const result = await handleGrant(body);
      return json(res, 200, result);
    }
    return json(res, 404, { error: "not found" });
  } catch (err) {
    if (err instanceof HttpError) return json(res, err.code, { error: err.message });
    return json(res, 502, { error: String(err?.message ?? err) });
  }
});
// Bind 0.0.0.0 INSIDE the container; host isolation is the Docker port map
// (127.0.0.1:8790:8790) + Caddy TLS + bearer auth.
server.listen(PORT, "0.0.0.0", () => {
  // eslint-disable-next-line no-console
  console.log(`citrate-treasury-signer on :${PORT} signer=${account.address} vault=${VAULT} sbt=${SBT} grantWei=${GRANT_WEI} dailyCap=${DAILY_CAP} model=bond-clone`);
});
