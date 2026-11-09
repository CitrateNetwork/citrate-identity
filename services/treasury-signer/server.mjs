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
 *   - Per-UTC-day SALT cap + orderId idempotency ledger, persisted to disk. The
 *     ledger is keyed by chain generation (`<genesis>/<orderId>`), so a result
 *     recorded on an earlier generation is never replayed on this one (#70 P1-1).
 *   - Chain-generation pin (#70 P1-2): r1005 and r1006 share chainId 40204, so the
 *     caller sends `expectedGenesis` and the signer compares it with the block-0
 *     hash of ITS OWN RPC, at request start, before every broadcast, after every
 *     receipt (a flip there raises an ALARM log line and fails the request), and
 *     once more after all grant-state reads, before success is recorded.
 *     Missing/malformed → 422, different → 412, lookup failure → 503. Nothing is
 *     read or sent on a refusal. Block 0 is fetched per check, never cached.
 *   - Signs → broadcasts → waits for inclusion → returns the REAL hash. Never a
 *     fabricated hash; a skipped leg returns null.
 *
 * HTTP:
 *   GET  /health                         -> { status, signer, day, spentToday, dailyCap, vault, sbt }
 *   POST /grant   (Authorization: Bearer <TREASURY_SIGNER_TOKEN>)
 *     body { orderId, sub, member, amountWei, termStart, termEnd, chainId, contracts:{vault,sbt}, expectedGenesis }
 *     200  { orderId, fundTxHash|null, vaultTxHash|null, sbtTxHash|null, sbtTokenId|null, status:"granted"|"already_granted", genesis }
 *          (vaultTxHash = the vault.grant that deploys+funds the MemberBond clone;
 *           fundTxHash  = the gas-only top-up to the member EOA for its activate tx.)
 *     401 auth · 403 cap · 409 orderId in-flight · 412 genesis mismatch · 422 validation/allowlist
 *     503 not ready / genesis lookup failed · 5xx broadcast
 *   POST /kyc-attest   (same bearer) — scoped KYC attestation, see handleKycAttest
 *     body { member, sub, chainId, contracts:{sbt}, expectedGenesis }   (nothing else)
 *     The signer re-reads identity's stored record (GET <KYC_STATUS_URL>/kyc/status) and
 *     can send only CitrateMemberSBT.setKycVerified(tokenId, true) for the token bound to
 *     keccak256(sub) and owned by `member`. Own daily count cap, idempotent, audit JSONL
 *     with the subject hash only, disabled (503) unless KYC_STATUS_URL + _SECRET are set.
 *     200  { status:"attested"|"already_attested", txHash|null, tokenId, subHash, genesis }
 */
import { createServer } from "node:http";
import { readFileSync, existsSync, mkdirSync, openSync, writeSync, fsyncSync, closeSync, renameSync, unlinkSync } from "node:fs";
import { dirname, join } from "node:path";
import {
  createWalletClient, createPublicClient, http, defineChain,
  encodeFunctionData, getAddress, isAddress, keccak256, toHex, toEventSelector, hexToBigInt, decodeEventLog,
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

// ---- /kyc-attest config (scoped KYC attestation) ------------------------------
// The signer re-reads the subject's STORED verification record from identity itself:
// GET <KYC_STATUS_URL>/kyc/status?sub=<sub>, Authorization: Bearer <KYC_STATUS_SECRET>.
// Both unset (or an unusable URL) leaves /kyc-attest disabled (503) and /grant as is.
// The URL must be https, or plain http only to loopback or a single-label in-network
// host (a compose service name such as `identity`), so the secret never crosses a
// public network in clear.
function kycStatusConfig() {
  const raw = (process.env.KYC_STATUS_URL ?? "").trim();
  const secret = (process.env.KYC_STATUS_SECRET ?? "").trim();
  if (!raw || !secret) return { enabled: false, why: "KYC_STATUS_URL / KYC_STATUS_SECRET unset" };
  let u;
  try { u = new URL(raw); } catch { return { enabled: false, why: "KYC_STATUS_URL is not a URL" }; }
  const host = u.hostname.replace(/^\[|\]$/g, "");
  const local = host === "localhost" || host === "::1" || /^127\.\d+\.\d+\.\d+$/.test(host) || (host.length > 0 && !host.includes(".") && !host.includes(":"));
  if (!(u.protocol === "https:" || (u.protocol === "http:" && local))) return { enabled: false, why: "KYC_STATUS_URL must be https (http only to loopback or an in-network host)" };
  if (u.username || u.password || u.search || u.hash) return { enabled: false, why: "KYC_STATUS_URL must be a plain base URL" };
  return { enabled: true, base: raw.replace(/\/+$/, ""), secret };
}
const KYC_STATUS = kycStatusConfig();
const KYC_STATUS_TIMEOUT_MS = Math.max(100, Number(process.env.KYC_STATUS_TIMEOUT_MS ?? "10000") || 10000);
// Attestations per UTC day (a count, not SALT: setKycVerified moves no value). An
// unparsable value is 0, which refuses every attestation (fail closed).
const KYC_ATTEST_DAILY_CAP = (() => {
  const v = (process.env.KYC_ATTEST_DAILY_CAP ?? "20").trim();
  return /^\d{1,6}$/.test(v) ? Number(v) : 0;
})();
// Append-only audit trail, next to the state file by default (same volume). Records
// carry the subject HASH, token id, tx hash, generation and outcome; never the sub,
// the wallet, a token or a secret.
const KYC_AUDIT_FILE = process.env.KYC_ATTEST_AUDIT_FILE ?? join(dirname(STATE_FILE), "kyc-attest-audit.jsonl");

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
// /kyc-attest: the reads it needs and the ONE write it can make. setKycVerified is
// encoded only with the literal `true` (see attestTx), never from caller input.
const SBT_KYC_ABI = [
  { type: "function", name: "getMember", stateMutability: "view", inputs: [{ name: "tokenId", type: "uint256" }], outputs: [{ name: "", type: "tuple", components: [
    { name: "subHash", type: "bytes32" }, { name: "termStart", type: "uint64" }, { name: "termEnd", type: "uint64" },
    { name: "quarantined", type: "bool" }, { name: "revoked", type: "bool" }, { name: "kycVerified", type: "bool" },
  ] }] },
  { type: "function", name: "ownerOf", stateMutability: "view", inputs: [{ name: "tokenId", type: "uint256" }], outputs: [{ name: "", type: "address" }] },
  { type: "function", name: "setKycVerified", stateMutability: "nonpayable", inputs: [{ name: "tokenId", type: "uint256" }, { name: "verified", type: "bool" }], outputs: [] },
  { type: "event", name: "KycVerifiedSet", inputs: [{ name: "tokenId", type: "uint256", indexed: true }, { name: "verified", type: "bool", indexed: false }] },
];

// ---- persisted daily-cap + orderId idempotency ledger ------------------------
// The state file holds the caps and the idempotency ledger. A missing file is a fresh
// signer; an unreadable one REFUSES start-up (silently resetting it would reopen the
// caps and forget completed orders). Writes are atomic: temp file, fsync, rename.
function loadState() {
  if (!existsSync(STATE_FILE)) return { day: "", spentToday: "0", orders: {} };
  let s;
  try { s = JSON.parse(readFileSync(STATE_FILE, "utf8")); } catch (e) { throw new Error(`state file unreadable (${e?.name ?? "error"})`); }
  if (!s || typeof s !== "object" || Array.isArray(s) || typeof s.orders !== "object" || s.orders === null || typeof s.spentToday !== "string" || !/^\d+$/.test(s.spentToday)) {
    throw new Error("state file unreadable (unexpected shape)");
  }
  return s;
}
function saveState(s) {
  mkdirSync(dirname(STATE_FILE), { recursive: true });
  const tmp = `${STATE_FILE}.tmp-${process.pid}`;
  const fd = openSync(tmp, "w", 0o600);
  try { writeSync(fd, JSON.stringify(s)); fsyncSync(fd); } finally { closeSync(fd); }
  try { renameSync(tmp, STATE_FILE); } catch (e) { try { unlinkSync(tmp); } catch {} throw e; }
  try { const dfd = openSync(dirname(STATE_FILE), "r"); try { fsyncSync(dfd); } finally { closeSync(dfd); } } catch {} // best effort
}
let state;
try { state = loadState(); } catch (e) {
  // eslint-disable-next-line no-console
  console.error(`citrate-treasury-signer: ${e.message}: ${STATE_FILE}. Refusing to start; restore it or move it aside deliberately.`);
  process.exit(1);
}
const utcDay = () => new Date().toISOString().slice(0, 10);
function rollDay() { const d = utcDay(); if (state.day !== d) { state.day = d; state.spentToday = "0"; saveState(state); } }
// Charge `wei` against the per-UTC-day cap, or throw 403. Callers roll the day first.
function chargeDailyCap(wei) {
  const spent = BigInt(state.spentToday);
  if (spent + wei > DAILY_CAP) throw new HttpError(403, `daily cap exceeded: ${spent + wei} > ${DAILY_CAP}`);
  state.spentToday = String(spent + wei); saveState(state);
  return state.day;
}
// Give `wei` back when the send it was charged for never reached the chain (see
// sendAndConfirm's `broadcast` flag). Only within the same UTC day it was charged.
function refundDailyCap(wei, day) {
  if (state.day !== day) return;
  const spent = BigInt(state.spentToday);
  state.spentToday = String(spent > wei ? spent - wei : 0n); saveState(state);
}
// A charged leg: refund the cap iff the tx was certainly never broadcast.
async function chargedSend(wei, run) {
  const day = chargeDailyCap(wei);
  try { return await run(); } catch (e) { if (e?.broadcast === false) refundDailyCap(wei, day); throw e; }
}
// chainId: the integer, or its exact decimal string. Nothing else ("0x9d0c", [40204],
// " 40204", 40204.5 and true all used to pass Number()).
function chainIdOk(v) {
  if (typeof v === "number") return Number.isSafeInteger(v) && v === CHAIN_ID;
  if (typeof v === "string") return /^[1-9][0-9]{0,15}$/.test(v) && Number(v) === CHAIN_ID;
  return false;
}

function json(res, code, obj) { const b = JSON.stringify(obj); res.writeHead(code, { "content-type": "application/json", "content-length": Buffer.byteLength(b) }); res.end(b); }
function readBody(req) { return new Promise((resolve, reject) => { let b = "", n = 0; req.on("data", (c) => { n += c.length; if (n > 16_384) { reject(new Error("body too large")); req.destroy(); } b += c; }); req.on("end", () => resolve(b)); req.on("error", reject); }); }

class HttpError extends Error { constructor(code, msg) { super(msg); this.code = code; } }

// ---- chain-generation pin (#70 P1-2) ----------------------------------------
const GENESIS_RE = /^0x[0-9a-fA-F]{64}$/;
// Neutral refusal log: a reason code and a reference only (never sub, key, token).
// `ctx` names the route and its reference: /grant logs the order id, /kyc-attest the
// subject hash. A bare string is an order id (the /grant call sites).
const logCtx = (ctx) => (typeof ctx === "object" && ctx ? ctx : { what: "grant", key: "order", ref: ctx });
function refuse(code, reason, ctx) {
  const c = logCtx(ctx);
  // eslint-disable-next-line no-console
  console.warn(`${c.what} refused: ${reason} ${c.key}=${String(c.ref).slice(0, 80)}`);
  return new HttpError(code, reason);
}
// The block-0 hash of THIS signer's RPC, lower-cased. Fetched on every call (no
// cache): the RPC behind a fixed URL can move to a new generation, as rpc.citrate.ai
// did at the r1006 cutover.
async function ownGenesis(ctx) {
  let hash;
  try { hash = (await publicClient.getBlock({ blockNumber: 0n })).hash; } catch { throw refuse(503, "genesis_lookup_failed", ctx); }
  if (typeof hash !== "string" || !GENESIS_RE.test(hash)) throw refuse(503, "genesis_lookup_failed", ctx);
  return hash.toLowerCase();
}
async function requireGenesis(expected, ctx) {
  const own = await ownGenesis(ctx);
  if (own !== expected) throw refuse(412, "genesis_mismatch", ctx);
  return own;
}
// Every send from the signing key goes through ONE process-wide queue. /grant legs and
// /kyc-attest share the key; without the queue, two requests read the same pending
// nonce and one of the sends is lost (or replaces the other). A send holds the queue
// from its pre-send generation check until its receipt (or the receipt timeout), so the
// next send always reads a nonce that already counts it.
let sendQueue = Promise.resolve();
function withSendLock(fn) {
  const run = sendQueue.then(fn, fn);
  sendQueue = run.then(() => {}, () => {});
  return run;
}
const RECEIPT_TIMEOUT_MS = Math.max(1000, Number(process.env.TREASURY_RECEIPT_TIMEOUT_MS ?? "120000") || 120000);
// Did a failed sendTransaction certainly not reach the node? An explicit RPC rejection
// or a failure while preparing the tx: yes. A transport error or timeout: unknown, so
// treated as broadcast (no cap refund, may-have-landed).
function certainlyNotBroadcast(e) {
  let ambiguous = false;
  const visit = (x) => { if (x && (x.name === "HttpRequestError" || x.name === "TimeoutError" || x.name === "SocketClosedError")) ambiguous = true; };
  if (typeof e?.walk === "function") e.walk((x) => { visit(x); return false; }); else visit(e);
  visit(e);
  return !ambiguous;
}
const flagBroadcast = (e, broadcast) => { const err = e instanceof Error ? e : new Error(String(e)); err.broadcast = broadcast; return err; };

// Pinned, serialized broadcast, shared by /grant and /kyc-attest. The generation is
// re-checked before the send and after the receipt. The pre-send check and the
// broadcast are separate RPC calls, and a 40204 tx is valid on either generation, so a
// flip in between would land the tx on the wrong chain. That cannot be undone here:
// raise an ALARM for the operator and fail the request (502), so nothing is recorded
// done and the caller keeps its may-have-landed marker. The receipt must be for OUR
// hash: viem resolves with a replacement's receipt when a same-nonce tx replaced ours,
// and that is a failure (ALARM tx_replaced), never a success.
// Resolves { hash, rcpt }. A thrown error carries `broadcast`: false only when no tx
// can have reached the chain (callers refund their cap on that alone).
function pinnedSender(expected, ctx) {
  const c = logCtx(ctx);
  const ref = () => `${c.key}=${String(c.ref).slice(0, 80)}`;
  const sendAndConfirm = (tx) => withSendLock(async () => {
    let hash;
    try {
      await requireGenesis(expected, ctx);
    } catch (e) { throw flagBroadcast(e, false); }
    try {
      hash = await walletClient.sendTransaction(tx);
    } catch (e) { throw flagBroadcast(e, !certainlyNotBroadcast(e)); }
    try {
      const rcpt = await publicClient.waitForTransactionReceipt({ hash, timeout: RECEIPT_TIMEOUT_MS });
      if (String(rcpt.transactionHash).toLowerCase() !== String(hash).toLowerCase()) {
        // eslint-disable-next-line no-console
        console.error(`ALARM tx_replaced ${ref()} tx=${hash} replacement=${rcpt.transactionHash}`);
        throw new HttpError(502, "tx_replaced");
      }
      const own = await ownGenesis(ctx);
      if (own !== expected) {
        // eslint-disable-next-line no-console
        console.error(`ALARM genesis_changed_after_broadcast ${ref()} tx=${hash}`);
        throw new HttpError(502, "genesis_changed_after_broadcast");
      }
      return { hash, rcpt };
    } catch (e) { const err = flagBroadcast(e, true); err.txHash = hash; throw err; }
  });
  return { sendAndConfirm };
}

async function handleGrant(body) {
  const { orderId, sub, member, amountWei, termStart, termEnd, chainId, contracts, expectedGenesis } = body ?? {};
  // ---- validation (422) ----
  if (!orderId || typeof orderId !== "string") throw new HttpError(422, "orderId required");
  if (!sub || typeof sub !== "string") throw new HttpError(422, "sub required");
  if (!isAddress(member, { strict: false })) throw new HttpError(422, "member must be an address");
  if (!chainIdOk(chainId)) throw new HttpError(422, `chainId must be ${CHAIN_ID}`);
  const ts = BigInt(termStart ?? 0), te = BigInt(termEnd ?? 0);
  if (te <= ts) throw new HttpError(422, "termEnd must be > termStart");
  if (!contracts || getAddress(contracts.vault) !== VAULT || getAddress(contracts.sbt) !== SBT) throw new HttpError(422, "contracts not on allowlist");
  // clamp amount to policy (never trust the caller)
  let amount = GRANT_WEI;
  try { if (amountWei != null) amount = BigInt(amountWei) < GRANT_WEI ? BigInt(amountWei) : GRANT_WEI; } catch { throw new HttpError(422, "amountWei invalid"); }
  if (amount <= 0n) throw new HttpError(422, "amountWei must be > 0");
  if (typeof expectedGenesis !== "string" || !GENESIS_RE.test(expectedGenesis)) throw refuse(422, "genesis_missing_or_malformed", orderId);
  const expected = expectedGenesis.toLowerCase();

  // ---- chain-generation pin, BEFORE any ledger replay or grant-state read ----
  const genesis = await requireGenesis(expected, orderId);

  // ---- idempotency by (generation, orderId) (409 in-flight, replay returns prior) ----
  // A pre-reroll entry (plain orderId key, or another generation's key) never
  // matches, so its old tx hashes are never handed back as a grant on this chain.
  const key = `${genesis}/${orderId}`;
  const prior = state.orders[key];
  if (prior?.done) return prior.result;
  if (prior?.inflight) throw new HttpError(409, "orderId in-flight");
  state.orders[key] = { inflight: true }; saveState(state);
  // Every broadcast re-checks the generation before sending and after the receipt.
  const { sendAndConfirm } = pinnedSender(expected, orderId);

  try {
    const m = getAddress(member);
    const subHash = keccak256(toHex(sub));
    let fundTxHash = null, vaultTxHash = null, sbtTxHash = null, sbtTokenId = null;

    // ---- Leg 1: sbt.mintMember (FIRST — vault.grant needs the tokenId) ----
    // The SBT enforces uniqueness per subHash, so isSubBound is the durable guard.
    const bound = await publicClient.readContract({ address: SBT, abi: SBT_ABI, functionName: "isSubBound", args: [subHash] });
    if (!bound) {
      const data = encodeFunctionData({ abi: SBT_ABI, functionName: "mintMember", args: [m, subHash, ts, te] });
      const { hash, rcpt } = await sendAndConfirm({ to: SBT, data });
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
      const data = encodeFunctionData({ abi: VAULT_ABI, functionName: "grant", args: [m, amount, memberTokenId] });
      const { hash, rcpt } = await chargedSend(amount, () => sendAndConfirm({ to: VAULT, data, value: amount }));
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
      const { hash, rcpt } = await chargedSend(topUp, () => sendAndConfirm({ to: m, value: topUp }));
      if (rcpt.status !== "success") throw new HttpError(502, `gas top-up reverted in ${hash}`);
      fundTxHash = hash;
    }

    // Re-check the generation AFTER every grant-state read and BEFORE recording success.
    // When every leg skips, no sendAndConfirm() check ran, and a skip decided by state
    // read from another generation (where this member is already granted) would
    // otherwise be recorded as done under this generation's ledger key.
    await requireGenesis(expected, orderId);

    // "granted" iff a money leg (grant or SBT mint) actually broadcast this call; a
    // gas-only top-up on an otherwise-complete order is still an idempotent replay.
    const result = { orderId, fundTxHash, vaultTxHash, sbtTxHash, sbtTokenId, status: (vaultTxHash || sbtTxHash) ? "granted" : "already_granted", genesis };
    state.orders[key] = { done: true, result }; saveState(state);
    return result;
  } catch (err) {
    delete state.orders[key]; saveState(state); // release so the order stays re-triable
    throw err;
  }
}

// ---- POST /kyc-attest: scoped KYC attestation ---------------------------------
// After a re-roll the SBTs are re-minted with kycVerified = false, and only the SBT
// owner (this key) can set it. This route can do exactly one thing: call
// CitrateMemberSBT.setKycVerified(tokenId, true) on the pinned SBT, for the token
// bound to keccak256(sub) and owned by `member`, and only when identity's STORED record
// for `sub` says verified right now. The caller supplies a subject and a wallet; it
// never supplies a verdict, a token id, a function, a value or calldata.
const KYC_BODY_KEYS = new Set(["member", "sub", "chainId", "contracts", "expectedGenesis"]);
const kycInflight = new Set(); // subHash; single process, so in-memory is the lock
function kycAudit(rec, durable) {
  const line = JSON.stringify({ ts: new Date().toISOString(), event: "kyc_attest", ...rec });
  // eslint-disable-next-line no-console
  console.log(`kyc-attest audit ${line}`);
  mkdirSync(dirname(KYC_AUDIT_FILE), { recursive: true });
  const fd = openSync(KYC_AUDIT_FILE, "a", 0o600);
  try { writeSync(fd, line + "\n"); if (durable) fsyncSync(fd); } finally { closeSync(fd); }
}
function kycAuditBestEffort(rec) {
  // eslint-disable-next-line no-console
  try { kycAudit(rec, false); } catch (e) { console.error(`kyc-attest audit write failed: ${e?.code ?? "error"}`); }
}
function kycCapToday() {
  const d = utcDay();
  if (!state.kycAttest || state.kycAttest.day !== d) state.kycAttest = { day: d, count: 0 };
  return state.kycAttest;
}
// The stored record, read by the signer itself. Anything but a 200 that names this
// subject with kyc_status "verified" refuses: not-verified is 403, unconfirmable 503.
async function requireStoredKycVerified(sub) {
  let res, j;
  try {
    res = await fetch(`${KYC_STATUS.base}/kyc/status?sub=${encodeURIComponent(sub)}`, {
      headers: { authorization: `Bearer ${KYC_STATUS.secret}`, accept: "application/json" },
      redirect: "error", signal: AbortSignal.timeout(KYC_STATUS_TIMEOUT_MS),
    });
    if (res.status !== 200) throw new Error(`status ${res.status}`);
    j = await res.json();
  } catch { throw new HttpError(503, "kyc_record_lookup_failed"); }
  if (!j || typeof j !== "object" || j.sub !== sub || typeof j.kyc_status !== "string") throw new HttpError(503, "kyc_record_lookup_failed");
  if (j.kyc_status !== "verified") throw new HttpError(403, "kyc_record_not_verified");
}
// The only transaction this route builds. Arguments: a token id read from the SBT, and
// the literal `true`.
const attestTx = (tokenId) => ({ to: SBT, value: 0n, data: encodeFunctionData({ abi: SBT_KYC_ABI, functionName: "setKycVerified", args: [tokenId, true] }) });

async function handleKycAttest(body) {
  const { member, sub, chainId, contracts, expectedGenesis } = body && typeof body === "object" ? body : {};
  const subOk = typeof sub === "string" && sub.length > 0 && sub.length <= 256;
  const subHash = subOk ? keccak256(toHex(sub)) : null;
  const ctx = { what: "kyc-attest", key: "subHash", ref: subHash };
  // Every request that passed auth leaves one result record (refusals included).
  const audit = { subHash, tokenId: null, genesis: null };
  try {
    if (!KYC_STATUS.enabled) throw new HttpError(503, "kyc_attest_unconfigured");
    // ---- validation (422), strict shape ----
    if (!body || typeof body !== "object" || Array.isArray(body)) throw new HttpError(422, "body must be an object");
    for (const k of Object.keys(body)) if (!KYC_BODY_KEYS.has(k)) throw new HttpError(422, "unexpected_field");
    if (!subOk) throw new HttpError(422, "sub required");
    if (typeof member !== "string" || !isAddress(member, { strict: false })) throw new HttpError(422, "member must be an address");
    if (!chainIdOk(chainId)) throw new HttpError(422, `chainId must be ${CHAIN_ID}`);
    if (!contracts || typeof contracts !== "object" || Object.keys(contracts).length !== 1 || typeof contracts.sbt !== "string" || !isAddress(contracts.sbt, { strict: false }) || getAddress(contracts.sbt) !== SBT) throw new HttpError(422, "contracts not on allowlist");
    if (typeof expectedGenesis !== "string" || !GENESIS_RE.test(expectedGenesis)) throw refuse(422, "genesis_missing_or_malformed", ctx);
    const expected = expectedGenesis.toLowerCase();
    // ---- chain-generation pin, BEFORE any lookup or read ----
    audit.genesis = await requireGenesis(expected, ctx);
    if (kycInflight.has(subHash)) throw new HttpError(409, "kyc_attest_in_flight");
    kycInflight.add(subHash);
    try {
      const result = await attestOne({ m: getAddress(member), sub, subHash, expected, ctx, audit });
      kycAuditBestEffort({ phase: "result", outcome: result.status, ...audit, txHash: result.txHash });
      return result;
    } finally { kycInflight.delete(subHash); }
  } catch (err) {
    const e = err instanceof HttpError ? err : new HttpError(502, "chain_error");
    kycAuditBestEffort({ phase: "result", outcome: "refused", reason: e.message, code: e.code, ...audit });
    throw e;
  }
}

async function attestOne({ m, sub, subHash, expected, ctx, audit }) {
  // ---- the stored record, re-checked here (never the caller's claim) ----
  await requireStoredKycVerified(sub);
  // ---- the token bound to this subject, owned by this wallet, in good standing ----
  const bound = await publicClient.readContract({ address: SBT, abi: SBT_ABI, functionName: "isSubBound", args: [subHash] });
  if (!bound) throw new HttpError(422, "sub_not_bound");
  const tokenId = await publicClient.readContract({ address: SBT, abi: SBT_ABI, functionName: "tokenIdForSub", args: [subHash] });
  audit.tokenId = tokenId.toString();
  const rec = await publicClient.readContract({ address: SBT, abi: SBT_KYC_ABI, functionName: "getMember", args: [tokenId] });
  if (String(rec.subHash).toLowerCase() !== subHash.toLowerCase()) throw new HttpError(502, "sbt_record_inconsistent");
  if (rec.revoked) throw new HttpError(422, "member_revoked");
  if (rec.quarantined) throw new HttpError(422, "member_quarantined");
  const owner = await publicClient.readContract({ address: SBT, abi: SBT_KYC_ABI, functionName: "ownerOf", args: [tokenId] });
  if (getAddress(owner) !== m) throw new HttpError(422, "member_mismatch");

  if (rec.kycVerified) {
    // Idempotent: already set, nothing to send. Re-check the generation before
    // answering, since the reads above may have come from another one.
    await requireGenesis(expected, ctx);
    return { status: "already_attested", txHash: null, tokenId: audit.tokenId, subHash, genesis: audit.genesis };
  }

  // ---- own daily cap (count), charged before the broadcast, persisted ----
  rollDay();
  const cap = kycCapToday();
  if (cap.count + 1 > KYC_ATTEST_DAILY_CAP) throw new HttpError(429, "kyc_attest_daily_cap");
  cap.count += 1; saveState(state);
  // Give the slot back only if no tx can have been sent (same UTC day).
  const refund = () => { const c = state.kycAttest; if (c && c.day === cap.day && c.count > 0) { c.count -= 1; saveState(state); } };

  // ---- durable intent record BEFORE the broadcast; no record, no tx ----
  try { kycAudit({ phase: "intent", ...audit }, true); } catch { refund(); throw new HttpError(500, "audit_unavailable"); }

  const { sendAndConfirm } = pinnedSender(expected, ctx);
  let hash, rcpt;
  try { ({ hash, rcpt } = await sendAndConfirm(attestTx(tokenId))); } catch (e) {
    if (e?.broadcast === false) refund();
    if (e?.txHash) audit.txHash = e.txHash; // may have landed: keep the hash in the audit
    throw e;
  }
  audit.txHash = hash;
  if (rcpt.status !== "success") throw new HttpError(502, "set_kyc_reverted");
  // The receipt must carry KycVerifiedSet(tokenId, true) from the pinned SBT.
  const ok = rcpt.logs.some((l) => {
    if (getAddress(l.address) !== SBT) return false;
    try {
      const ev = decodeEventLog({ abi: SBT_KYC_ABI, data: l.data, topics: l.topics });
      return ev.eventName === "KycVerifiedSet" && ev.args.tokenId === tokenId && ev.args.verified === true;
    } catch { return false; }
  });
  if (!ok) throw new HttpError(502, "kyc_event_missing");
  await requireGenesis(expected, ctx);
  delete audit.txHash;
  return { status: "attested", txHash: hash, tokenId: audit.tokenId, subHash, genesis: audit.genesis };
}

const server = createServer(async (req, res) => {
  try {
    if (req.method === "GET" && req.url === "/health") {
      rollDay();
      // Block-0 hash of this signer's RPC, so an operator can confirm the generation
      // before pointing core-membership at it. null when the lookup fails.
      let genesis = null;
      try { const h = (await publicClient.getBlock({ blockNumber: 0n })).hash; if (typeof h === "string" && GENESIS_RE.test(h)) genesis = h.toLowerCase(); } catch {}
      return json(res, 200, { genesis, status: "ok", signer: account.address, day: state.day, spentToday: state.spentToday, dailyCap: String(DAILY_CAP), grantWei: String(GRANT_WEI), gasHeadroomWei: String(GAS_HEADROOM), vault: VAULT, sbt: SBT,
      // Bond-clone model: idempotency for the grant leg is the durable on-chain
      // BondExists check (bondOf(member) has code), so there is no weaker fallback
      // mode to surface — the SBT (isSubBound) and bond (code) guards are both durable.
      model: "bond-clone",
      // Scoped KYC attestation: enabled iff identity's /kyc/status is configured.
      kycAttest: { enabled: KYC_STATUS.enabled, dailyCap: KYC_ATTEST_DAILY_CAP, attestedToday: kycCapToday().count } });
    }
    if (req.method === "POST" && req.url === "/grant") {
      if (!authorized(req.headers["authorization"])) return json(res, 401, { error: "unauthorized" });
      let body; try { body = JSON.parse((await readBody(req)) || "{}"); } catch { return json(res, 422, { error: "invalid json" }); }
      const result = await handleGrant(body);
      return json(res, 200, result);
    }
    if (req.method === "POST" && req.url === "/kyc-attest") {
      if (!authorized(req.headers["authorization"])) return json(res, 401, { error: "unauthorized" });
      let body; try { body = JSON.parse((await readBody(req)) || "{}"); } catch { return json(res, 422, { error: "invalid json" }); }
      const result = await handleKycAttest(body);
      return json(res, 200, result);
    }
    return json(res, 404, { error: "not found" });
  } catch (err) {
    if (err instanceof HttpError) return json(res, err.code, { error: err.message });
    // Never hand back a raw RPC/viem message (it can carry call arguments and endpoints).
    // eslint-disable-next-line no-console
    console.error(`request failed: chain_error (${err?.name ?? "Error"})`);
    return json(res, 502, { error: "chain_error" });
  }
});
// Bind 0.0.0.0 INSIDE the container; host isolation is the Docker port map
// (127.0.0.1:8790:8790) + Caddy TLS + bearer auth.
server.listen(PORT, "0.0.0.0", () => {
  // eslint-disable-next-line no-console
  console.log(`citrate-treasury-signer on :${PORT} signer=${account.address} vault=${VAULT} sbt=${SBT} grantWei=${GRANT_WEI} dailyCap=${DAILY_CAP} model=bond-clone kycAttest=${KYC_STATUS.enabled ? `on cap=${KYC_ATTEST_DAILY_CAP}` : `off (${KYC_STATUS.why})`}`);
});
