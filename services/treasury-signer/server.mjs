/**
 * Treasury signer worker — the DROPLET signing path for the Phase-D money flow
 * (CORE-S5.5 / D2.4, @rule8). Holds the vault/SBT OWNER key (the deterministic
 * treasury/grant signer) and performs the two onlyOwner grant writes the
 * core-membership orchestrator cannot make from Vercel (key NEVER on Vercel).
 *
 * Implements the membership team's API contract (handoffs/PHASE_D_DGX_OPERATOR_HANDOFF
 * appendix 2026-07-15). ONE endpoint does BOTH legs, idempotent by orderId +
 * on-chain guards; the service hashes the raw sub itself and clamps the amount.
 *
 * Security posture (@rule8):
 *   - Signing key only in this process env (TREASURY_SIGNER_KEY), on an operator
 *     droplet, never in the repo/Vercel. Bearer auth on every call.
 *   - Hard allowlist: only the two pinned contracts + the two grant selectors.
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
 *          (fundTxHash = the ADR-2026-07-27 bond-fund to the member EOA; vaultTxHash stays
 *           null now that Leg 1 funds the EOA instead of vault.grant.)
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
// ADR 2026-07-27 (membership = validator): the member SELF-BONDS by calling
// ValidatorRegistry.registerValidator{value: 32k}(pubkey, sig) from their own EOA,
// so the treasury must fund that EOA with the bond PLUS a little native SALT for
// the register tx's gas. GAS_HEADROOM is that gas cushion (default 0.05 SALT).
const GAS_HEADROOM = BigInt(process.env.TREASURY_GAS_HEADROOM_WEI ?? String(5n * 10n ** 16n));
// The ValidatorRegistry, read ONLY to answer "has this member already bonded?".
// See the durability note on Leg 1. Optional: unset degrades to the balance-only
// check and LOGS that the weaker guard is in force — it never silently downgrades.
const REGISTRY = (process.env.CITRATE_VALIDATOR_REGISTRY_ADDRESS ?? "").trim()
  ? getAddress(process.env.CITRATE_VALIDATOR_REGISTRY_ADDRESS.trim())
  : null;
const ZERO32 = "0x" + "00".repeat(32);
const PORT = Number(process.env.PORT ?? "8790");
const STATE_FILE = process.env.TREASURY_STATE_FILE ?? "/var/lib/citrate-treasury-signer/state.json";

const account = privateKeyToAccount((need("TREASURY_SIGNER_KEY").startsWith("0x") ? "" : "0x") + need("TREASURY_SIGNER_KEY"));
const chain = defineChain({ id: CHAIN_ID, name: "Citrate", nativeCurrency: { name: "SALT", symbol: "SALT", decimals: 18 }, rpcUrls: { default: { http: [RPC_URL] } } });
const publicClient = createPublicClient({ chain, transport: http(RPC_URL) });
const walletClient = createWalletClient({ account, chain, transport: http(RPC_URL) });

const VAULT_ABI = [
  { type: "function", name: "grant", stateMutability: "payable", inputs: [{ name: "member", type: "address" }, { name: "amount", type: "uint256" }], outputs: [{ name: "grantId", type: "uint256" }] },
  { type: "function", name: "attributedShares", stateMutability: "view", inputs: [{ name: "", type: "address" }], outputs: [{ name: "", type: "uint256" }] },
];
// One active binding per staker (`ValidatorRegistry.pubkeyOfStaker`). Non-zero
// means this address has ALREADY registered a validator — the registry itself
// reverts StakerHasValidator on a second attempt.
const REGISTRY_ABI = [
  { type: "function", name: "pubkeyOfStaker", stateMutability: "view", inputs: [{ name: "", type: "address" }], outputs: [{ name: "", type: "bytes32" }] },
];
const SBT_ABI = [
  { type: "function", name: "mintMember", stateMutability: "nonpayable", inputs: [{ name: "to", type: "address" }, { name: "subHash", type: "bytes32" }, { name: "termStart", type: "uint64" }, { name: "termEnd", type: "uint64" }], outputs: [{ name: "tokenId", type: "uint256" }] },
  { type: "function", name: "isSubBound", stateMutability: "view", inputs: [{ name: "subHash", type: "bytes32" }], outputs: [{ name: "", type: "bool" }] },
];
const TRANSFER_TOPIC = toEventSelector("Transfer(address,address,uint256)");

// ---- persisted daily-cap + orderId idempotency ledger ------------------------
function loadState() { try { if (existsSync(STATE_FILE)) return JSON.parse(readFileSync(STATE_FILE, "utf8")); } catch {} return { day: "", spentToday: "0", orders: {} }; }
function saveState(s) { mkdirSync(dirname(STATE_FILE), { recursive: true }); writeFileSync(STATE_FILE, JSON.stringify(s), "utf8"); }
let state = loadState();
const utcDay = () => new Date().toISOString().slice(0, 10);
function rollDay() { const d = utcDay(); if (state.day !== d) { state.day = d; state.spentToday = "0"; saveState(state); } }

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

    // ---- Leg 1: BOND-FUND (ADR 2026-07-27, membership = validator) ----
    // REPLACES the old vault.grant. Native-transfer the bond (+ gas headroom) to
    // the member's OWN EOA so it can self-bond via
    // ValidatorRegistry.registerValidator{value: 32k}(pubkey, sig). The stake then
    // lives in the ValidatorRegistry (bonded, slashable), not the MembershipStakeVault.
    // IDEMPOTENCY, AND WHY THE BALANCE ALONE IS NOT ENOUGH.
    // The obvious check — "skip if the EOA already holds >= the bond" — is a signal
    // CONSUMED BY ITS OWN SUCCESS: the member spends exactly that balance to
    // self-bond, so a funded-and-bonded member reads as unfunded. The window is
    // real: fund succeeds -> sbt.mintMember fails -> the catch below DELETES the
    // orderId record so the order stays re-triable -> the member bonds in the
    // meantime -> the retry sees a ~0 balance and sends a SECOND 32,000 SALT.
    //
    // So we ask the durable question first: has this address already registered a
    // validator? `pubkeyOfStaker` is non-zero for the life of the binding and does
    // not drain when the bond is paid — and the registry enforces one validator per
    // staker (StakerHasValidator), so a bonded member can never need funding again.
    // Balance stays as the second condition, covering the funded-but-not-yet-bonded
    // member. Both must say "needs funding" before any SALT moves.
    let alreadyBonded = false;
    if (REGISTRY) {
      const pk = await publicClient.readContract({ address: REGISTRY, abi: REGISTRY_ABI, functionName: "pubkeyOfStaker", args: [m] });
      alreadyBonded = pk !== ZERO32;
    }
    const bal = await publicClient.getBalance({ address: m });
    if (!alreadyBonded && bal < amount) {
      rollDay();
      const target = amount + GAS_HEADROOM;   // fund up to bond + gas for the register tx
      const topUp = target - bal;             // top up only the shortfall (idempotent w/ partial funding)
      const spent = BigInt(state.spentToday);
      if (spent + topUp > DAILY_CAP) throw new HttpError(403, `daily cap exceeded: ${spent + topUp} > ${DAILY_CAP}`);
      const hash = await walletClient.sendTransaction({ to: m, value: topUp });
      const rcpt = await publicClient.waitForTransactionReceipt({ hash });
      if (rcpt.status !== "success") throw new HttpError(502, `bond-fund reverted in ${hash}`);
      state.spentToday = String(spent + topUp); saveState(state);
      fundTxHash = hash;
    }

    // ---- Leg 2: sbt.mintMember (skip if sub already bound) ----
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

    const result = { orderId, fundTxHash, vaultTxHash, sbtTxHash, sbtTokenId, status: (fundTxHash || sbtTxHash) ? "granted" : "already_granted" };
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
      return json(res, 200, { status: "ok", signer: account.address, day: state.day, spentToday: state.spentToday, dailyCap: String(DAILY_CAP), grantWei: String(GRANT_WEI), vault: VAULT, sbt: SBT,
      // Which idempotency guard is in force. "registry+balance" is the durable
      // one; "balance-only" means CITRATE_VALIDATOR_REGISTRY_ADDRESS is unset and
      // a fund->mint-fail->bond->retry could double-fund. Surfaced so the weaker
      // mode is visible to an operator instead of inferred from a log line.
      registry: REGISTRY, fundGuard: REGISTRY ? "registry+balance" : "balance-only" });
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
  console.log(`citrate-treasury-signer on :${PORT} signer=${account.address} vault=${VAULT} sbt=${SBT} grantWei=${GRANT_WEI} dailyCap=${DAILY_CAP} registry=${REGISTRY ?? "UNSET"}`);
if (!REGISTRY) {
  console.warn("[treasury-signer] CITRATE_VALIDATOR_REGISTRY_ADDRESS is UNSET — the bond-fund falls back to the BALANCE-ONLY idempotency check, which a member spends when they self-bond. A fund->mint-fail->bond->retry sequence could double-fund. Set it.");
}
});
