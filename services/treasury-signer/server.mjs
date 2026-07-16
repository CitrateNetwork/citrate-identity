/**
 * Treasury signer worker — the DROPLET signing path for the Phase-D money flow
 * (CORE-S5.5 / D2.4, @rule8). Holds the vault/SBT OWNER key (the deterministic
 * treasury/grant signer) and performs the onlyOwner calls the core-membership
 * grant orchestrator cannot make from Vercel (the key must NEVER be on Vercel).
 *
 * Security posture (@rule8):
 *   - The signing key lives ONLY in this process's env (TREASURY_SIGNER_KEY),
 *     on an operator-controlled droplet, never in the repo, never on Vercel.
 *   - Bearer auth (TREASURY_SIGNER_TOKEN) on every signing call.
 *   - Per-UTC-day SALT cap (TREASURY_DAILY_CAP_WEI), persisted to disk so a
 *     restart cannot reset it. Blast radius is bounded to the daily cap.
 *   - The key can ONLY reach a fixed allow-list of onlyOwner methods on two
 *     pinned contracts (vault + SBT). It cannot send arbitrary calldata or
 *     transfer the balance out.
 *   - Dual-control is a documented follow-up: set TREASURY_REQUIRE_APPROVALS>1
 *     to require a second-operator HMAC header (X-Approval) — see README.
 *
 * HTTP contract (what core-membership's droplet client POSTs):
 *   GET  /health                      -> { status, day, spentToday, dailyCap }
 *   POST /v1/sign  (Bearer)           -> { txHash, blockNumber, status }
 *     body: { method, args, idempotencyKey? }
 *       method "grant":   args { member, amountWei }        -> vault.grant(member, amountWei){value: amountWei}
 *       method "mint":    args { member, subHash, termStart, termEnd } -> sbt.mintMember(...)
 *       method "release"|"renew"|"lapse": args { grantId }  -> vault.<method>(grantId)   (onlyOwner)
 *   Idempotency: an idempotencyKey that already succeeded returns the prior receipt.
 */
import { createServer } from "node:http";
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import {
  createWalletClient,
  createPublicClient,
  http,
  defineChain,
  encodeFunctionData,
  getAddress,
  isAddress,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";

const need = (k) => {
  const v = process.env[k];
  if (!v || !v.trim()) throw new Error(`${k} is required`);
  return v.trim();
};

const RPC_URL = need("CITRATE_RPC_URL");
const CHAIN_ID = Number(process.env.CITRATE_CHAIN_ID ?? "40204");
const VAULT = getAddress(need("MEMBERSHIP_STAKE_VAULT_ADDRESS"));
const SBT = getAddress(need("CITRATE_MEMBER_SBT_ADDRESS"));
const TOKEN = need("TREASURY_SIGNER_TOKEN");
const DAILY_CAP = BigInt(process.env.TREASURY_DAILY_CAP_WEI ?? String(96_000n * 10n ** 18n)); // 3 grants/day default
const PORT = Number(process.env.PORT ?? "8790");
const STATE_FILE = process.env.TREASURY_STATE_FILE ?? "/var/lib/citrate-treasury-signer/state.json";

const account = privateKeyToAccount(
  (need("TREASURY_SIGNER_KEY").startsWith("0x") ? "" : "0x") + need("TREASURY_SIGNER_KEY"),
);

const chain = defineChain({
  id: CHAIN_ID,
  name: "Citrate",
  nativeCurrency: { name: "SALT", symbol: "SALT", decimals: 18 },
  rpcUrls: { default: { http: [RPC_URL] } },
});
const publicClient = createPublicClient({ chain, transport: http(RPC_URL) });
const walletClient = createWalletClient({ account, chain, transport: http(RPC_URL) });

const VAULT_ABI = [
  { type: "function", name: "grant", stateMutability: "payable", inputs: [{ name: "member", type: "address" }, { name: "amount", type: "uint256" }], outputs: [{ name: "grantId", type: "uint256" }] },
  { type: "function", name: "release", stateMutability: "nonpayable", inputs: [{ name: "grantId", type: "uint256" }], outputs: [] },
  { type: "function", name: "renew", stateMutability: "nonpayable", inputs: [{ name: "grantId", type: "uint256" }], outputs: [] },
  { type: "function", name: "lapse", stateMutability: "nonpayable", inputs: [{ name: "grantId", type: "uint256" }], outputs: [] },
];
const SBT_ABI = [
  { type: "function", name: "mintMember", stateMutability: "nonpayable", inputs: [{ name: "member", type: "address" }, { name: "subHash", type: "bytes32" }, { name: "termStart", type: "uint64" }, { name: "termEnd", type: "uint64" }], outputs: [{ name: "tokenId", type: "uint256" }] },
];

// ---- persisted daily-cap + idempotency state ---------------------------------
function loadState() {
  try { if (existsSync(STATE_FILE)) return JSON.parse(readFileSync(STATE_FILE, "utf8")); } catch {}
  return { day: "", spentToday: "0", receipts: {} };
}
function saveState(s) {
  mkdirSync(dirname(STATE_FILE), { recursive: true });
  writeFileSync(STATE_FILE, JSON.stringify(s), "utf8");
}
let state = loadState();
function utcDay() { return new Date().toISOString().slice(0, 10); }
function rollDay() {
  const d = utcDay();
  if (state.day !== d) { state.day = d; state.spentToday = "0"; saveState(state); }
}

function json(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, { "content-type": "application/json", "content-length": Buffer.byteLength(body) });
  res.end(body);
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let b = ""; let n = 0;
    req.on("data", (c) => { n += c.length; if (n > 16_384) { reject(new Error("body too large")); req.destroy(); } b += c; });
    req.on("end", () => resolve(b));
    req.on("error", reject);
  });
}

async function doSign(method, args) {
  if (method === "grant") {
    if (!isAddress(args.member, { strict: false })) throw new Error("member must be an address");
    const amount = BigInt(args.amountWei);
    if (amount <= 0n) throw new Error("amountWei must be > 0");
    rollDay();
    const spent = BigInt(state.spentToday);
    if (spent + amount > DAILY_CAP) throw new Error(`daily cap exceeded: ${spent + amount} > ${DAILY_CAP}`);
    const data = encodeFunctionData({ abi: VAULT_ABI, functionName: "grant", args: [getAddress(args.member), amount] });
    const hash = await walletClient.sendTransaction({ to: VAULT, data, value: amount });
    const rcpt = await publicClient.waitForTransactionReceipt({ hash });
    if (rcpt.status === "success") { state.spentToday = String(spent + amount); saveState(state); }
    return { txHash: hash, blockNumber: Number(rcpt.blockNumber), status: rcpt.status };
  }
  if (method === "mint") {
    if (!isAddress(args.member, { strict: false })) throw new Error("member must be an address");
    const data = encodeFunctionData({ abi: SBT_ABI, functionName: "mintMember", args: [getAddress(args.member), args.subHash, BigInt(args.termStart), BigInt(args.termEnd)] });
    const hash = await walletClient.sendTransaction({ to: SBT, data });
    const rcpt = await publicClient.waitForTransactionReceipt({ hash });
    return { txHash: hash, blockNumber: Number(rcpt.blockNumber), status: rcpt.status };
  }
  if (method === "release" || method === "renew" || method === "lapse") {
    const data = encodeFunctionData({ abi: VAULT_ABI, functionName: method, args: [BigInt(args.grantId)] });
    const hash = await walletClient.sendTransaction({ to: VAULT, data });
    const rcpt = await publicClient.waitForTransactionReceipt({ hash });
    return { txHash: hash, blockNumber: Number(rcpt.blockNumber), status: rcpt.status };
  }
  throw new Error(`unknown method ${method}`);
}

const server = createServer(async (req, res) => {
  try {
    if (req.method === "GET" && req.url === "/health") {
      rollDay();
      return json(res, 200, { status: "ok", signer: account.address, day: state.day, spentToday: state.spentToday, dailyCap: String(DAILY_CAP), vault: VAULT, sbt: SBT });
    }
    if (req.method === "POST" && req.url === "/v1/sign") {
      const auth = req.headers["authorization"] || "";
      if (auth !== `Bearer ${TOKEN}`) return json(res, 401, { error: "unauthorized" });
      const body = await readBody(req);
      let parsed; try { parsed = JSON.parse(body || "{}"); } catch { return json(res, 400, { error: "invalid json" }); }
      const { method, args, idempotencyKey } = parsed;
      if (!method || typeof args !== "object") return json(res, 400, { error: "method + args required" });
      if (idempotencyKey && state.receipts[idempotencyKey]) return json(res, 200, { ...state.receipts[idempotencyKey], idempotent: true });
      const result = await doSign(method, args);
      if (idempotencyKey && result.status === "success") { state.receipts[idempotencyKey] = result; saveState(state); }
      return json(res, 200, result);
    }
    return json(res, 404, { error: "not found" });
  } catch (err) {
    return json(res, 502, { error: String(err?.message ?? err) });
  }
});
// Bind 0.0.0.0 INSIDE the container; host isolation comes from the Docker port
// map (127.0.0.1:8790:8790) + Caddy. For a bare-metal run, front it the same way.
server.listen(PORT, "0.0.0.0", () => {
  // eslint-disable-next-line no-console
  console.log(`citrate-treasury-signer on 127.0.0.1:${PORT} signer=${account.address} vault=${VAULT} sbt=${SBT} dailyCap=${DAILY_CAP}`);
});
