/**
 * Treasury signer: scoped KYC attestation endpoint (`POST /kyc-attest`).
 *
 * After a chain re-roll the member SBTs are re-minted with `kycVerified = false`. The
 * signer key owns the SBT, so it is the only key that can set the flag again. The new
 * endpoint must be narrow:
 *   - it takes a member wallet and a subject reference, nothing that names a function,
 *     a token id, a value or calldata;
 *   - the signer itself re-reads the subject's STORED verification record from identity
 *     (`GET /kyc/status`) and refuses unless it says `verified`. The caller's word is
 *     never enough;
 *   - the only transaction it can build is `CitrateMemberSBT.setKycVerified(tokenId,
 *     true)` on the pinned SBT, for the token bound to keccak256(sub) and owned by the
 *     member wallet;
 *   - same bearer auth and the same chain-generation pin as `/grant`; its own daily cap;
 *     idempotent (no transaction when the flag is already set); an audit trail with the
 *     subject hash only; fail closed on anything it cannot confirm.
 *
 * Black-box: the real `services/treasury-signer/server.mjs` runs as a child process
 * against an in-test JSON-RPC double and an in-test `/kyc/status` double, both on
 * ephemeral loopback ports. No live chain, no real key (a throwaway key per run), no real
 * token or secret.
 */
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { spawn, type ChildProcess } from "node:child_process";
import { createServer, type Server } from "node:http";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import type { AddressInfo } from "node:net";
import {
  decodeFunctionData, encodeAbiParameters, encodeFunctionData, keccak256, parseTransaction, toEventSelector,
  toFunctionSelector, toHex, type Hex,
} from "viem";
import { generatePrivateKey } from "viem/accounts";

const SERVER = join(dirname(fileURLToPath(import.meta.url)), "..", "services", "treasury-signer", "server.mjs");

const R1007 = "0x" + "a7".repeat(32);
const R1006 = "0xa3651a272fe411948cbb4cf7cca4cee44be4248d32ab4376cea7636821c6cdd4";
const VAULT = "0x1111111111111111111111111111111111111111";
const SBT = "0x2222222222222222222222222222222222222222";
const OTHER_SBT = "0x5555555555555555555555555555555555555555";
const MEMBER = "0x4444444444444444444444444444444444444444";
const MEMBER_B = "0x6666666666666666666666666666666666666666";
const STRANGER = "0x7777777777777777777777777777777777777777";
const TOKEN = "test-only-bearer";
const KYC_SECRET = "test-only-kyc-status-secret";
const SUB = "acct-sub-1-private";
const SUB_B = "acct-sub-2-private";
const subHash = (s: string) => keccak256(toHex(s));

const SET_KYC_ABI = [
  { type: "function", name: "setKycVerified", stateMutability: "nonpayable", inputs: [{ name: "tokenId", type: "uint256" }, { name: "verified", type: "bool" }], outputs: [] },
] as const;
const SEL = {
  isSubBound: toFunctionSelector("isSubBound(bytes32)"),
  tokenIdForSub: toFunctionSelector("tokenIdForSub(bytes32)"),
  getMember: toFunctionSelector("getMember(uint256)"),
  ownerOf: toFunctionSelector("ownerOf(uint256)"),
  setKycVerified: toFunctionSelector("setKycVerified(uint256,bool)"),
};
const KYC_SET_TOPIC = toEventSelector("KycVerifiedSet(uint256,bool)");
const MEMBER_TUPLE = [{
  type: "tuple", components: [
    { name: "subHash", type: "bytes32" }, { name: "termStart", type: "uint64" }, { name: "termEnd", type: "uint64" },
    { name: "quarantined", type: "bool" }, { name: "revoked", type: "bool" }, { name: "kycVerified", type: "bool" },
  ],
}] as const;

// ---- JSON-RPC double --------------------------------------------------------
interface MemberRow { tokenId: bigint; owner: string; quarantined: boolean; revoked: boolean; kycVerified: boolean }
interface ChainDouble {
  genesis: (call: number) => string | null | "error";
  members: Map<string, MemberRow>; // subHash (lower) -> row
  acceptBroadcasts: boolean;
  receiptStatus: "0x1" | "0x0";
  emitEvent: boolean;
  /** Delay (ms) before a broadcast is accepted and counted in the pending nonce. */
  sendDelayMs: number;
  /** The next broadcast is replaced (same sender + nonce) by REPLACEMENT_HASH, which mines instead. */
  replaceNext: boolean;
  /** Bond clone code for /grant's leg 2 ("0x" = no clone yet). */
  bondCode: string;
  /** vault.bondOf reverts (an unexpected chain error on /grant). */
  vaultRevert: boolean;
  calls: string[];
  ethCalls: string[]; // selectors of eth_call reads
  raw: Hex[]; // broadcast raw transactions (accepted)
  nonce: number; // pending nonce the double reports
  receipts: Map<string, { status: "0x1" | "0x0"; logs: unknown[] }>;
  pending: Map<string, Hex>; // replaced (never mined) hash -> raw
  genesisCalls: number;
}
const chain = {} as ChainDouble;
const SENDER = "0x" + "99".repeat(20); // the double reports one sender for every tx
const REPLACEMENT_HASH = "0x" + "ee".repeat(32);
function resetChain() {
  Object.assign(chain, {
    genesis: () => R1007, acceptBroadcasts: true, receiptStatus: "0x1", emitEvent: true, sendDelayMs: 0, replaceNext: false,
    bondCode: "0x6080", vaultRevert: false, calls: [], ethCalls: [], raw: [], nonce: 0, receipts: new Map(), pending: new Map(), genesisCalls: 0,
  });
  chain.members = new Map([
    [subHash(SUB).toLowerCase(), { tokenId: 7n, owner: MEMBER, quarantined: false, revoked: false, kycVerified: false }],
    [subHash(SUB_B).toLowerCase(), { tokenId: 8n, owner: MEMBER_B, quarantined: false, revoked: false, kycVerified: false }],
  ]);
}
resetChain();
const lastHash = () => keccak256(chain.raw[chain.raw.length - 1]!);
const nonces = () => chain.raw.map((r) => parseTransaction(r).nonce);

function block(hash: string | null, number: string, transactions: unknown[] = []) {
  return {
    hash, number, parentHash: "0x" + "00".repeat(32), nonce: "0x0000000000000000", sha3Uncles: "0x" + "00".repeat(32),
    logsBloom: "0x" + "00".repeat(256), transactionsRoot: "0x" + "00".repeat(32), stateRoot: "0x" + "00".repeat(32),
    receiptsRoot: "0x" + "00".repeat(32), miner: "0x" + "00".repeat(20), difficulty: "0x0", totalDifficulty: "0x0",
    extraData: "0x", size: "0x0", gasLimit: "0x1c9c380", gasUsed: "0x0", timestamp: "0x1", transactions, uncles: [],
    baseFeePerGas: "0x1", mixHash: "0x" + "00".repeat(32),
  };
}
function rpcTx(hash: string, raw: Hex, blockNumber: string | null, over: Record<string, unknown> = {}) {
  const t = parseTransaction(raw);
  return {
    hash, from: SENDER, to: t.to ?? null, nonce: toHex(t.nonce ?? 0), value: toHex(t.value ?? 0n), input: t.data ?? "0x",
    gas: toHex(t.gas ?? 21000n), maxFeePerGas: toHex(t.maxFeePerGas ?? 1n), maxPriorityFeePerGas: toHex(t.maxPriorityFeePerGas ?? 1n),
    type: "0x2", chainId: "0x9d0c", accessList: [], v: "0x0", r: "0x1", s: "0x1", yParity: "0x0",
    blockHash: blockNumber ? "0x" + "ab".repeat(32) : null, blockNumber, transactionIndex: blockNumber ? "0x0" : null, ...over,
  };
}
const rowByToken = (id: bigint) => [...chain.members.entries()].find(([, r]) => r.tokenId === id);
const revert = { error: { code: 3, message: "execution reverted" } };
const MINT_ABI = [{ type: "function", name: "mintMember", stateMutability: "nonpayable", inputs: [{ name: "to", type: "address" }, { name: "subHash", type: "bytes32" }, { name: "termStart", type: "uint64" }, { name: "termEnd", type: "uint64" }], outputs: [{ name: "", type: "uint256" }] }] as const;

/** Apply an accepted tx to the double's state and build its receipt logs, as the contract would. */
function apply(raw: Hex): unknown[] {
  const tx = parseTransaction(raw);
  const data = tx.data ?? "0x";
  if (data.startsWith(SEL.setKycVerified)) {
    const { args } = decodeFunctionData({ abi: SET_KYC_ABI, data });
    if (chain.receiptStatus === "0x1") { const hit = rowByToken(args[0]); if (hit) hit[1].kycVerified = args[1]; }
    return chain.emitEvent ? [{
      address: SBT, topics: [KYC_SET_TOPIC, encodeAbiParameters([{ type: "uint256" }], [args[0]])],
      data: encodeAbiParameters([{ type: "bool" }], [args[1]]),
    }] : [];
  }
  if (data.startsWith(toFunctionSelector("mintMember(address,bytes32,uint64,uint64)"))) {
    const { args } = decodeFunctionData({ abi: MINT_ABI, data });
    if (chain.receiptStatus === "0x1") chain.members.set(args[1].toLowerCase(), { tokenId: 20n + BigInt(chain.members.size), owner: args[0], quarantined: false, revoked: false, kycVerified: false });
  }
  return [];
}
function receiptOf(hash: string, r: { status: "0x1" | "0x0"; logs: unknown[] }) {
  return {
    transactionHash: hash, transactionIndex: "0x0", blockHash: "0x" + "ab".repeat(32), blockNumber: "0x10",
    from: SENDER, to: SBT, cumulativeGasUsed: "0x5208", gasUsed: "0x5208", effectiveGasPrice: "0x1",
    contractAddress: null, logsBloom: "0x" + "00".repeat(256), status: r.status, type: "0x2",
    logs: r.logs.map((l, i) => ({ ...(l as object), blockHash: "0x" + "ab".repeat(32), blockNumber: "0x10", transactionHash: hash, transactionIndex: "0x0", logIndex: toHex(i), removed: false })),
  };
}

type Answer = { result?: unknown; error?: { code: number; message: string } };
async function answer(method: string, params: unknown[]): Promise<Answer> {
  chain.calls.push(method);
  switch (method) {
    case "eth_getBlockByNumber": {
      if (params[0] === "0x0") {
        const g = chain.genesis(chain.genesisCalls++);
        if (g === "error") return { error: { code: -32000, message: "upstream unavailable" } };
        return { result: block(g, "0x0") };
      }
      // The block that mined a replacement carries it (viem scans it for same sender + nonce).
      const txs = params[1] === true ? [...chain.pending.values()].map((raw) => rpcTx(REPLACEMENT_HASH, raw, "0x10", { to: SENDER, value: "0x0", input: "0x" })) : [];
      return { result: block("0x" + "ab".repeat(32), "0x10", txs) };
    }
    case "eth_call": {
      const p = params[0] as { to?: string; data?: string; input?: string };
      const data = String(p.data ?? p.input);
      chain.ethCalls.push(data.slice(0, 10));
      const arg = "0x" + data.slice(10, 74);
      if (String(p.to).toLowerCase() === VAULT.toLowerCase() && data.startsWith(toFunctionSelector("bondOf(address)"))) {
        if (chain.vaultRevert) return { error: { code: 3, message: `execution reverted: bondOf(${MEMBER}) internal detail` } };
        return { result: encodeAbiParameters([{ type: "address" }], ["0x3333333333333333333333333333333333333333"]) };
      }
      if (String(p.to).toLowerCase() !== SBT.toLowerCase()) return revert;
      if (data.startsWith(SEL.isSubBound)) return { result: encodeAbiParameters([{ type: "bool" }], [chain.members.has(arg.toLowerCase())]) };
      if (data.startsWith(SEL.tokenIdForSub)) {
        const r = chain.members.get(arg.toLowerCase());
        return r ? { result: encodeAbiParameters([{ type: "uint256" }], [r.tokenId]) } : revert;
      }
      if (data.startsWith(SEL.getMember)) {
        const hit = rowByToken(BigInt(arg));
        if (!hit) return revert;
        const [sh, r] = hit;
        return { result: encodeAbiParameters(MEMBER_TUPLE, [{ subHash: sh as Hex, termStart: 1n, termEnd: 2_000_000_000n, quarantined: r.quarantined, revoked: r.revoked, kycVerified: r.kycVerified }]) };
      }
      if (data.startsWith(SEL.ownerOf)) {
        const hit = rowByToken(BigInt(arg));
        if (!hit || hit[1].revoked) return revert; // burned
        return { result: encodeAbiParameters([{ type: "address" }], [hit[1].owner as Hex]) };
      }
      return revert;
    }
    case "eth_getCode": return { result: chain.bondCode };
    case "eth_getBalance": return { result: "0xffffffffffffffffffff" };
    case "eth_blockNumber": return { result: "0x10" };
    case "eth_getTransactionByHash": {
      const h = String(params[0]).toLowerCase();
      const raw = chain.pending.get(h) ?? chain.raw.find((r) => keccak256(r).toLowerCase() === h);
      if (!raw) return { result: null };
      return { result: rpcTx(h, raw, chain.pending.has(h) ? null : "0x10") };
    }
    case "eth_getTransactionReceipt": {
      const h = String(params[0]).toLowerCase();
      const r = chain.receipts.get(h);
      return { result: r ? receiptOf(h, r) : null };
    }
    case "eth_chainId": return { result: "0x9d0c" };
    case "eth_getTransactionCount": return { result: toHex(chain.nonce) };
    case "eth_estimateGas": return { result: "0x5208" };
    case "eth_gasPrice": case "eth_maxPriorityFeePerGas": return { result: "0x1" };
    case "eth_sendRawTransaction": {
      if (chain.sendDelayMs) await new Promise((r) => setTimeout(r, chain.sendDelayMs));
      if (!chain.acceptBroadcasts) return { error: { code: -32000, message: "double rejects broadcasts" } };
      const raw = params[0] as Hex;
      const h = keccak256(raw).toLowerCase();
      chain.raw.push(raw);
      chain.nonce += 1;
      if (chain.replaceNext) {
        // Our tx never mines; a same-nonce replacement (a 0-value self-send) mines instead,
        // and its receipt even looks like a success.
        chain.replaceNext = false;
        chain.pending.set(h, raw);
        chain.receipts.set(REPLACEMENT_HASH, { status: "0x1", logs: apply(raw) });
      } else {
        chain.receipts.set(h, { status: chain.receiptStatus, logs: apply(raw) });
      }
      return { result: h };
    }
    default: return { error: { code: -32601, message: `unsupported ${method}` } };
  }
}

// ---- identity /kyc/status double --------------------------------------------
interface KycDouble {
  /** sub -> live status string identity would report; absent = "none". */
  status: Map<string, string>;
  /** Override the whole response (HTTP code + body) for failure modes. */
  override: ((sub: string) => { code: number; body: unknown } | "hang") | null;
  seen: { sub: string | null; auth: string | undefined }[];
}
const kyc: KycDouble = { status: new Map(), override: null, seen: [] };
function resetKyc() { kyc.status = new Map([[SUB, "verified"], [SUB_B, "verified"]]); kyc.override = null; kyc.seen = []; }
resetKyc();

let rpc: Server;
let rpcUrl = "";
let kycSrv: Server;
let kycUrl = "";
let signer: ChildProcess | null = null;
let signerUrl = "";
let signerOut = "";
let dir = "";

async function freePort(): Promise<number> {
  const s = createServer();
  await new Promise<void>((r) => s.listen(0, "127.0.0.1", () => r()));
  const { port } = s.address() as AddressInfo;
  await new Promise<void>((r) => s.close(() => r()));
  return port;
}

async function startSigner(env: Record<string, string | undefined> = {}): Promise<void> {
  dir = mkdtempSync(join(tmpdir(), "signer-kyc-"));
  const port = await freePort();
  signerUrl = `http://127.0.0.1:${port}`;
  signerOut = "";
  const base: Record<string, string | undefined> = {
    PATH: process.env.PATH ?? "",
    CITRATE_RPC_URL: rpcUrl, CITRATE_CHAIN_ID: "40204",
    MEMBERSHIP_STAKE_VAULT_ADDRESS: VAULT, CITRATE_MEMBER_SBT_ADDRESS: SBT,
    TREASURY_SIGNER_TOKEN: TOKEN, TREASURY_SIGNER_KEY: generatePrivateKey(),
    TREASURY_STATE_FILE: join(dir, "state.json"), PORT: String(port),
    KYC_STATUS_URL: kycUrl, KYC_STATUS_SECRET: KYC_SECRET,
    ...env,
  };
  const clean = Object.fromEntries(Object.entries(base).filter(([, v]) => v !== undefined)) as Record<string, string>;
  signer = spawn(process.execPath, [SERVER], { env: clean, stdio: ["ignore", "pipe", "pipe"] });
  signer.stdout!.on("data", (c) => { signerOut += String(c); });
  signer.stderr!.on("data", (c) => { signerOut += String(c); });
  const deadline = Date.now() + 20_000;
  while (!signerOut.includes("citrate-treasury-signer on")) {
    if (Date.now() > deadline || signer.exitCode != null) throw new Error(`signer did not start: ${signerOut}`);
    await new Promise((r) => setTimeout(r, 25));
  }
  chain.calls = []; chain.ethCalls = []; chain.genesisCalls = 0; kyc.seen = [];
}

async function stopSigner(): Promise<void> {
  if (signer && signer.exitCode == null) {
    const p = new Promise((r) => signer!.once("exit", r));
    signer.kill("SIGTERM");
    await p;
  }
  signer = null;
  if (dir) rmSync(dir, { recursive: true, force: true });
  dir = "";
}

function attestBody(over: Record<string, unknown> = {}) {
  return { member: MEMBER, sub: SUB, chainId: 40204, contracts: { sbt: SBT }, expectedGenesis: R1007, ...over };
}
async function post(path: string, body: unknown, token: string | null = TOKEN): Promise<{ status: number; json: Record<string, unknown> }> {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (token !== null) headers.authorization = `Bearer ${token}`;
  const res = await fetch(`${signerUrl}${path}`, { method: "POST", headers, body: JSON.stringify(body) });
  return { status: res.status, json: (await res.json()) as Record<string, unknown> };
}
const attest = (over: Record<string, unknown> = {}) => post("/kyc-attest", attestBody(over));

const broadcasts = () => chain.raw.length;
const chainReads = () => chain.calls.filter((m) => m === "eth_call" || m === "eth_getCode" || m === "eth_getBalance");
function auditRecords(): Record<string, unknown>[] {
  const f = join(dir, "kyc-attest-audit.jsonl");
  if (!existsSync(f)) return [];
  return readFileSync(f, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l));
}

beforeAll(async () => {
  rpc = createServer((req, res) => {
    let b = "";
    req.on("data", (c) => { b += c; });
    req.on("end", () => {
      const msg = JSON.parse(b);
      const one = async (m: { id: unknown; method: string; params?: unknown[] }) => ({ jsonrpc: "2.0", id: m.id, ...(await answer(m.method, m.params ?? [])) });
      void (async () => {
        const out = Array.isArray(msg) ? await Promise.all(msg.map(one)) : await one(msg);
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify(out));
      })();
    });
  });
  await new Promise<void>((r) => rpc.listen(0, "127.0.0.1", () => r()));
  rpcUrl = `http://127.0.0.1:${(rpc.address() as AddressInfo).port}`;

  kycSrv = createServer((req, res) => {
    const u = new URL(req.url ?? "/", "http://x");
    const sub = u.searchParams.get("sub");
    kyc.seen.push({ sub, auth: req.headers.authorization });
    if (u.pathname !== "/kyc/status") { res.writeHead(404); res.end("{}"); return; }
    if (req.headers.authorization !== `Bearer ${KYC_SECRET}`) { res.writeHead(401, { "content-type": "application/json" }); res.end('{"error":"unauthorized"}'); return; }
    const o = kyc.override?.(sub ?? "");
    if (o === "hang") return; // never answers: the signer must time out, not wait forever
    const code = o ? o.code : 200;
    const body = o ? o.body : { sub, kyc_status: kyc.status.get(sub ?? "") ?? "none" };
    res.writeHead(code, { "content-type": "application/json" });
    res.end(typeof body === "string" ? body : JSON.stringify(body));
  });
  await new Promise<void>((r) => kycSrv.listen(0, "127.0.0.1", () => r()));
  kycUrl = `http://127.0.0.1:${(kycSrv.address() as AddressInfo).port}`;
});
afterAll(async () => {
  await new Promise<void>((r) => rpc.close(() => r()));
  kycSrv.closeAllConnections();
  await new Promise<void>((r) => kycSrv.close(() => r()));
});
afterEach(async () => { await stopSigner(); resetChain(); resetKyc(); });

describe("POST /kyc-attest: the one transaction it can send", { timeout: 30_000 }, () => {
  it("attests a member whose stored record is verified: exactly setKycVerified(tokenId, true) on the pinned SBT, no value", async () => {
    await startSigner();
    const r = await attest();
    expect(r.status).toBe(200);
    expect(r.json).toMatchObject({ status: "attested", txHash: lastHash(), tokenId: "7", subHash: subHash(SUB), genesis: R1007 });
    expect(broadcasts()).toBe(1);
    const tx = parseTransaction(chain.raw[0]!);
    expect(tx.to?.toLowerCase()).toBe(SBT.toLowerCase());
    expect(tx.value ?? 0n).toBe(0n);
    expect(tx.data).toBe(encodeFunctionData({ abi: SET_KYC_ABI, functionName: "setKycVerified", args: [7n, true] }));
  });

  it("re-checks the stored record with identity itself, with its own secret and the caller's sub", async () => {
    await startSigner();
    await attest();
    expect(kyc.seen).toEqual([{ sub: SUB, auth: `Bearer ${KYC_SECRET}` }]);
  });

  it.each([
    ["verified", { verified: true }],
    ["tokenId", { tokenId: "1" }],
    ["data", { data: "0x" + SEL.setKycVerified.slice(2) }],
    ["to", { to: OTHER_SBT }],
    ["value", { value: "1" }],
    ["kyc_status", { kyc_status: "verified" }],
  ])("refuses a body that carries an extra field (%s) with 422, before any lookup", async (_l, extra) => {
    await startSigner();
    const r = await attest(extra);
    expect(r.status).toBe(422);
    expect(kyc.seen).toEqual([]);
    expect(chainReads()).toEqual([]);
    expect(broadcasts()).toBe(0);
  });

  it("a caller's claim that the member is verified does not help: a pending stored record is refused (403), nothing sent", async () => {
    kyc.status.set(SUB, "pending");
    await startSigner();
    const r = await attest();
    expect(r.status).toBe(403);
    expect(r.json.error).toBe("kyc_record_not_verified");
    expect(broadcasts()).toBe(0);
  });

  it.each(["pending", "revoked", "expired", "none", "VERIFIED", ""])("refuses stored status %j (403)", async (s) => {
    kyc.status.set(SUB, s);
    await startSigner();
    const r = await attest();
    expect(r.status).toBe(403);
    expect(broadcasts()).toBe(0);
  });

  it("refuses an SBT address other than the pinned one (422)", async () => {
    await startSigner();
    const r = await attest({ contracts: { sbt: OTHER_SBT } });
    expect(r.status).toBe(422);
    expect(kyc.seen).toEqual([]);
    expect(broadcasts()).toBe(0);
  });

  it("refuses when the member wallet is not the owner of the SBT bound to the subject (422)", async () => {
    await startSigner();
    const r = await attest({ member: STRANGER });
    expect(r.status).toBe(422);
    expect(r.json.error).toBe("member_mismatch");
    expect(broadcasts()).toBe(0);
  });

  it("refuses a subject with no SBT on this chain (422)", async () => {
    kyc.status.set("never-minted", "verified");
    await startSigner();
    const r = await attest({ sub: "never-minted" });
    expect(r.status).toBe(422);
    expect(r.json.error).toBe("sub_not_bound");
    expect(broadcasts()).toBe(0);
  });

  it("refuses a revoked membership (422)", async () => {
    chain.members.get(subHash(SUB).toLowerCase())!.revoked = true;
    await startSigner();
    const r = await attest();
    expect(r.status).toBe(422);
    expect(r.json.error).toBe("member_revoked");
    expect(broadcasts()).toBe(0);
  });

  it("refuses a quarantined membership (422)", async () => {
    chain.members.get(subHash(SUB).toLowerCase())!.quarantined = true;
    await startSigner();
    const r = await attest();
    expect(r.status).toBe(422);
    expect(r.json.error).toBe("member_quarantined");
    expect(broadcasts()).toBe(0);
  });

  it.each([
    ["missing member", { member: undefined }],
    ["bad member", { member: "0x1234" }],
    ["missing sub", { sub: undefined }],
    ["empty sub", { sub: "" }],
    ["non-string sub", { sub: 42 }],
    ["oversized sub", { sub: "s".repeat(300) }],
    ["wrong chainId", { chainId: 1 }],
    ["missing contracts", { contracts: undefined }],
    ["extra contract key", { contracts: { sbt: SBT, vault: VAULT } }],
  ])("validates the body (%s) with 422", async (_l, over) => {
    await startSigner();
    const r = await attest(over);
    expect(r.status).toBe(422);
    expect(kyc.seen).toEqual([]);
    expect(broadcasts()).toBe(0);
  });
});

describe("POST /kyc-attest: auth, pin and fail-closed", { timeout: 30_000 }, () => {
  it("requires the same bearer as /grant (401 without it or with a wrong one)", async () => {
    await startSigner();
    expect((await post("/kyc-attest", attestBody(), null)).status).toBe(401);
    expect((await post("/kyc-attest", attestBody(), "wrong")).status).toBe(401);
    expect(kyc.seen).toEqual([]);
    expect(broadcasts()).toBe(0);
  });

  it("accepts the previous token during a rotation, as /grant does", async () => {
    await startSigner({ TREASURY_SIGNER_TOKEN: "new-token", TREASURY_SIGNER_TOKEN_PREV: TOKEN });
    expect((await attest()).status).toBe(200);
  });

  it.each([
    ["no status URL", { KYC_STATUS_URL: undefined }],
    ["no status secret", { KYC_STATUS_SECRET: undefined }],
    ["status URL not http(s)", { KYC_STATUS_URL: "file:///etc/passwd" }],
    ["plain http to a public host", { KYC_STATUS_URL: "http://auth.example.com" }],
  ])("is disabled (503) when unconfigured: %s; /grant still starts", async (_l, env) => {
    await startSigner(env);
    const r = await attest();
    expect(r.status).toBe(503);
    expect(r.json.error).toBe("kyc_attest_unconfigured");
    expect(kyc.seen).toEqual([]);
    expect(broadcasts()).toBe(0);
  });

  it("refuses a missing expectedGenesis (422) and a different generation (412) before any lookup", async () => {
    await startSigner();
    const body = attestBody(); delete (body as Record<string, unknown>).expectedGenesis;
    expect((await post("/kyc-attest", body)).status).toBe(422);
    expect((await attest({ expectedGenesis: R1006 })).status).toBe(412);
    expect(kyc.seen).toEqual([]);
    expect(chainReads()).toEqual([]);
    expect(broadcasts()).toBe(0);
  });

  it("refuses when block 0 cannot be read (503)", async () => {
    chain.genesis = () => "error";
    await startSigner();
    expect((await attest()).status).toBe(503);
    expect(broadcasts()).toBe(0);
  });

  it("re-checks the generation before the broadcast: a flip sends nothing (412)", async () => {
    chain.genesis = (n) => (n === 0 ? R1007 : R1006);
    await startSigner();
    const r = await attest();
    expect(r.status).toBe(412);
    expect(broadcasts()).toBe(0);
  });

  it("re-checks the generation after the receipt: a flip raises an ALARM (502)", async () => {
    chain.genesis = (n) => (n <= 1 ? R1007 : R1006);
    await startSigner();
    const r = await attest();
    expect(r.status).toBe(502);
    expect(r.json.error).toBe("genesis_changed_after_broadcast");
    expect(signerOut).toMatch(/ALARM genesis_changed_after_broadcast/);
  });

  it.each([
    ["identity 500", () => ({ code: 500, body: { error: "boom" } })],
    ["identity 503 (unconfigured there)", () => ({ code: 503, body: { error: "kyc_status_unconfigured" } })],
    ["not JSON", () => ({ code: 200, body: "<html>" })],
    ["answer for another subject", () => ({ code: 200, body: { sub: "someone-else", kyc_status: "verified" } })],
    ["no status field", (s: string) => ({ code: 200, body: { sub: s } })],
  ])("fails closed (503) when the stored record cannot be confirmed: %s", async (_l, o) => {
    kyc.override = o as KycDouble["override"];
    await startSigner();
    const r = await attest();
    expect(r.status).toBe(503);
    expect(r.json.error).toBe("kyc_record_lookup_failed");
    expect(broadcasts()).toBe(0);
  });

  it("fails closed (503) when identity rejects the signer's secret", async () => {
    await startSigner({ KYC_STATUS_SECRET: "wrong-secret" });
    const r = await attest();
    expect(r.status).toBe(503);
    expect(broadcasts()).toBe(0);
  });

  it("fails closed (503) when identity is unreachable", async () => {
    await startSigner({ KYC_STATUS_URL: `http://127.0.0.1:${await freePort()}` });
    const r = await attest();
    expect(r.status).toBe(503);
    expect(broadcasts()).toBe(0);
  });

  it("fails closed (503) when identity does not answer in time", async () => {
    kyc.override = () => "hang";
    await startSigner({ KYC_STATUS_TIMEOUT_MS: "300" });
    const r = await attest();
    expect(r.status).toBe(503);
    expect(broadcasts()).toBe(0);
  });

  it("a reverted setKycVerified is a 502, not a success", async () => {
    chain.receiptStatus = "0x0";
    await startSigner();
    const r = await attest();
    expect(r.status).toBe(502);
    expect(r.json.status).toBeUndefined();
  });

  it("a receipt without the KycVerifiedSet(tokenId, true) event is a 502, not a success", async () => {
    chain.emitEvent = false;
    await startSigner();
    const r = await attest();
    expect(r.status).toBe(502);
    expect(r.json.status).toBeUndefined();
  });

  it("fails closed (500) and sends nothing when the audit record cannot be written", async () => {
    const blocker = join(mkdtempSync(join(tmpdir(), "signer-kyc-blk-")), "file");
    writeFileSync(blocker, "x");
    await startSigner({ KYC_ATTEST_AUDIT_FILE: join(blocker, "audit.jsonl") }); // parent is a file
    const r = await attest();
    expect(r.status).toBe(500);
    expect(broadcasts()).toBe(0);
    rmSync(dirname(blocker), { recursive: true, force: true });
  });
});

describe("POST /kyc-attest: idempotency, cap and audit", { timeout: 30_000 }, () => {
  it("is idempotent: an already-set flag sends nothing and spends no cap", async () => {
    chain.members.get(subHash(SUB).toLowerCase())!.kycVerified = true;
    await startSigner({ KYC_ATTEST_DAILY_CAP: "1" });
    const r = await attest();
    expect(r.status).toBe(200);
    expect(r.json).toMatchObject({ status: "already_attested", txHash: null, tokenId: "7", genesis: R1007 });
    expect(broadcasts()).toBe(0);
    // the cap of 1 is still available for a real attestation
    expect((await attest({ member: MEMBER_B, sub: SUB_B })).status).toBe(200);
    expect(broadcasts()).toBe(1);
  });

  it("an already-set flag is still not reported when the stored record no longer says verified", async () => {
    chain.members.get(subHash(SUB).toLowerCase())!.kycVerified = true;
    kyc.status.set(SUB, "revoked");
    await startSigner();
    expect((await attest()).status).toBe(403);
  });

  it("has its own daily cap (429 once spent), separate from the SALT cap", async () => {
    await startSigner({ KYC_ATTEST_DAILY_CAP: "1" });
    expect((await attest()).status).toBe(200);
    const r = await attest({ member: MEMBER_B, sub: SUB_B });
    expect(r.status).toBe(429);
    expect(r.json.error).toBe("kyc_attest_daily_cap");
    expect(broadcasts()).toBe(1);
    const h = (await (await fetch(`${signerUrl}/health`)).json()) as Record<string, any>;
    expect(h.spentToday).toBe("0");
    expect(h.kycAttest).toMatchObject({ enabled: true, dailyCap: 1, attestedToday: 1 });
  });

  it("the cap survives a restart (persisted with the signer state)", async () => {
    await startSigner({ KYC_ATTEST_DAILY_CAP: "1" });
    expect((await attest()).status).toBe(200);
    const state = readFileSync(join(dir, "state.json"), "utf8");
    // restart on the same state file
    const keep = dir; dir = "";
    await stopSigner();
    dir = keep;
    writeFileSync(join(dir, "state.json"), state);
    const port = await freePort();
    signerUrl = `http://127.0.0.1:${port}`; signerOut = "";
    signer = spawn(process.execPath, [SERVER], {
      env: {
        PATH: process.env.PATH ?? "", CITRATE_RPC_URL: rpcUrl, CITRATE_CHAIN_ID: "40204",
        MEMBERSHIP_STAKE_VAULT_ADDRESS: VAULT, CITRATE_MEMBER_SBT_ADDRESS: SBT,
        TREASURY_SIGNER_TOKEN: TOKEN, TREASURY_SIGNER_KEY: generatePrivateKey(),
        TREASURY_STATE_FILE: join(dir, "state.json"), PORT: String(port),
        KYC_STATUS_URL: kycUrl, KYC_STATUS_SECRET: KYC_SECRET, KYC_ATTEST_DAILY_CAP: "1",
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    signer.stdout!.on("data", (c) => { signerOut += String(c); });
    signer.stderr!.on("data", (c) => { signerOut += String(c); });
    while (!signerOut.includes("citrate-treasury-signer on")) await new Promise((r) => setTimeout(r, 25));
    expect((await attest({ member: MEMBER_B, sub: SUB_B })).status).toBe(429);
  });

  it("a cap of 0 refuses every attestation", async () => {
    await startSigner({ KYC_ATTEST_DAILY_CAP: "0" });
    expect((await attest()).status).toBe(429);
    expect(broadcasts()).toBe(0);
  });

  it("concurrent requests for one subject: one sends, the other gets 409 or already_attested", async () => {
    await startSigner();
    const [a, b] = await Promise.all([attest(), attest()]);
    const codes = [a.status, b.status].sort();
    expect(codes[0]).toBe(200);
    expect([200, 409]).toContain(codes[1]);
    expect(broadcasts()).toBe(1);
  });

  it("writes an audit trail with the subject hash only: no sub, no wallet, no token, no secret", async () => {
    await startSigner();
    await attest();
    kyc.status.set(SUB_B, "pending");
    await attest({ member: MEMBER_B, sub: SUB_B });
    const recs = auditRecords();
    expect(recs.length).toBeGreaterThanOrEqual(3); // intent + result for A, result for B
    const intent = recs.find((r) => r.phase === "intent");
    expect(intent).toMatchObject({ subHash: subHash(SUB), tokenId: "7", genesis: R1007 });
    const results = recs.filter((r) => r.phase === "result");
    expect(results.map((r) => r.outcome)).toEqual(["attested", "refused"]);
    expect(results[0]).toMatchObject({ txHash: keccak256(chain.raw[0]!), subHash: subHash(SUB) });
    expect(results[1]).toMatchObject({ reason: "kyc_record_not_verified", subHash: subHash(SUB_B) });
    const text = readFileSync(join(dir, "kyc-attest-audit.jsonl"), "utf8") + signerOut;
    for (const secret of [SUB, SUB_B, MEMBER.toLowerCase(), MEMBER_B.toLowerCase(), TOKEN, KYC_SECRET]) {
      expect(text.toLowerCase()).not.toContain(secret.toLowerCase());
    }
  });

  it("does not echo the sub or wallet in an error response", async () => {
    kyc.status.set(SUB, "pending");
    await startSigner();
    const r = await attest();
    expect(JSON.stringify(r.json)).not.toContain(SUB);
    expect(JSON.stringify(r.json).toLowerCase()).not.toContain(MEMBER.toLowerCase());
  });

  it("/grant is unchanged: it still refuses a body with no expectedGenesis and charges no KYC cap", async () => {
    await startSigner();
    const r = await post("/grant", { orderId: "o", sub: SUB, member: MEMBER, termStart: 1, termEnd: 2, chainId: 40204, contracts: { vault: VAULT, sbt: SBT } });
    expect(r.status).toBe(422);
    const h = (await (await fetch(`${signerUrl}/health`)).json()) as Record<string, any>;
    expect(h.kycAttest.attestedToday).toBe(0);
  });
});

// ---- shared signing key, state file and caps (security review of #44) ------------
const GRANT_SUB = "grant-sub-private";
function grantBody(over: Record<string, unknown> = {}) {
  return {
    orderId: "order-1", sub: GRANT_SUB, member: MEMBER, amountWei: String(32_000n * 10n ** 18n),
    termStart: 1_700_000_000, termEnd: 1_800_000_000, chainId: 40204, contracts: { vault: VAULT, sbt: SBT },
    expectedGenesis: R1007, ...over,
  };
}
const health = async () => (await (await fetch(`${signerUrl}/health`)).json()) as Record<string, any>;

describe("treasury signer: one signing key, serialized sends", { timeout: 60_000 }, () => {
  it("a concurrent /grant mint and /kyc-attest get distinct nonces", async () => {
    chain.sendDelayMs = 600; // a broadcast is slow to land, so an unserialized second send reads the same nonce
    await startSigner();
    const [g, a] = await Promise.all([post("/grant", grantBody()), attest()]);
    expect(g.status).toBe(200);
    expect(a.status).toBe(200);
    expect(nonces().length).toBe(2);
    expect(new Set(nonces()).size).toBe(2);
  });

  it("two concurrent attestations for different members get distinct nonces", async () => {
    chain.sendDelayMs = 600;
    await startSigner();
    const [a, b] = await Promise.all([attest(), attest({ member: MEMBER_B, sub: SUB_B })]);
    expect([a.status, b.status]).toEqual([200, 200]);
    expect(new Set(nonces()).size).toBe(2);
  });

  it("a replaced attestation tx is a failure, not 'attested', even though the replacement mined", async () => {
    chain.replaceNext = true;
    await startSigner();
    const r = await attest();
    expect(r.status).toBe(502);
    expect(r.json.error).toBe("tx_replaced");
    expect(r.json.status).toBeUndefined();
    expect(signerOut).toMatch(/ALARM tx_replaced/);
    expect(auditRecords().filter((x) => x.phase === "result").map((x) => x.outcome)).toEqual(["refused"]);
    // The tx was broadcast, so the cap slot is NOT refunded.
    expect((await health()).kycAttest.attestedToday).toBe(1);
  });

  it("a replaced /grant mint is never recorded as granted", async () => {
    chain.replaceNext = true;
    await startSigner();
    const r = await post("/grant", grantBody());
    expect(r.status).toBe(502);
    expect(r.json.error).toBe("tx_replaced");
    const saved = JSON.parse(readFileSync(join(dir, "state.json"), "utf8"));
    expect(saved.orders[`${R1007}/order-1`]).toBeUndefined();
  });
});

describe("treasury signer: state file and cap refunds", { timeout: 60_000 }, () => {
  async function spawnOnState(content: string): Promise<{ code: number | null; out: string }> {
    dir = mkdtempSync(join(tmpdir(), "signer-state-"));
    writeFileSync(join(dir, "state.json"), content);
    let out = "";
    const p = spawn(process.execPath, [SERVER], {
      env: {
        PATH: process.env.PATH ?? "", CITRATE_RPC_URL: rpcUrl, CITRATE_CHAIN_ID: "40204",
        MEMBERSHIP_STAKE_VAULT_ADDRESS: VAULT, CITRATE_MEMBER_SBT_ADDRESS: SBT,
        TREASURY_SIGNER_TOKEN: TOKEN, TREASURY_SIGNER_KEY: generatePrivateKey(),
        TREASURY_STATE_FILE: join(dir, "state.json"), PORT: String(await freePort()),
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    p.stdout!.on("data", (c) => { out += String(c); });
    p.stderr!.on("data", (c) => { out += String(c); });
    const code = await new Promise<number | null>((r) => {
      p.once("exit", (c) => r(c));
      setTimeout(() => { if (out.includes("citrate-treasury-signer on")) { p.kill("SIGTERM"); } }, 3000);
    });
    return { code, out };
  }

  it.each([["truncated JSON", '{"day":"2026-11-09","spentToday":"32'], ["empty file", ""], ["not an object", "[1,2]"]])(
    "refuses to start on an unreadable state file (%s) instead of resetting the caps and ledger", async (_l, content) => {
      const { code, out } = await spawnOnState(content);
      expect(code).not.toBe(0);
      expect(code).not.toBeNull();
      expect(out).not.toContain("citrate-treasury-signer on");
      expect(out).toMatch(/state file unreadable/);
    });

  it("writes the state file atomically (no temp file left behind, always parseable)", async () => {
    await startSigner();
    expect((await attest()).status).toBe(200);
    const files = readdirSync(dir).sort();
    expect(files).toEqual(["kyc-attest-audit.jsonl", "state.json"]);
    expect(JSON.parse(readFileSync(join(dir, "state.json"), "utf8")).kycAttest.count).toBe(1);
  });

  it("refunds the KYC cap when the broadcast never happened", async () => {
    chain.acceptBroadcasts = false;
    await startSigner({ KYC_ATTEST_DAILY_CAP: "1" });
    expect((await attest()).status).toBe(502);
    expect((await health()).kycAttest.attestedToday).toBe(0);
    chain.acceptBroadcasts = true;
    expect((await attest()).status).toBe(200);
  });

  it("refunds the /grant SALT cap when the vault.grant broadcast never happened", async () => {
    chain.acceptBroadcasts = false; chain.bondCode = "0x"; // leg 1 skipped (SUB is bound), leg 2 would grant
    await startSigner();
    const r = await post("/grant", grantBody({ sub: SUB }));
    expect(r.status).toBe(502);
    expect((await health()).spentToday).toBe("0");
  });

  it("an unexpected /grant chain error is answered as chain_error, without the raw RPC message", async () => {
    chain.vaultRevert = true;
    await startSigner();
    const r = await post("/grant", grantBody({ sub: SUB }));
    expect(r.status).toBe(502);
    expect(r.json).toEqual({ error: "chain_error" });
  });

  it.each([["hex string", "0x9d0c"], ["array", [40204]], ["decimal with fraction", "40204.0"], ["padded", " 40204"], ["fractional number", 40204.5], ["boolean", true]])(
    "parses chainId strictly (%s is 422 on both routes)", async (_l, chainId) => {
      await startSigner();
      expect((await attest({ chainId })).status).toBe(422);
      expect((await post("/grant", grantBody({ chainId }))).status).toBe(422);
      expect(broadcasts()).toBe(0);
    });

  it("accepts chainId as the number or its exact decimal string", async () => {
    await startSigner();
    expect((await attest({ chainId: "40204" })).status).toBe(200);
  });
});
