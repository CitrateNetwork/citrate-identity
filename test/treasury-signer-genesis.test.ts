/**
 * Treasury signer: chain-generation pin (core-membership#70 P1-2) and the
 * per-generation idempotency ledger (#70 P1-1).
 *
 * r1005 and r1006 both answer chainId 40204, so the chain id cannot tell one
 * generation from the next. The signer must compare the caller's `expectedGenesis`
 * with the block-0 hash of ITS OWN RPC and refuse the grant (before any read of
 * grant state and before any broadcast) when the value is missing, malformed,
 * different, or cannot be looked up.
 *
 * Black-box: the real `services/treasury-signer/server.mjs` runs as a child process
 * against an in-test JSON-RPC double on an ephemeral loopback port. No live chain,
 * no real key (a throwaway key is generated per run), no real token.
 */
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { spawn, type ChildProcess } from "node:child_process";
import { createServer, type Server } from "node:http";
import { mkdtempSync, rmSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import type { AddressInfo } from "node:net";
import { encodeAbiParameters, toFunctionSelector } from "viem";
import { generatePrivateKey } from "viem/accounts";

const SERVER = join(dirname(fileURLToPath(import.meta.url)), "..", "services", "treasury-signer", "server.mjs");

const R1006 = "0xa3651a272fe411948cbb4cf7cca4cee44be4248d32ab4376cea7636821c6cdd4";
const R1005 = "0x1dcfc4909dd9fdcb0f03c823d627e4b2032cc86bef5fc4561030d6c64b9775f1";
const VAULT = "0x1111111111111111111111111111111111111111";
const SBT = "0x2222222222222222222222222222222222222222";
const BOND = "0x3333333333333333333333333333333333333333";
const MEMBER = "0x4444444444444444444444444444444444444444";
const TOKEN = "test-only-bearer";

const SEL = {
  isSubBound: toFunctionSelector("isSubBound(bytes32)"),
  tokenIdForSub: toFunctionSelector("tokenIdForSub(bytes32)"),
  bondOf: toFunctionSelector("bondOf(address)"),
};

// ---- JSON-RPC double --------------------------------------------------------
interface ChainDouble {
  /** Block-0 hash, or a function of the call index (to flip mid-request). */
  genesis: (call: number) => string | null | "error";
  subBound: boolean;
  bondExists: boolean;
  /** Member EOA balance (wei, hex). Low → the gas top-up leg broadcasts. */
  balance: string;
  /** Accept broadcasts and return a successful receipt (default: reject them). */
  acceptBroadcasts: boolean;
  calls: string[];
  genesisCalls: number;
}
const HIGH_BALANCE = "0xffffffffffffffffffff";
const chain: ChainDouble = { genesis: () => R1006, subBound: true, bondExists: true, balance: HIGH_BALANCE, acceptBroadcasts: false, calls: [], genesisCalls: 0 };
const TX_HASH = "0x" + "cd".repeat(32);

function block(hash: string | null, number: string) {
  return {
    hash, number, parentHash: "0x" + "00".repeat(32), nonce: "0x0000000000000000", sha3Uncles: "0x" + "00".repeat(32),
    logsBloom: "0x" + "00".repeat(256), transactionsRoot: "0x" + "00".repeat(32), stateRoot: "0x" + "00".repeat(32),
    receiptsRoot: "0x" + "00".repeat(32), miner: "0x" + "00".repeat(20), difficulty: "0x0", totalDifficulty: "0x0",
    extraData: "0x", size: "0x0", gasLimit: "0x1c9c380", gasUsed: "0x0", timestamp: "0x1", transactions: [], uncles: [],
    baseFeePerGas: "0x1", mixHash: "0x" + "00".repeat(32),
  };
}

function answer(method: string, params: unknown[]): { result?: unknown; error?: { code: number; message: string } } {
  chain.calls.push(method);
  switch (method) {
    case "eth_getBlockByNumber": {
      if (params[0] === "0x0") {
        const g = chain.genesis(chain.genesisCalls++);
        if (g === "error") return { error: { code: -32000, message: "upstream unavailable" } };
        return { result: block(g, "0x0") };
      }
      return { result: block("0x" + "ab".repeat(32), "0x10") };
    }
    case "eth_call": {
      const data = String((params[0] as { data?: string; input?: string }).data ?? (params[0] as { input?: string }).input);
      if (data.startsWith(SEL.isSubBound)) return { result: encodeAbiParameters([{ type: "bool" }], [chain.subBound]) };
      if (data.startsWith(SEL.tokenIdForSub)) return { result: encodeAbiParameters([{ type: "uint256" }], [7n]) };
      if (data.startsWith(SEL.bondOf)) return { result: encodeAbiParameters([{ type: "address" }], [BOND]) };
      return { error: { code: -32000, message: "unknown call" } };
    }
    case "eth_getCode": return { result: chain.bondExists ? "0x6080" : "0x" };
    case "eth_getBalance": return { result: chain.balance };
    case "eth_blockNumber": return { result: "0x10" };
    case "eth_getTransactionReceipt":
      return {
        result: {
          transactionHash: TX_HASH, transactionIndex: "0x0", blockHash: "0x" + "ab".repeat(32), blockNumber: "0x10",
          from: MEMBER, to: SBT, cumulativeGasUsed: "0x5208", gasUsed: "0x5208", effectiveGasPrice: "0x1",
          contractAddress: null, logs: [], logsBloom: "0x" + "00".repeat(256), status: "0x1", type: "0x2",
        },
      };
    case "eth_chainId": return { result: "0x9d0c" };
    case "eth_getTransactionCount": return { result: "0x0" };
    case "eth_estimateGas": return { result: "0x5208" };
    case "eth_gasPrice": case "eth_maxPriorityFeePerGas": return { result: "0x1" };
    // Never accept a broadcast: a test that reaches here proves a send was attempted.
    case "eth_sendRawTransaction":
      return chain.acceptBroadcasts ? { result: TX_HASH } : { error: { code: -32000, message: "double rejects broadcasts" } };
    default: return { error: { code: -32601, message: `unsupported ${method}` } };
  }
}

let rpc: Server;
let rpcUrl = "";
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

async function startSigner(seedState?: unknown): Promise<void> {
  dir = mkdtempSync(join(tmpdir(), "signer-genesis-"));
  const stateFile = join(dir, "state.json");
  if (seedState) writeFileSync(stateFile, JSON.stringify(seedState));
  const port = await freePort();
  signerUrl = `http://127.0.0.1:${port}`;
  signerOut = "";
  const key = generatePrivateKey(); // throwaway, per run
  signer = spawn(process.execPath, [SERVER], {
    env: {
      PATH: process.env.PATH ?? "",
      CITRATE_RPC_URL: rpcUrl, CITRATE_CHAIN_ID: "40204",
      MEMBERSHIP_STAKE_VAULT_ADDRESS: VAULT, CITRATE_MEMBER_SBT_ADDRESS: SBT,
      TREASURY_SIGNER_TOKEN: TOKEN, TREASURY_SIGNER_KEY: key,
      TREASURY_STATE_FILE: stateFile, PORT: String(port),
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  signer.stdout!.on("data", (c) => { signerOut += String(c); });
  signer.stderr!.on("data", (c) => { signerOut += String(c); });
  const deadline = Date.now() + 20_000;
  while (!signerOut.includes("citrate-treasury-signer on")) {
    if (Date.now() > deadline || signer.exitCode != null) throw new Error(`signer did not start: ${signerOut}`);
    await new Promise((r) => setTimeout(r, 25));
  }
  // Reading /health or start-up must not have touched the grant legs.
  chain.calls = []; chain.genesisCalls = 0;
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

function grantBody(over: Record<string, unknown> = {}) {
  return {
    orderId: "order-1", sub: "sub-1", member: MEMBER, amountWei: String(32_000n * 10n ** 18n),
    termStart: 1_700_000_000, termEnd: 1_800_000_000, chainId: 40204, contracts: { vault: VAULT, sbt: SBT },
    expectedGenesis: R1006, ...over,
  };
}

async function postGrant(body: unknown): Promise<{ status: number; json: Record<string, unknown> }> {
  const res = await fetch(`${signerUrl}/grant`, {
    method: "POST", headers: { authorization: `Bearer ${TOKEN}`, "content-type": "application/json" }, body: JSON.stringify(body),
  });
  return { status: res.status, json: (await res.json()) as Record<string, unknown> };
}

const legReads = () => chain.calls.filter((m) => m === "eth_call" || m === "eth_getCode" || m === "eth_getBalance");
const broadcasts = () => chain.calls.filter((m) => m === "eth_sendRawTransaction");

beforeAll(async () => {
  rpc = createServer((req, res) => {
    let b = "";
    req.on("data", (c) => { b += c; });
    req.on("end", () => {
      const msg = JSON.parse(b);
      const one = (m: { id: unknown; method: string; params?: unknown[] }) => ({ jsonrpc: "2.0", id: m.id, ...answer(m.method, m.params ?? []) });
      const out = Array.isArray(msg) ? msg.map(one) : one(msg);
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(out));
    });
  });
  await new Promise<void>((r) => rpc.listen(0, "127.0.0.1", () => r()));
  rpcUrl = `http://127.0.0.1:${(rpc.address() as AddressInfo).port}`;
});
afterAll(async () => { await new Promise<void>((r) => rpc.close(() => r())); });
afterEach(async () => {
  await stopSigner();
  chain.genesis = () => R1006; chain.subBound = true; chain.bondExists = true; chain.balance = HIGH_BALANCE; chain.acceptBroadcasts = false;
  chain.calls = []; chain.genesisCalls = 0;
});

describe("treasury signer: expectedGenesis pin (fail closed)", { timeout: 30_000 }, () => {
  it("a matching expectedGenesis proceeds to the legs and echoes the signer's own genesis", async () => {
    await startSigner();
    const r = await postGrant(grantBody());
    expect(r.status).toBe(200);
    expect(r.json.status).toBe("already_granted");
    expect(r.json.genesis).toBe(R1006);
    expect(legReads().length).toBeGreaterThan(0);
  });

  it("matches case-insensitively (an upper-case pin is the same hash)", async () => {
    await startSigner();
    const r = await postGrant(grantBody({ expectedGenesis: "0x" + R1006.slice(2).toUpperCase() }));
    expect(r.status).toBe(200);
    expect(r.json.genesis).toBe(R1006);
  });

  it("refuses a missing expectedGenesis with 422, before any grant read or broadcast", async () => {
    await startSigner();
    const body = grantBody(); delete (body as Record<string, unknown>).expectedGenesis;
    const r = await postGrant(body);
    expect(r.status).toBe(422);
    expect(legReads()).toEqual([]);
    expect(broadcasts()).toEqual([]);
  });

  it.each([
    ["short", "0x1234"],
    ["not hex", "0x" + "zz".repeat(32)],
    ["no 0x prefix", R1006.slice(2)],
    ["not a string", 12345],
    ["empty", ""],
  ])("refuses a malformed expectedGenesis (%s) with 422", async (_label, value) => {
    await startSigner();
    const r = await postGrant(grantBody({ expectedGenesis: value }));
    expect(r.status).toBe(422);
    expect(chain.genesisCalls).toBe(0);
    expect(legReads()).toEqual([]);
  });

  it("refuses a different generation (r1005 pin against an r1006 RPC) with 412, nothing read or sent", async () => {
    await startSigner();
    const r = await postGrant(grantBody({ expectedGenesis: R1005 }));
    expect(r.status).toBe(412);
    expect(legReads()).toEqual([]);
    expect(broadcasts()).toEqual([]);
    expect(signerOut).toMatch(/grant refused: genesis_mismatch/);
  });

  it("refuses when the block-0 lookup fails (503), and does not cache the failure", async () => {
    chain.genesis = (n) => (n === 0 ? "error" : R1006);
    await startSigner();
    const r = await postGrant(grantBody());
    expect(r.status).toBe(503);
    expect(legReads()).toEqual([]);
    expect(signerOut).toMatch(/grant refused: genesis_lookup_failed/);
    // The next request re-fetches block 0 and succeeds.
    const r2 = await postGrant(grantBody());
    expect(r2.status).toBe(200);
  });

  it("refuses when the RPC returns block 0 with no hash (503)", async () => {
    chain.genesis = () => null;
    await startSigner();
    const r = await postGrant(grantBody());
    expect(r.status).toBe(503);
    expect(legReads()).toEqual([]);
  });

  it("re-checks block 0 before a broadcast: a generation flip mid-request sends nothing", async () => {
    chain.subBound = false; // leg 1 would mint
    chain.genesis = (n) => (n === 0 ? R1006 : R1005);
    await startSigner();
    const r = await postGrant(grantBody());
    expect(r.status).toBe(412);
    expect(broadcasts()).toEqual([]);
  });

  it("re-checks block 0 before the vault.grant broadcast (leg 2): a flip sends nothing", async () => {
    chain.subBound = true; chain.bondExists = false; // leg 1 skipped, leg 2 would grant
    chain.genesis = (n) => (n === 0 ? R1006 : R1005);
    await startSigner();
    const r = await postGrant(grantBody());
    expect(r.status).toBe(412);
    expect(broadcasts()).toEqual([]);
  });

  it("re-checks block 0 before the gas top-up broadcast (leg 3): a flip sends nothing", async () => {
    chain.balance = "0x0"; // legs 1 and 2 skipped, leg 3 would top up
    chain.genesis = (n) => (n === 0 ? R1006 : R1005);
    await startSigner();
    const r = await postGrant(grantBody());
    expect(r.status).toBe(412);
    expect(broadcasts()).toEqual([]);
  });

  it("re-checks block 0 after a receipt: a flip raises an ALARM and the order is not recorded done", async () => {
    chain.subBound = false; chain.acceptBroadcasts = true; // leg 1 mints and gets a receipt
    chain.genesis = (n) => (n <= 1 ? R1006 : R1005); // start, pre-send ok; post-receipt flipped
    await startSigner();
    const r = await postGrant(grantBody());
    expect(r.status).toBe(502);
    expect(r.json.error).toBe("genesis_changed_after_broadcast");
    expect(broadcasts().length).toBe(1);
    expect(signerOut).toMatch(/ALARM genesis_changed_after_broadcast/);
    const saved = JSON.parse(readFileSync(join(dir, "state.json"), "utf8"));
    expect(saved.orders[`${R1006}/order-1`]).toBeUndefined(); // released, re-triable
  });

  it("all legs skipped on state read from another generation: rejected before success is recorded", async () => {
    // The start check sees r1006; the RPC then serves r1005, where this member is
    // already fully granted (sub bound, bond clone, gas), so every leg skips and
    // neither send() nor receipt() runs. The success path must still re-check.
    chain.genesis = (n) => (n === 0 ? R1006 : R1005);
    await startSigner();
    const r = await postGrant(grantBody());
    expect(r.status).toBe(412);
    expect(r.json.status).toBeUndefined();
    expect(broadcasts()).toEqual([]);
    const saved = JSON.parse(readFileSync(join(dir, "state.json"), "utf8"));
    expect(saved.orders[`${R1006}/order-1`]).toBeUndefined(); // no completed entry
    expect(signerOut).toMatch(/grant refused: genesis_mismatch/);
  });

  it("a broadcast whose receipt is on the pinned generation completes", async () => {
    chain.subBound = false; chain.acceptBroadcasts = true; // mint; legs 2/3 skip (bond exists, balance high)
    await startSigner();
    const r = await postGrant(grantBody());
    expect(r.status).toBe(200);
    expect(r.json.sbtTxHash).toBe(TX_HASH);
    expect(r.json.status).toBe("granted");
  });

  it("/health reports the signer RPC's block-0 hash, or null when the lookup fails", async () => {
    await startSigner();
    const h = (await (await fetch(`${signerUrl}/health`)).json()) as { genesis: string | null };
    expect(h.genesis).toBe(R1006);
    chain.genesis = () => "error";
    const h2 = (await (await fetch(`${signerUrl}/health`)).json()) as { genesis: string | null };
    expect(h2.genesis).toBeNull();
  });

  it("the refusal log line is neutral: no key, no token, no sub", async () => {
    await startSigner();
    await postGrant(grantBody({ expectedGenesis: R1005 }));
    const line = signerOut.split("\n").find((l) => l.includes("grant refused")) ?? "";
    expect(line).not.toContain(TOKEN);
    expect(line).not.toContain("sub-1");
  });
});

describe("treasury signer: idempotency ledger is per chain generation (#70 P1-1)", { timeout: 30_000 }, () => {
  const STALE = { orderId: "order-1", fundTxHash: null, vaultTxHash: "0x" + "aa".repeat(32), sbtTxHash: "0x" + "bb".repeat(32), sbtTokenId: "3", status: "granted" };

  it("a completed entry from an earlier generation is NOT replayed: the grant runs again on this chain", async () => {
    chain.subBound = false; // the r1006 chain has no SBT for this sub
    await startSigner({ day: "", spentToday: "0", orders: { "order-1": { done: true, result: STALE } } });
    const r = await postGrant(grantBody());
    // The stale r1005 hashes must never come back as a success.
    expect(r.json.vaultTxHash).toBeUndefined();
    expect(r.status).toBe(502);
    expect(broadcasts().length).toBe(1); // the mint was attempted on this chain
  });

  it("a completed entry from THIS generation still replays without touching the chain", async () => {
    const result = { ...STALE, genesis: R1006 };
    await startSigner({ day: "", spentToday: "0", orders: { [`${R1006}/order-1`]: { done: true, result } } });
    const r = await postGrant(grantBody());
    expect(r.status).toBe(200);
    expect(r.json).toEqual(result);
    expect(legReads()).toEqual([]);
  });

  it("a successful grant is recorded under the generation-scoped key", async () => {
    await startSigner();
    const r = await postGrant(grantBody());
    expect(r.status).toBe(200);
    const saved = JSON.parse(readFileSync(join(dir, "state.json"), "utf8"));
    expect(Object.keys(saved.orders)).toEqual([`${R1006}/order-1`]);
  });
});
