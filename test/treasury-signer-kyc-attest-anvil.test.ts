/**
 * Treasury signer `POST /kyc-attest` against the REAL CitrateMemberSBT on a local anvil.
 *
 * The SBT creation bytecode comes from citrate-chain (fixture
 * test/fixtures/treasury-signer/CitrateMemberSBT.json, provenance inside). The SBT is
 * deployed to a throwaway anvil chain (chain id 40204) owned by a key generated per run,
 * and the real `services/treasury-signer/server.mjs` runs with that key. Identity's
 * `GET /kyc/status` is an in-test double. Nothing leaves 127.0.0.1.
 *
 * Needs `anvil` (Foundry) on PATH; without it the suite is skipped and says why.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { createServer, type Server } from "node:http";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import type { AddressInfo } from "node:net";
import {
  createPublicClient, createWalletClient, defineChain, http, keccak256, parseAbi, toHex, type Address, type Hex,
} from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";

const HERE = dirname(fileURLToPath(import.meta.url));
const SERVER = join(HERE, "..", "services", "treasury-signer", "server.mjs");
const FIXTURE = JSON.parse(readFileSync(join(HERE, "fixtures", "treasury-signer", "CitrateMemberSBT.json"), "utf8")) as { bytecode: Hex };
const HAVE_ANVIL = spawnSync("anvil", ["--version"]).status === 0;
if (!HAVE_ANVIL) console.warn("treasury-signer-kyc-attest-anvil: SKIPPED (anvil not on PATH)");

const SBT_ABI = parseAbi([
  "constructor(address initialOwner)",
  "function mintMember(address to, bytes32 subHash, uint64 termStart, uint64 termEnd) returns (uint256)",
  "function tokenIdForSub(bytes32 subHash) view returns (uint256)",
  "function isKycVerified(uint256 tokenId) view returns (bool)",
  "function setKycVerified(uint256 tokenId, bool verified)",
  "function quarantine(uint256 tokenId)",
  "function revoke(uint256 tokenId)",
]);
const TOKEN = "test-only-bearer";
const KYC_SECRET = "test-only-kyc-status-secret";
const VAULT = "0x1111111111111111111111111111111111111111";

async function freePort(): Promise<number> {
  const s = createServer();
  await new Promise<void>((r) => s.listen(0, "127.0.0.1", () => r()));
  const { port } = s.address() as AddressInfo;
  await new Promise<void>((r) => s.close(() => r()));
  return port;
}
async function waitFor(fn: () => Promise<boolean> | boolean, what: string, ms = 20_000) {
  const end = Date.now() + ms;
  for (;;) {
    try { if (await fn()) return; } catch { /* not up yet */ }
    if (Date.now() > end) throw new Error(`${what} did not come up`);
    await new Promise((r) => setTimeout(r, 50));
  }
}

const kycStatus = new Map<string, string>();
let anvil: ChildProcess | null = null;
let signer: ChildProcess | null = null;
let kycSrv: Server;
let rpcUrl = "";
let signerUrl = "";
let signerOut = "";
let dir = "";
let genesis: Hex;
let sbt: Address;
const ownerKey = generatePrivateKey();
const owner = privateKeyToAccount(ownerKey);
const chain = defineChain({ id: 40204, name: "anvil-40204", nativeCurrency: { name: "SALT", symbol: "SALT", decimals: 18 }, rpcUrls: { default: { http: ["http://127.0.0.1"] } } });
let pub: ReturnType<typeof createPublicClient>;
let wallet: ReturnType<typeof createWalletClient>;

const members = {
  a: { sub: "anvil-sub-a", wallet: privateKeyToAccount(generatePrivateKey()).address },
  b: { sub: "anvil-sub-b", wallet: privateKeyToAccount(generatePrivateKey()).address },
  pending: { sub: "anvil-sub-pending", wallet: privateKeyToAccount(generatePrivateKey()).address },
  quarantined: { sub: "anvil-sub-q", wallet: privateKeyToAccount(generatePrivateKey()).address },
  revoked: { sub: "anvil-sub-r", wallet: privateKeyToAccount(generatePrivateKey()).address },
  replaced: { sub: "anvil-sub-x", wallet: privateKeyToAccount(generatePrivateKey()).address },
};
const rpcCall = async (method: string, params: unknown[]) => {
  const r = await fetch(rpcUrl, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) });
  const j = (await r.json()) as { result?: any; error?: { message: string } };
  if (j.error) throw new Error(`${method}: ${j.error.message}`);
  return j.result;
};
const tokenOf = async (sub: string) => pub.readContract({ address: sbt, abi: SBT_ABI, functionName: "tokenIdForSub", args: [keccak256(toHex(sub))] });
const flagOf = async (sub: string) => pub.readContract({ address: sbt, abi: SBT_ABI, functionName: "isKycVerified", args: [await tokenOf(sub)] });
async function ownerWrite(functionName: "mintMember" | "quarantine" | "revoke", args: readonly unknown[]) {
  const hash = await wallet.writeContract({ address: sbt, abi: SBT_ABI, functionName, args, account: owner, chain } as never);
  const r = await pub.waitForTransactionReceipt({ hash });
  if (r.status !== "success") throw new Error(`${functionName} reverted`);
}
async function attest(over: Record<string, unknown>) {
  const res = await fetch(`${signerUrl}/kyc-attest`, {
    method: "POST", headers: { authorization: `Bearer ${TOKEN}`, "content-type": "application/json" },
    body: JSON.stringify({ chainId: 40204, contracts: { sbt }, expectedGenesis: genesis, ...over }),
  });
  return { status: res.status, json: (await res.json()) as Record<string, unknown> };
}

describe.skipIf(!HAVE_ANVIL)("POST /kyc-attest on anvil with the real CitrateMemberSBT", { timeout: 60_000 }, () => {
  beforeAll(async () => {
    const port = await freePort();
    rpcUrl = `http://127.0.0.1:${port}`;
    anvil = spawn("anvil", ["--port", String(port), "--chain-id", "40204", "--accounts", "0", "--silent"], { stdio: "ignore" });
    const rpc = (method: string, params: unknown[]) => fetch(rpcUrl, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) });
    await waitFor(async () => (await rpc("eth_chainId", [])).ok, "anvil");
    await rpc("anvil_setBalance", [owner.address, toHex(10n ** 21n)]);
    pub = createPublicClient({ chain, transport: http(rpcUrl) });
    wallet = createWalletClient({ account: owner, chain, transport: http(rpcUrl) });
    genesis = (await pub.getBlock({ blockNumber: 0n })).hash!;

    const hash = await wallet.deployContract({ abi: SBT_ABI, bytecode: FIXTURE.bytecode, args: [owner.address], account: owner, chain });
    sbt = (await pub.waitForTransactionReceipt({ hash })).contractAddress!;
    for (const m of Object.values(members)) await ownerWrite("mintMember", [m.wallet, keccak256(toHex(m.sub)), 1n, 4_000_000_000n]);
    await ownerWrite("quarantine", [await tokenOf(members.quarantined.sub)]);
    await ownerWrite("revoke", [await tokenOf(members.revoked.sub)]);
    for (const m of [members.a, members.b, members.quarantined, members.revoked, members.replaced]) kycStatus.set(m.sub, "verified");
    kycStatus.set(members.pending.sub, "pending");

    kycSrv = createServer((req, res) => {
      const u = new URL(req.url ?? "/", "http://x");
      if (u.pathname !== "/kyc/status" || req.headers.authorization !== `Bearer ${KYC_SECRET}`) { res.writeHead(401); res.end("{}"); return; }
      const sub = u.searchParams.get("sub") ?? "";
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ sub, kyc_status: kycStatus.get(sub) ?? "none" }));
    });
    await new Promise<void>((r) => kycSrv.listen(0, "127.0.0.1", () => r()));

    dir = mkdtempSync(join(tmpdir(), "signer-kyc-anvil-"));
    const sport = await freePort();
    signerUrl = `http://127.0.0.1:${sport}`;
    signer = spawn(process.execPath, [SERVER], {
      env: {
        PATH: process.env.PATH ?? "", CITRATE_RPC_URL: rpcUrl, CITRATE_CHAIN_ID: "40204",
        MEMBERSHIP_STAKE_VAULT_ADDRESS: VAULT, CITRATE_MEMBER_SBT_ADDRESS: sbt,
        TREASURY_SIGNER_TOKEN: TOKEN, TREASURY_SIGNER_KEY: ownerKey,
        TREASURY_STATE_FILE: join(dir, "state.json"), PORT: String(sport),
        KYC_STATUS_URL: `http://127.0.0.1:${(kycSrv.address() as AddressInfo).port}`, KYC_STATUS_SECRET: KYC_SECRET,
        KYC_ATTEST_DAILY_CAP: "5",
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    signer.stdout!.on("data", (c) => { signerOut += String(c); });
    signer.stderr!.on("data", (c) => { signerOut += String(c); });
    await waitFor(() => signerOut.includes("citrate-treasury-signer on") || signer!.exitCode != null, "signer");
    if (signer.exitCode != null) throw new Error(`signer exited: ${signerOut}`);
  });

  afterAll(async () => {
    for (const p of [signer, anvil]) if (p && p.exitCode == null) { const e = new Promise((r) => p.once("exit", r)); p.kill("SIGTERM"); await e; }
    if (kycSrv) await new Promise<void>((r) => kycSrv.close(() => r()));
    if (dir) rmSync(dir, { recursive: true, force: true });
  });

  it("sets the flag on the real contract for a verified member, and the tx is the signer's setKycVerified", async () => {
    expect(await flagOf(members.a.sub)).toBe(false);
    const r = await attest({ member: members.a.wallet, sub: members.a.sub });
    expect(r.status).toBe(200);
    expect(r.json.status).toBe("attested");
    expect(await flagOf(members.a.sub)).toBe(true);
    const tx = await pub.getTransaction({ hash: r.json.txHash as Hex });
    expect(tx.from.toLowerCase()).toBe(owner.address.toLowerCase());
    expect(tx.to?.toLowerCase()).toBe(sbt.toLowerCase());
    expect(tx.value).toBe(0n);
    expect(tx.input.slice(0, 10)).toBe("0x8effaab4"); // setKycVerified(uint256,bool)
    expect(r.json.tokenId).toBe(String(await tokenOf(members.a.sub)));
  });

  it("is idempotent on the real contract: a second call sends nothing", async () => {
    const before = await pub.getBlockNumber();
    const r = await attest({ member: members.a.wallet, sub: members.a.sub });
    expect(r.status).toBe(200);
    expect(r.json.status).toBe("already_attested");
    expect(r.json.txHash).toBeNull();
    expect(await pub.getBlockNumber()).toBe(before);
  });

  it("refuses a member whose stored record is pending: the flag stays false, nothing mined", async () => {
    const before = await pub.getBlockNumber();
    const r = await attest({ member: members.pending.wallet, sub: members.pending.sub });
    expect(r.status).toBe(403);
    expect(await flagOf(members.pending.sub)).toBe(false);
    expect(await pub.getBlockNumber()).toBe(before);
  });

  it("refuses a wallet that does not own the subject's SBT (sub b with member a's wallet)", async () => {
    const before = await pub.getBlockNumber();
    const r = await attest({ member: members.a.wallet, sub: members.b.sub });
    expect(r.status).toBe(422);
    expect(r.json.error).toBe("member_mismatch");
    expect(await flagOf(members.b.sub)).toBe(false);
    expect(await pub.getBlockNumber()).toBe(before);
  });

  it("refuses quarantined and revoked memberships before sending", async () => {
    const before = await pub.getBlockNumber();
    const q = await attest({ member: members.quarantined.wallet, sub: members.quarantined.sub });
    expect(q.status).toBe(422);
    expect(q.json.error).toBe("member_quarantined");
    const v = await attest({ member: members.revoked.wallet, sub: members.revoked.sub });
    expect(v.status).toBe(422);
    expect(v.json.error).toBe("member_revoked");
    expect(await pub.getBlockNumber()).toBe(before);
  });

  it("refuses a different generation pin (412), nothing mined", async () => {
    const before = await pub.getBlockNumber();
    const r = await attest({ member: members.b.wallet, sub: members.b.sub, expectedGenesis: "0x" + "11".repeat(32) });
    expect(r.status).toBe(412);
    expect(await flagOf(members.b.sub)).toBe(false);
    expect(await pub.getBlockNumber()).toBe(before);
  });

  it("attests the second member; the refusals spent no cap", async () => {
    const r = await attest({ member: members.b.wallet, sub: members.b.sub });
    expect(r.status).toBe(200);
    expect(await flagOf(members.b.sub)).toBe(true);
    const h = (await (await fetch(`${signerUrl}/health`)).json()) as { kycAttest: { attestedToday: number } };
    expect(h.kycAttest.attestedToday).toBe(2);
  });

  it("a signer tx replaced in the pool (same nonce) is reported as a failure, never as attested", async () => {
    await rpcCall("evm_setAutomine", [false]);
    try {
      const pending = attest({ member: members.replaced.wallet, sub: members.replaced.sub });
      let tx: { nonce: string; maxFeePerGas: string; maxPriorityFeePerGas: string } | undefined;
      await waitFor(async () => {
        const pool = await rpcCall("txpool_content", []);
        const mine = Object.entries(pool.pending ?? {}).find(([from]) => from.toLowerCase() === owner.address.toLowerCase());
        tx = mine ? (Object.values(mine[1] as object)[0] as typeof tx) : undefined;
        return !!tx;
      }, "signer tx in the pool");
      await new Promise((r) => setTimeout(r, 1500)); // let the signer start watching it
      // Same nonce, higher fee, a 0-value self-send: the pool replaces the signer's tx.
      await wallet.sendTransaction({
        account: owner, chain, to: owner.address, value: 0n, nonce: Number(BigInt(tx!.nonce)),
        maxFeePerGas: BigInt(tx!.maxFeePerGas) * 3n, maxPriorityFeePerGas: BigInt(tx!.maxPriorityFeePerGas) * 3n + 1n,
      });
      await rpcCall("evm_mine", []);
      const r = await pending;
      expect(r.status).toBe(502);
      expect(r.json.error).toBe("tx_replaced");
      expect(await flagOf(members.replaced.sub)).toBe(false);
    } finally {
      await rpcCall("evm_setAutomine", [true]);
    }
  });
});
