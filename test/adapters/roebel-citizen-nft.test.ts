import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { spawn } from "node:child_process";
import type { ChildProcess } from "node:child_process";
import { once } from "node:events";
import { createServer } from "node:net";
import { readFile } from "node:fs/promises";
import { createServer as createHttpServer } from "node:http";
import { createPublicClient, createWalletClient, encodeFunctionData, getCreate2Address, hashMessage, http, keccak256, serializeErc6492Signature } from "viem";
import type { Abi, Address, Hex, PublicClient, WalletClient, Transport } from "viem";
import { mnemonicToAccount } from "viem/accounts";
import type { HDAccount } from "viem/accounts";
import { foundry } from "viem/chains";
import { RoebelCitizenNftAdapter, validateRoebelCitizenNftConfig, walletProofMessage } from "../../src/adapters/roebel-citizen-nft.ts";
import type { RoebelCitizenNftConfig } from "../../src/adapters/roebel-citizen-nft.ts";
import type { EligibilityCheckInput } from "../../src/shared/seams.ts";

// Public Anvil test mnemonic; never a production key.
const account = mnemonicToAccount("test test test test test test test test test test test junk");
const fixtures = JSON.parse(await readFile(new URL("../fixtures/evm-mocks/bytecode.json", import.meta.url), "utf8")) as Record<string, { abi: Abi; bytecode: Hex }>;
let process: ChildProcess;
let rpcUrl: string;
let citizen: Address;
let wallet: Address;
let factory: Address;
let config: RoebelCitizenNftConfig;
let adapter: RoebelCitizenNftAdapter;
let publicClient: PublicClient;
let walletClient: WalletClient<Transport, typeof foundry, HDAccount>;

const request: EligibilityCheckInput = {
  municipalityId: "roebel", policyVersion: "roebel-v1", subjectPubkey: "ab".repeat(32),
  purpose: { kind: "commitment_enrollment", commitment: `0x${"01".repeat(32)}` },
  requestId: "cd".repeat(32), evidence: null, now: 1_800_000_000, signal: new AbortController().signal,
};

before(async () => {
  const server = createServer();
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  assert(address && typeof address !== "string");
  const port = address.port;
  const closed = Promise.withResolvers<void>();
  server.close(error => error ? closed.reject(error) : closed.resolve());
  await closed.promise;
  rpcUrl = `http://127.0.0.1:${port}`;
  process = spawn("anvil", ["--host", "127.0.0.1", "--port", String(port)], { stdio: ["ignore", "pipe", "pipe"] });
  const ready = Promise.withResolvers<void>();
  let output = "";
  process.stdout!.on("data", (chunk: Buffer) => {
    output += chunk.toString();
    if (output.includes(`Listening on 127.0.0.1:${port}`)) ready.resolve();
  });
  process.once("error", ready.reject);
  process.once("exit", code => ready.reject(new Error(`anvil exited before startup: ${code}`)));
  await ready.promise;
  publicClient = createPublicClient({ transport: http(rpcUrl, { retryCount: 0, timeout: 200 }) });
  walletClient = createWalletClient({ chain: foundry, account, transport: http(rpcUrl, { retryCount: 0 }) });
  for (const name of ["CitizenMock", "WalletMock", "WalletFactoryMock"]) {
    const fixture = fixtures[name]!;
    const hash = await walletClient.deployContract({ ...fixture, account, chain: foundry });
    const receipt = await publicClient.waitForTransactionReceipt({ hash });
    assert(receipt.contractAddress);
    if (name === "CitizenMock") citizen = receipt.contractAddress;
    else if (name === "WalletMock") wallet = receipt.contractAddress;
    else factory = receipt.contractAddress;
  }
  const code = await publicClient.getCode({ address: citizen });
  assert(code);
  config = { kind: "roebel_citizen_nft_v1", chainId: 31337, contractAddress: citizen.toLowerCase() as Address, expectedCodeHash: keccak256(code), blockTag: "latest", walletProofMaxAgeSeconds: 300 };
  adapter = new RoebelCitizenNftAdapter(config, { rpcUrl });
});

after(async () => {
  if (process && process.exitCode === null) {
    const exited = once(process, "exit");
    process.kill("SIGTERM");
    await exited;
  }
});

async function setActive(address: Address, active: boolean): Promise<void> {
  const hash = await walletClient.writeContract({ address: citizen, abi: fixtures.CitizenMock!.abi, functionName: "setActive", args: [address, active], account, chain: foundry });
  await publicClient.waitForTransactionReceipt({ hash });
}

async function eoaInput(overrides: Partial<EligibilityCheckInput> = {}, issuedAt = request.now): Promise<EligibilityCheckInput> {
  const signature = await account.signMessage({ message: walletProofMessage(request, issuedAt) });
  return { ...request, evidence: { wallet: account.address, signature, issuedAt }, ...overrides };
}

test("EOA active and inactive; private reference is lowercase and rechecks deactivation", async () => {
  await setActive(account.address, true);
  const input = await eoaInput();
  assert.deepEqual(await adapter.check(input), { state: "active", effectiveAt: request.now, validUntil: null, evidenceRef: account.address.toLowerCase() });
  await setActive(account.address, false);
  assert.deepEqual(await adapter.check(input), { state: "inactive", reason: "citizen_inactive" });
  assert.deepEqual(await adapter.recheck({ ...request, evidenceRef: account.address.toLowerCase() }), { state: "inactive", reason: "citizen_inactive" });
});

test("unexpected bytecode and wrong chain fail closed", async () => {
  await setActive(account.address, true);
  const wrongCode = new RoebelCitizenNftAdapter({ ...config, expectedCodeHash: `0x${"00".repeat(32)}` }, { rpcUrl });
  assert.deepEqual(await wrongCode.check(await eoaInput()), { state: "inactive", reason: "code_hash_mismatch" });
  const wrongChain = new RoebelCitizenNftAdapter({ ...config, chainId: 100 }, { rpcUrl });
  assert.deepEqual(await wrongChain.check(await eoaInput()), { state: "inactive", reason: "chain_mismatch" });
});

test("ERC-1271 valid signature succeeds and invalid signature fails", async () => {
  await setActive(wallet, true);
  const hash = await walletClient.writeContract({ address: wallet, abi: fixtures.WalletMock!.abi, functionName: "approve", args: [hashMessage(walletProofMessage(request, request.now))], account, chain: foundry });
  await publicClient.waitForTransactionReceipt({ hash });
  const input = { ...request, evidence: { wallet, signature: `0x42${"00".repeat(64)}`, issuedAt: request.now } };
  assert.deepEqual(await adapter.check(input), { state: "active", effectiveAt: request.now, validUntil: null, evidenceRef: wallet.toLowerCase() });
  assert.deepEqual(await adapter.check({ ...input, evidence: { ...input.evidence, signature: `0x43${"00".repeat(64)}` } }), { state: "inactive", reason: "wallet_proof_invalid" });
});

test("ERC-6492 counterfactual wallet verifies without deploying it on chain", async () => {
  const salt = `0x${"12".repeat(32)}` as Hex;
  const counterfactual = getCreate2Address({ from: factory, salt, bytecodeHash: keccak256(fixtures.WalletMock!.bytecode) });
  await setActive(counterfactual, true);
  assert.equal(await publicClient.getCode({ address: counterfactual }), undefined);
  const signature = serializeErc6492Signature({
    address: factory,
    data: encodeFunctionData({ abi: fixtures.WalletFactoryMock!.abi, functionName: "deploy", args: [salt, hashMessage(walletProofMessage(request, request.now))] }),
    signature: `0x42${"00".repeat(64)}`,
  });
  assert.deepEqual(await adapter.check({ ...request, evidence: { wallet: counterfactual, signature, issuedAt: request.now } }), {
    state: "active", effectiveAt: request.now, validUntil: null, evidenceRef: counterfactual.toLowerCase(),
  });
  assert.equal(await publicClient.getCode({ address: counterfactual }), undefined);
});

test("proof age includes the exact boundary and rejects stale or future proofs", async () => {
  await setActive(account.address, true);
  assert.equal((await adapter.check(await eoaInput({}, request.now - 300))).state, "active");
  for (const issuedAt of [request.now - 301, request.now + 1]) {
    assert.deepEqual(await adapter.check(await eoaInput({}, issuedAt)), { state: "inactive", reason: "wallet_proof_invalid" });
  }
});

test("proof binds subject, complete purpose, request, municipality and policy", async () => {
  await setActive(account.address, true);
  const overrides: Partial<EligibilityCheckInput>[] = [
    { subjectPubkey: "ef".repeat(32) }, { requestId: "00".repeat(32) },
    { municipalityId: "another-town" }, { policyVersion: "other-v1" },
    { purpose: { kind: "commitment_enrollment", commitment: `0x${"02".repeat(32)}` } },
    { purpose: { kind: "adoption_receipt", participantSuggestionId: "11".repeat(32), topicId: "urn:stadtstack:topic:municipality:roebel:roads" } },
  ];
  for (const override of overrides) assert.deepEqual(await adapter.check(await eoaInput(override)), { state: "inactive", reason: "wallet_proof_invalid" });
});

test("unreachable RPC and cancellation fail closed", async () => {
  const unavailable = new RoebelCitizenNftAdapter(config, { rpcUrl: "http://127.0.0.1:0", timeoutMs: 100 });
  assert.deepEqual(await unavailable.check(await eoaInput()), { state: "inactive", reason: "rpc_failed" });
  assert.deepEqual(await unavailable.recheck({ ...request, evidenceRef: account.address.toLowerCase() }), { state: "inactive", reason: "rpc_failed" });
  const controller = new AbortController();
  controller.abort();
  assert.deepEqual(await adapter.check(await eoaInput({ signal: controller.signal })), { state: "inactive", reason: "rpc_failed" });
});

test("stalled RPC times out and an in-flight request honours cancellation", async () => {
  for (const cancel of [false, true]) {
    const controller = new AbortController();
    const server = createHttpServer(() => {
      if (cancel) controller.abort();
      // Deliberately never respond: exercise the real fetch/AbortSignal timeout.
      // Fake clocks cannot control the external HTTP connection lifecycle.
    });
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    const address = server.address();
    assert(address && typeof address !== "string");
    try {
      const stalled = new RoebelCitizenNftAdapter(config, { rpcUrl: `http://127.0.0.1:${address.port}`, timeoutMs: cancel ? 5_000 : 50 });
      assert.deepEqual(await stalled.check(await eoaInput({ signal: controller.signal })), { state: "inactive", reason: "rpc_failed" });
    } finally {
      server.closeAllConnections();
      const closed = Promise.withResolvers<void>();
      server.close(error => error ? closed.reject(error) : closed.resolve());
      await closed.promise;
    }
  }
});

test("malformed evidence and config are rejected without coercion", async () => {
  for (const evidence of [null, {}, { wallet: account.address, signature: "0x42", issuedAt: request.now, extra: true }]) {
    assert.deepEqual(await adapter.check({ ...request, evidence }), { state: "inactive", reason: "wallet_proof_invalid" });
  }
  for (const change of [{ chainId: 0 }, { blockTag: "pending" }, { walletProofMaxAgeSeconds: 0 }, { extra: true }]) {
    assert.throws(() => validateRoebelCitizenNftConfig({ ...config, ...change }));
  }
});
