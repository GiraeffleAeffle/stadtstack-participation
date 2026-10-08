import assert from "node:assert/strict";
import { execFile, spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { promisify } from "node:util";
import { createPublicClient, createWalletClient, http, type Address, type Hex } from "viem";
import { mnemonicToAccount } from "viem/accounts";
import { foundry } from "viem/chains";
import { getPublicKey } from "nostr-tools/pure";
import { runOperator, transactionArtifacts } from "../../src/cli/operator.ts";
import { startServer } from "../../src/server.ts";
import { canonical, digest } from "../../src/shared/canonical.ts";
import { signCanonical } from "../../src/shared/ed25519.ts";
import { nip98Header, nip98Template } from "../../src/shared/nostr.ts";
import { getElection, type ElectionMirror } from "../../src/vote/registry-client.ts";
import type { ElectionAnchor } from "../../src/vote/anchor.ts";
import { buildMerkleTree, identityCommitment, inclusionPath, VoteProver, type VoteCircuit } from "../../src/vote/index.ts";
import { attestorKeys, basis, policyInput, signed } from "../issuer/fixtures.ts";
import { electionFixture } from "../vote/helpers.ts";
const exec = promisify(execFile);
const save = (path: string, value: unknown) => writeFile(path, JSON.stringify(value));
const registry = { schemaVersion: "municipal_registry_snapshot_v1", snapshotId: "operator-test-v1", generatedAt: "2026-10-03T14:30:00.000Z", sources: [], units: [{ schemaVersion: "administrative_unit_v1", id: "strausberg", kind: "gemeinde", designation: "Stadt", officialName: "Strausberg", ars: "120640472472", ags: "12064472" }], localities: [], adjacencies: [] };

test("issuer key is PKCS8, private, and never overwritten", async (t) => {
  const dir = await mkdtemp(join(tmpdir(), "operator-key-")); t.after(() => rm(dir, { recursive: true, force: true }));
  const out = join(dir, "issuer.pem");
  const key = await runOperator(["issuer-key", "--out", out]) as { issuerPublicKey: string };
  assert.match(key.issuerPublicKey, /^[0-9a-f]{64}$/u);
  assert.match(await readFile(out, "utf8"), /^-----BEGIN PRIVATE KEY-----/u);
  assert.equal((await stat(out)).mode & 0o777, 0o600);
  await assert.rejects(runOperator(["issuer-key", "--out", out]), /EEXIST/u);
});

test("Safe and cast artifacts encode matching deterministic calls without signing keys", async (t) => {
  const fixture = await electionFixture([identityCommitment(1n)]); t.after(() => fixture.db.close());
  const input = { chainId: 31337, address: `0x${"12".repeat(20)}` as Address, rpcUrl: "http://127.0.0.1:8545", election: fixture.mirror };
  const a = transactionArtifacts(input);
  assert.deepEqual(a, transactionArtifacts(input));
  assert.equal(a.batch.chainId, "31337");
  assert.equal(a.batch.transactions[0]!.value, "0");
  assert.match(a.castCommand, /openElection\(bytes32,string,bytes32,uint8,bytes32,uint256,uint64,uint64\)/u);
  assert.doesNotMatch(a.castCommand, /private-key|mnemonic/u);
  const close = transactionArtifacts({ ...input, tally: { tallyHash: `0x${"ab".repeat(32)}`, totalAccepted: 2 } });
  assert.match(close.castCommand, /closeElection/u);
  assert.notEqual(close.batch.transactions[0]!.data, a.batch.transactions[0]!.data);
});

test("policy derives Strausberg AGS and canonical snapshot pin and prints verifier projection", async (t) => {
  const dir = await mkdtemp(join(tmpdir(), "operator-policy-")); t.after(() => rm(dir, { recursive: true, force: true }));
  const original = policyInput();
  await save(join(dir, "basis.json"), original.basis);
  await save(join(dir, "adapter.json"), original.adapter);
  await save(join(dir, "registry.json"), registry);
  const result = await runOperator(["policy", "--registry", join(dir, "registry.json"), "--out", join(dir, "policy.json"), "--municipality", "strausberg", "--policy-version", "pilot-v1", "--issuer", original.issuer, "--issuer-key-id", original.issuerKeyId, "--issuer-public-key", original.issuerPublicKey, "--public-base-url", original.publicBaseUrl, "--receipt-ttl-seconds", "600", "--status-max-age-seconds", "60", "--max-event-clock-skew-seconds", "30", "--allowed-agent-pubkeys", original.allowedAgentPubkeys.join(","), "--basis", join(dir, "basis.json"), "--adapter", join(dir, "adapter.json")]) as { policy: { ags: string; registry: { snapshotId: string; digest: string } }; stadtstackPolicy: { municipalityId: string; issuerPublicKey: string } };
  assert.equal(result.policy.ags, "12064472");
  assert.deepEqual(result.policy.registry, { snapshotId: registry.snapshotId, digest: `sha256:${digest(registry)}` });
  assert.equal(result.stadtstackPolicy.municipalityId, "strausberg");
  assert.equal(result.stadtstackPolicy.issuerPublicKey, original.issuerPublicKey);
  assert.deepEqual(JSON.parse(await readFile(join(dir, "policy.json"), "utf8")), result.policy);
});

test("complete local operator HTTP enrollment, real proof, chain lifecycle and result", { timeout: 300000 }, async (t) => {
  for (const binary of ["anvil", "forge"]) {
    try { await exec(binary, ["--version"]); } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") { t.skip(`${binary} unavailable`); return; }
      throw error;
    }
  }
  const dir = await mkdtemp(join(tmpdir(), "operator-flow-")); t.after(() => rm(dir, { recursive: true, force: true }));
  const listener = createServer(); listener.listen(0, "127.0.0.1"); await once(listener, "listening");
  const endpoint = listener.address(); assert(endpoint && typeof endpoint !== "string");
  const released = Promise.withResolvers<void>();
  listener.close((error) => error ? released.reject(error) : released.resolve());
  await released.promise;
  const rpcUrl = `http://127.0.0.1:${endpoint.port}`;
  const anvil = spawn("anvil", ["--host", "127.0.0.1", "--port", String(endpoint.port)], { stdio: ["ignore", "pipe", "pipe"] });
  t.after(async () => { if (anvil.exitCode === null) { const done = once(anvil, "exit"); anvil.kill("SIGTERM"); await done; } });
  const ready = Promise.withResolvers<void>();
  let logs = "";
  anvil.stdout!.on("data", (chunk: Buffer) => { logs += chunk.toString(); if (logs.includes("Listening on")) ready.resolve(); });
  anvil.once("error", ready.reject);
  anvil.once("exit", (code) => ready.reject(new Error(`anvil startup exit ${code}`)));
  await ready.promise;
  const root = new URL("../../", import.meta.url);
  // Public Anvil account 0 only. Forge links the generated verifier libraries
  // and runs the same role assertions as the operator deployment procedure.
  const anvilKey = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
  const account = mnemonicToAccount("test test test test test test test test test test test junk");
  const client = createPublicClient({ transport: http(rpcUrl) });
  const wallet = createWalletClient({ account, chain: foundry, transport: http(rpcUrl) });
  const deployment = await exec("forge", ["script", "script/DeployElectionRegistry.s.sol:DeployElectionRegistry",
    "--root", new URL("contracts", root).pathname, "--rpc-url", rpcUrl, "--private-key", anvilKey, "--broadcast", "--color", "never",
    "--cache-path", join(dir, "forge-cache")],
    { cwd: new URL("contracts", root).pathname, env: { ...process.env, ADMIN_ADDRESS: account.address, OPERATOR_ADDRESS: account.address }, maxBuffer: 4 * 1024 * 1024 });
  const registryLog = /\bElectionRegistry:?\s+(0x[0-9a-fA-F]{40})\b/u.exec(deployment.stdout);
  const verifierLog = /\bMembershipVoteVerifier:?\s+(0x[0-9a-fA-F]{40})\b/u.exec(deployment.stdout);
  assert.ok(registryLog, deployment.stdout);
  assert.ok(verifierLog, deployment.stdout);
  const registryAddress = registryLog[1]!.toLowerCase() as Address;
  assert.notEqual(await client.getCode({ address: registryAddress }), undefined);
  const keyPath = join(dir, "issuer.pem");
  const key = await runOperator(["issuer-key", "--out", keyPath]) as { issuerPublicKey: string };
  let now = Number((await client.getBlock()).timestamp);
  const original = policyInput();
  const adapter = { ...original.adapter, attestors: original.adapter.attestors.map((a) => ({ ...a, validFrom: now - 100, validUntil: now + 10000 })) };
  await save(join(dir, "adapter.json"), adapter); await save(join(dir, "basis.json"), basis);
  const policyPath = join(dir, "policy.json");
  await save(join(dir, "registry.json"), registry);
  const built = await runOperator(["policy", "--registry", join(dir, "registry.json"), "--out", policyPath, "--municipality", "strausberg", "--policy-version", "pilot-v1", "--issuer", "Strausberg issuer", "--issuer-key-id", "issuer-1", "--issuer-public-key", key.issuerPublicKey, "--public-base-url", "https://eligibility.example", "--receipt-ttl-seconds", "600", "--status-max-age-seconds", "60", "--max-event-clock-skew-seconds", "300", "--allowed-agent-pubkeys", original.allowedAgentPubkeys[0]!, "--basis", join(dir, "basis.json"), "--adapter", join(dir, "adapter.json")]) as { policy: typeof original; stadtstackPolicy: unknown };
  assert.equal(built.policy.ags, "12064472");
  assert.deepEqual(built.policy.registry, { snapshotId: registry.snapshotId, digest: `sha256:${digest(registry)}` });
  const environment = { DATABASE_PATH: join(dir, "db.sqlite"), POLICY_PATH: policyPath, ISSUER_SIGNING_KEY_FILE: keyPath, RPC_URL: rpcUrl, PUBLIC_RPC_URL: rpcUrl, DISPLAY_NAME: "Strausberg", OPERATOR_NAME: "Stadtstack", CHAIN_ID: "31337", REGISTRY_ADDRESS: registryAddress, PORT: "0" };
  const server = await startServer(environment); t.after(() => server.close());
  const serverAddress = server.server.address(); assert(serverAddress && typeof serverAddress !== "string");
  const origin = `http://127.0.0.1:${serverAddress.port}`;
  const post = async (path: string, body: unknown, subjectKey?: Uint8Array) => {
    const bytes = Buffer.from(JSON.stringify(body));
    const authorization = subjectKey ? nip98Header(signed(nip98Template({ url: `https://eligibility.example${path}`, method: "POST", body: bytes, createdAt: Math.floor(Date.now() / 1000) }), subjectKey)) : undefined;
    const response = await fetch(`${origin}${path}`, { method: "POST", body: bytes, headers: { "content-type": "application/json", ...(authorization ? { authorization } : {}) } });
    const result = await response.json(); assert.equal(response.status, path.endsWith("/ballots") ? 200 : 201, canonical(result)); return result;
  };
  const subjects = [new Uint8Array(32).fill(71), new Uint8Array(32).fill(72)];
  const secrets = [1n, 8n];
  for (let s = 0; s < subjects.length; s++) {
    for (let a = 0; a < 2; a++) {
      const core = { schemaVersion: "in_person_residency_attestation_v1", municipalityId: "strausberg", policyVersion: "pilot-v1", subjectPubkey: getPublicKey(subjects[s]!), attestorId: `attestor-${a}`, attestedAt: Math.min(now, Math.floor(Date.now() / 1000)), basis, documentKinds: ["identity_card", "residence_register"] };
      await post("/v1/attestations", { core, signature: signCanonical(attestorKeys[a]!, { domain: "in-person-residency-attestation/v1", core }) });
    }
    await post("/v1/identity-commitments", { identityCommitment: identityCommitment(secrets[s]!), evidence: null }, subjects[s]);
  }
  now = Math.max(Number((await client.getBlock()).timestamp) + 1, Math.floor(Date.now() / 1000));
  await client.request({ method: "evm_setNextBlockTimestamp" as never, params: [now] as never });
  await client.request({ method: "evm_mine" as never, params: [] as never });
  const metadataPath = join(dir, "metadata.json");
  await save(metadataPath, { electionSlug: "park", title: "Park consultation", question: "Which improvement?", choices: [{ index: 0, label: "Trees" }, { index: 1, label: "Paths" }], participationContract: { id: "park-contract", version: 1 } });
  const draft = await runOperator(["poll-draft", "--metadata", metadataPath, "--opens-at", String(Math.min(now, Math.floor(Date.now() / 1000))), "--closes-at", String(now + 100), "--out", join(dir, "open.json")], environment) as { election: ElectionMirror; anchor: ElectionAnchor; batch: { transactions: { data: Hex }[] } };
  assert.deepEqual(draft.anchor.leaves, secrets.map(identityCommitment).sort((a, b) => BigInt(a) < BigInt(b) ? -1 : 1));
  const send = async (data: Hex) => { const hash = await wallet.sendTransaction({ to: registryAddress, data }); const receipt = await client.waitForTransactionReceipt({ hash }); assert.equal(receipt.status, "success"); };
  await send(draft.batch.transactions[0]!.data);
  const id = draft.election.electionId;
  await runOperator(["poll-confirm-open", "--election-id", id], environment);
  const chain = await getElection(client, registryAddress, id);
  assert.equal(chain.anchorRoot, draft.anchor.root); assert.equal(chain.metadataHash, draft.election.metadataHash);
  const circuit = JSON.parse(await readFile(new URL("artifacts/membership_vote.json", root), "utf8")) as VoteCircuit;
  const prover = new VoteProver(circuit); t.after(() => prover.destroy());
  const tree = buildMerkleTree(draft.anchor.leaves);
  const ballot = await prover.prove({ secret: secrets[0]!, electionId: id, choiceIndex: 0, inclusion: inclusionPath(tree, identityCommitment(secrets[0]!)), anchorRoot: draft.anchor.root });
  await post(`/v1/elections/${id}/ballots`, ballot);
  await assert.rejects(runOperator(["poll-tally", id, "--out", join(dir, "early.json")], environment), /election_not_ended/u);
  await client.request({ method: "evm_setNextBlockTimestamp" as never, params: [now + 101] as never });
  await client.request({ method: "evm_mine" as never, params: [] as never });
  const counted = await runOperator(["poll-tally", id, "--out", join(dir, "close.json")], environment) as { tally: { totalAccepted: number; choices: { count: number }[] }; tallyHash: Hex; batch: { transactions: { data: Hex }[] } };
  assert.equal(counted.tally.totalAccepted, 1); assert.deepEqual(counted.tally.choices.map((c) => c.count), [1, 0]);
  await send(counted.batch.transactions[0]!.data);
  await runOperator(["poll-confirm-close", id], environment);
  const closed = await getElection(client, registryAddress, id); assert.equal(closed.closed, true); assert.equal(closed.tallyHash, counted.tallyHash); assert.equal(closed.acceptedBallots, 1n);
  const reviewPath = join(dir, "review.json");
  await save(reviewPath, { id: "park-result", methodKind: "anonymous_advisory_poll", methodVersion: "1", ruleId: "one-response", ruleVersion: "1", resultSummary: "Consultation totals.", unresolvedDissent: [], representationAudit: { targetPopulationDescription: "Municipal residents", recruitmentMethod: "Public invitation", samplingMethod: null, totalInvited: null, totalStarted: 2, totalCompleted: 2, limitations: ["Self-selection."] }, limitations: ["Advisory and non-binding."], reviewedAt: new Date((now + 102) * 1000).toISOString(), resultArtifactRef: "https://town.example/results/park", minorityReportRef: null, checksumBinding: { sourceBrief: { id: "park-brief", briefChecksum: `sha256:${"1".repeat(64)}`, briefEventId: "park-event" }, policyVersion: "pilot-v1", actorBinding: { actorId: "reviewer", actorClass: "participation_reviewer" } } });
  const result = await runOperator(["poll-result", id, "--review", reviewPath], environment) as { schemaVersion: string; authorityBinding: string; totalAccepted: number; options: { aggregateCount: number }[] };
  assert.equal(result.schemaVersion, "participation_result_v1"); assert.equal(result.authorityBinding, "none"); assert.equal(result.totalAccepted, 1); assert.deepEqual(result.options.map((o) => o.aggregateCount), [1, 0]);
});
