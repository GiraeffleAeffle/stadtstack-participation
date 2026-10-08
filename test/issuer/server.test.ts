import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startServer, type ServerRuntime } from "../../src/server.ts";
import { openDatabase } from "../../src/shared/db.ts";
import { buildAnchor, signalHash, VoteStore, type Hex } from "../../src/vote/index.ts";
import { chainFor, metadata } from "../vote/helpers.ts";
import { policyInput } from "./fixtures.ts";

test("server binds a random local port, publishes policy and mounts the vote lane", async () => {
  const directory = await mkdtemp(join(tmpdir(), "stadtstack-issuer-"));
  let runtime: ServerRuntime | undefined;
  try {
    const path = join(directory, "policy.json");
    await writeFile(path, JSON.stringify(policyInput()));
    runtime = await startServer({ POLICY_PATH: path, DATABASE_PATH: ":memory:", ISSUER_SIGNING_KEY_SEED_HEX: "51".repeat(32), PORT: "0" });
    const address = runtime.server.address();
    assert.ok(address && typeof address !== "string");
    const origin = `http://127.0.0.1:${address.port}`;
    const response = await fetch(`${origin}/v1/policy`);
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), policyInput());
    assert.equal(response.headers.get("cache-control"), "no-store");
    assert.equal(response.headers.get("set-cookie"), null);
    const election = await fetch(`${origin}/v1/elections/0x${"01".repeat(32)}`);
    assert.equal(election.status, 404);
    assert.deepEqual(await election.json(), { error: "election_unknown" });
    const invalid = await fetch(`${origin}/v1/elections/not-an-id/ballots`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
    assert.equal(invalid.status, 400);
    assert.deepEqual(await invalid.json(), { ok: false, code: "election_id_invalid" });
  } finally { await runtime?.close(); await rm(directory, { recursive: true, force: true }); }
});

test("server requires exactly one issuer signing-key source before opening resources", async () => {
  await assert.rejects(startServer({ POLICY_PATH: "unused", DATABASE_PATH: ":memory:" }), /server_configuration_invalid/u);
  await assert.rejects(startServer({ POLICY_PATH: "unused", DATABASE_PATH: ":memory:", ISSUER_SIGNING_KEY_FILE: "unused", ISSUER_SIGNING_KEY_SEED_HEX: "51".repeat(32) }), /server_configuration_invalid/u);
});

test("server keys ballot rate limits by the trusted proxy header, not the shared proxy socket", async () => {
  const directory = await mkdtemp(join(tmpdir(), "stadtstack-proxy-"));
  let runtime: ServerRuntime | undefined;
  try {
    const databasePath = join(directory, "eligibility.sqlite");
    const now = Math.floor(Date.now() / 1000);
    const electionMetadata = { ...metadata("proxy-keys"), opensAt: now - 60, closesAt: now + 3_600 };
    const nullifier: Hex = `0x${"0".repeat(63)}7`;
    let scope: Hex;
    const db = openDatabase(databasePath);
    try {
      const store = new VoteStore(db);
      const anchor = await buildAnchor({ async listEligibleCommitments() { return [`0x${"0".repeat(63)}1`, `0x${"0".repeat(63)}2`]; } },
        { metadata: electionMetadata, anchoredAt: now - 120, signal: new AbortController().signal });
      const draft = store.putElection(electionMetadata, anchor);
      const mirror = store.openElection(electionMetadata.electionId, chainFor({ ...draft, state: "open" }));
      scope = mirror.scope;
      // A stored nullifier makes every request fail after the limiter and before proof verification.
      assert.equal(store.insertBallot({ schemaVersion: "advisory_ballot_v1", electionId: mirror.electionId, choiceIndex: 0, nullifier, signalHash: signalHash(0, scope), proof: "0x00" }), true);
    } finally { db.close(); }
    const policyPath = join(directory, "policy.json");
    await writeFile(policyPath, JSON.stringify(policyInput()));
    runtime = await startServer({ POLICY_PATH: policyPath, DATABASE_PATH: databasePath, ISSUER_SIGNING_KEY_SEED_HEX: "51".repeat(32), PORT: "0", CLIENT_KEY_HEADER: "X-Real-IP" });
    const address = runtime.server.address();
    assert.ok(address && typeof address !== "string");
    const body = JSON.stringify({ schemaVersion: "advisory_ballot_v1", electionId: electionMetadata.electionId, choiceIndex: 0, nullifier, signalHash: signalHash(0, scope), proof: "0x00" });
    const post = (clientAddress: string) => fetch(`http://127.0.0.1:${address.port}/v1/elections/${electionMetadata.electionId}/ballots`,
      { method: "POST", headers: { "content-type": "application/json", "x-real-ip": clientAddress }, body });
    for (let attempt = 0; attempt < 5; attempt++) assert.equal((await post("198.51.100.7")).status, 409);
    const limited = await post("198.51.100.7");
    assert.equal(limited.status, 429);
    assert.deepEqual(await limited.json(), { ok: false, code: "rate_limited" });
    assert.equal((await post("198.51.100.8")).status, 409);
  } finally { await runtime?.close(); await rm(directory, { recursive: true, force: true }); }
});

test("server rejects an unsafe client-key header name and a Röbel adapter without RPC", async () => {
  const directory = await mkdtemp(join(tmpdir(), "stadtstack-config-"));
  try {
    const attestorPolicy = join(directory, "policy.json");
    await writeFile(attestorPolicy, JSON.stringify(policyInput()));
    await assert.rejects(startServer({ POLICY_PATH: attestorPolicy, DATABASE_PATH: ":memory:", ISSUER_SIGNING_KEY_SEED_HEX: "51".repeat(32), PORT: "0", CLIENT_KEY_HEADER: "x-real-ip\r\nx" }), /server_configuration_invalid/u);
    const roebelPolicy = join(directory, "roebel-policy.json");
    await writeFile(roebelPolicy, JSON.stringify({ ...policyInput(), adapter: { kind: "roebel_citizen_nft_v1", chainId: 100, contractAddress: `0x${"11".repeat(20)}`,
      expectedCodeHash: `0x${"22".repeat(32)}`, blockTag: "finalized", walletProofMaxAgeSeconds: 300 } }));
    await assert.rejects(startServer({ POLICY_PATH: roebelPolicy, DATABASE_PATH: ":memory:", ISSUER_SIGNING_KEY_SEED_HEX: "51".repeat(32), PORT: "0" }), /server_configuration_invalid/u);
  } finally { await rm(directory, { recursive: true, force: true }); }
});
