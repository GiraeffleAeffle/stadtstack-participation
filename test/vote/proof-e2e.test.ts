import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { BallotIntake, buildMerkleTree, buildTally, bytesHex, electionNullifier, fieldHex, identityCommitment, inclusionPath, projectParticipationResult, proofBytes, signalHash, tallyHash, VoteProver, VoteVerifier, type Hex, type ResultContext, type VoteCircuit } from "../../src/vote/index.ts";
import { digest } from "../../src/shared/canonical.ts";
import { electionFixture, metadata } from "./helpers.ts";
import { assertStadtstackConformance } from "./stadtstack-conformance.ts";

const circuit = JSON.parse(await readFile(new URL("../../artifacts/membership_vote.json", import.meta.url), "utf8")) as VoteCircuit;
const manifest = JSON.parse(await readFile(new URL("../../artifacts/manifest.json", import.meta.url), "utf8")) as { artifacts: Record<string, string>; vkHash: Hex };
const provenance = { circuitSha256: manifest.artifacts["membership_vote.json"]!, vkHash: manifest.vkHash };

const context: ResultContext = {
  id: "park-result", methodKind: "anonymous_advisory_poll", methodVersion: "1", ruleId: "one-response-per-person", ruleVersion: "1", resultSummary: "Consultation totals for the park improvements.", unresolvedDissent: [],
  representationAudit: { targetPopulationDescription: "Municipal residents", recruitmentMethod: "Public invitation", samplingMethod: null, totalInvited: null, totalStarted: 2, totalCompleted: 2, limitations: ["Self-selected participation."] }, limitations: ["Advisory and non-binding."],
  reviewedAt: "2026-08-08T00:00:05.000Z", resultArtifactRef: "synthetic://consultation/park/result", minorityReportRef: null,
  checksumBinding: { sourceBrief: { id: "park-brief", briefChecksum: `sha256:${"1".repeat(64)}`, briefEventId: "park-brief-event" }, policyVersion: "policy-v1", actorBinding: { actorId: "reviewer", actorClass: "participation_reviewer" } },
};

test("Node Keccak-ZK proof intake rejects replay, wrong signal/choice/scope/window and tampering; reproducible tally", { timeout: 180000 }, async (t) => {
  const secrets = [1n, 8n, 42n];
  const commitments = secrets.map(identityCommitment);
  const fixture = await electionFixture(commitments);
  const other = await electionFixture(commitments, metadata("other-poll"));
  const prover = new VoteProver(circuit);
  const verifier = new VoteVerifier(circuit);
  t.after(async () => { await prover.destroy(); await verifier.destroy(); fixture.db.close(); other.db.close(); });
  const tree = buildMerkleTree(fixture.anchor.leaves);
  const ballot = await prover.prove({ secret: 1n, electionId: fixture.mirror.electionId, choiceIndex: 0, inclusion: inclusionPath(tree, identityCommitment(1n)), anchorRoot: fixture.anchor.root });
  assert.equal(ballot.nullifier, electionNullifier(1n, fixture.mirror.scope));
  let now = 100;
  const intake = new BallotIntake({ store: fixture.store, verifier, clock: () => now, rateLimit: { capacity: 20, refillPerSecond: 1 } });
  await assert.rejects(intake.accept({ ...ballot, signalHash: fieldHex(1n) }, "client"), /signal_mismatch/u);
  await assert.rejects(intake.accept({ ...ballot, choiceIndex: 2 }, "client"), /choice_invalid/u);
  await assert.rejects(intake.accept({ ...ballot, choiceIndex: 1, signalHash: signalHash(1, fixture.mirror.scope) }, "client"), /proof_invalid/u);
  const bytes = proofBytes(ballot.proof);
  bytes[bytes.length - 1] = bytes[bytes.length - 1]! ^ 1;
  await assert.rejects(intake.accept({ ...ballot, proof: bytesHex(bytes) }, "client"), /proof_invalid/u);
  const otherIntake = new BallotIntake({ store: other.store, verifier, clock: () => now });
  await assert.rejects(otherIntake.accept({ ...ballot, electionId: other.mirror.electionId, signalHash: signalHash(0, other.mirror.scope) }, "other-client"), /proof_invalid/u);
  now = 99;
  await assert.rejects(intake.accept(ballot, "client"), /election_not_open/u);
  now = 200;
  await assert.rejects(intake.accept(ballot, "client"), /election_not_open/u);
  now = 100;
  await intake.accept(ballot, "client");
  await assert.rejects(intake.accept(ballot, "client"), /duplicate_nullifier/u);
  const second = await prover.prove({ secret: 8n, electionId: fixture.mirror.electionId, choiceIndex: 1, inclusion: inclusionPath(tree, identityCommitment(8n)), anchorRoot: fixture.anchor.root });
  await intake.accept(second, "second-client");
  const stored = fixture.store.listBallots(ballot.electionId);
  assert.equal(stored.length, 2);
  assert.ok(BigInt(stored[0]!.nullifier) < BigInt(stored[1]!.nullifier));
  const tally = buildTally({ election: fixture.mirror, chain: fixture.chain, ballots: stored, verifier: provenance });
  const rebuilt = buildTally({ election: fixture.mirror, chain: fixture.chain, ballots: [...stored].reverse(), verifier: provenance });
  assert.deepEqual(tally, rebuilt);
  assert.equal(tallyHash(tally), `0x${digest(rebuilt)}`);
  assert.deepEqual(tally.choices.map((choice) => choice.count), [1, 1]);
  assert.deepEqual(tally.window, { opensAt: 100, closesAt: 200 });
  assert.equal("createdAt" in tally, false);
  fixture.store.putTally(ballot.electionId, tally, tallyHash(tally));
  const closed = fixture.store.closeElection(ballot.electionId, { ...fixture.chain, closed: true, tallyHash: tallyHash(tally), acceptedBallots: 2n });
  assert.equal(closed.state, "closed");
  assert.throws(() => fixture.store.putElection(fixture.mirror.metadata, fixture.anchor), /anchor_immutable/u);
  assertStadtstackConformance(projectParticipationResult(tally, fixture.mirror.metadata, context), context.checksumBinding);
});

test("Stadtstack coordinator currently admits only synthetic results: exact aggregate projection and contextual checksum", async (t) => {
  const fixture = await electionFixture([identityCommitment(1n)]);
  t.after(() => fixture.db.close());
  const tally = buildTally({ election: fixture.mirror, chain: fixture.chain, ballots: [], verifier: provenance });
  assert.throws(() => fixture.store.putTally(fixture.mirror.electionId, tally, fieldHex(1n)), /tally_hash_mismatch/u);
  const result = projectParticipationResult(tally, fixture.mirror.metadata, context);
  assertStadtstackConformance(result, context.checksumBinding);
  assert.equal("ballots" in result, false);
  assert.equal("nullifiers" in result, false);
  assert.equal("anchorRoot" in result, false);
  assert.equal(result.resultArtifactRef, context.resultArtifactRef);
  for (const resultSummary of ["ballot: abc", "identity", `0x${"1".repeat(40)}`, "npub1abcdefghijk"]) assert.throws(() => projectParticipationResult(tally, fixture.mirror.metadata, { ...context, resultSummary }), /result_text_invalid/u);
  assert.throws(() => projectParticipationResult(tally, fixture.mirror.metadata, { ...context, methodKind: "a".repeat(257) }), /result_text_invalid/u);
  assert.throws(() => projectParticipationResult(tally, fixture.mirror.metadata, { ...context, limitations: ["a".repeat(2049)] }), /result_text_invalid/u);
  const actualContext = { ...context, reviewedAt: "2026-10-08T00:00:00.000Z", resultArtifactRef: "https://town.example/results/park" };
  const actual = projectParticipationResult(tally, fixture.mirror.metadata, actualContext);
  assert.equal(actual.reviewedAt, actualContext.reviewedAt);
  assert.equal(actual.resultArtifactRef, actualContext.resultArtifactRef);
  assert.throws(() => assertStadtstackConformance(actual, actualContext.checksumBinding));
});
