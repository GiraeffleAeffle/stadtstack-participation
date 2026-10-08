import assert from "node:assert/strict";
import test from "node:test";
import { assertElectionMatchesChain, buildAnchor, buildMerkleTree, fieldHex, getElection, identityCommitment, metadataHash, type ChainElection } from "../../src/vote/index.ts";
import { electionFixture, metadata } from "./helpers.ts";

test("anchor source is rechecked at the requested instant and sorted independently of enrollment", async () => {
  const commitments = [identityCommitment(3n), identityCommitment(8n), identityCommitment(2n)];
  const electionMetadata = metadata();
  const signal = new AbortController().signal;
  const anchor = await buildAnchor({ async listEligibleCommitments(input) {
    assert.deepEqual(input, { municipalityId: "test-town", policyVersion: "policy-v1", at: 90, signal });
    return commitments;
  } }, { metadata: electionMetadata, anchoredAt: 90, signal });
  assert.deepEqual(anchor.leaves, buildMerkleTree(commitments).leaves);
  await assert.rejects(buildAnchor({ async listEligibleCommitments() { return [commitments[0]!, commitments[0]!]; } }, { metadata: electionMetadata, anchoredAt: 90, signal }), /commitment_duplicate/u);
});

test("opened anchors cannot change and lock enrolled commitments before the voting window", async (t) => {
  const commitment = identityCommitment(1n);
  const fixture = await electionFixture([commitment]);
  t.after(() => fixture.db.close());
  assert.equal(fixture.store.isCommitmentInOpenAnchor({ municipalityId: "test-town", commitment, at: 99 }), true);
  assert.equal(fixture.store.isCommitmentInOpenAnchor({ municipalityId: "test-town", commitment, at: 200 }), false);
  assert.throws(() => fixture.store.putElection(metadata(), fixture.anchor), /anchor_immutable/u);
  assert.throws(() => fixture.db.prepare("UPDATE vote_anchors SET anchor_json='{}' WHERE election_id=?").run(fixture.mirror.electionId), /anchor_immutable/u);
  assert.throws(() => fixture.db.prepare("DELETE FROM vote_anchor_leaves WHERE election_id=?").run(fixture.mirror.electionId), /anchor_immutable/u);
  assert.throws(() => fixture.db.prepare("UPDATE vote_elections SET opened=0 WHERE election_id=?").run(fixture.mirror.electionId), /election_immutable/u);
});

test("client rejects every chain/server root, metadata, scope, window and depth mismatch", async (t) => {
  const fixture = await electionFixture([identityCommitment(1n)]);
  t.after(() => fixture.db.close());
  const { mirror, chain, anchor } = fixture;
  assert.doesNotThrow(() => assertElectionMatchesChain(mirror, chain, anchor));
  const mutations: Partial<ChainElection>[] = [{ anchorRoot: fieldHex(1n) }, { metadataHash: fieldHex(1n) }, { scope: 1n }, { opensAt: 101n }, { closesAt: 201n }, { treeDepth: 10 }, { municipalityId: "other-town" }, { closed: true }];
  for (const mutation of mutations) assert.throws(() => assertElectionMatchesChain(mirror, { ...chain, ...mutation }, anchor), /chain_.*_mismatch/u);
  assert.throws(() => assertElectionMatchesChain({ ...mirror, scope: fieldHex(1n) }, { ...chain, scope: 1n }), /chain_scope_mismatch/u);
  assert.throws(() => assertElectionMatchesChain({ ...mirror, metadata: { ...mirror.metadata, title: "Changed" } }, chain), /chain_metadata_mismatch/u);
  assert.throws(() => assertElectionMatchesChain({ ...mirror, opensAt: 101 }, { ...chain, opensAt: 101n }), /chain_window_mismatch/u);
  assert.throws(() => assertElectionMatchesChain(mirror, chain, { ...anchor, root: fieldHex(1n) }), /chain_anchor_mismatch/u);
  assert.equal(metadataHash(mirror.metadata), mirror.metadataHash);
});

test("registry client reads the authoritative tuple through a viem public client", async () => {
  const expected = { municipalityId: "test-town", anchorRoot: fieldHex(1n), treeDepth: 16, metadataHash: fieldHex(2n), scope: 3n, opensAt: 100n, closesAt: 200n, closed: false, tallyHash: fieldHex(0n), acceptedBallots: 0n };
  const client = { async readContract(input: unknown) {
    assert.equal(typeof input, "object");
    return expected;
  } } as Parameters<typeof getElection>[0];
  assert.deepEqual(await getElection(client, "0x1111111111111111111111111111111111111111", metadata().electionId), expected);
});
