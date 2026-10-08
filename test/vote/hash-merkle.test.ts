import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { buildMerkleTree, electionScope, fieldHex, h, identityCommitment, inclusionPath, rootFromPath, signalHash, TREE_CAPACITY, TREE_DEPTH, type Hex } from "../../src/vote/index.ts";

const parity = JSON.parse(await readFile(new URL("../fixtures/circuit/poseidon2-parity.json", import.meta.url), "utf8")) as { cases: { a: Hex; b: Hex; domain: number; output: Hex }[]; example: { electionId: Hex; scope: Hex; choiceIndex: number; signalHash: Hex } };

test("domain-tagged TypeScript hashes equal every Noir parity vector", () => {
  for (const vector of parity.cases) assert.equal(fieldHex(h(BigInt(vector.a), BigInt(vector.b), BigInt(vector.domain))), vector.output);
  assert.equal(electionScope(parity.example.electionId), parity.example.scope);
  assert.equal(signalHash(parity.example.choiceIndex, parity.example.scope), parity.example.signalHash);
  assert.notEqual(h(1n, 2n, 1n), h(1n, 2n, 2n));
});

test("depth sixteen tree sorts occupied leaves numerically and provides LSB-first paths", () => {
  const commitments = [identityCommitment(42n), identityCommitment(1n), identityCommitment(300n)];
  const tree = buildMerkleTree(commitments);
  assert.equal(TREE_DEPTH, 16);
  assert.equal(TREE_CAPACITY, 65536);
  assert.deepEqual(tree.leaves, [...commitments].sort((a, b) => BigInt(a) < BigInt(b) ? -1 : 1));
  assert.equal(tree.root, buildMerkleTree([...commitments].reverse()).root);
  for (let index = 0; index < tree.leaves.length; index++) {
    const leaf: Hex = tree.leaves[index]!;
    const inclusion = inclusionPath(tree, leaf);
    assert.equal(inclusion.path.length, 16);
    assert.equal(inclusion.indices.length, 16);
    assert.deepEqual(inclusion.indices, Array.from({ length: 16 }, (_, bit) => ((index >> bit) & 1)));
    assert.equal(rootFromPath(BigInt(leaf), inclusion), tree.root);
    assert.throws(() => rootFromPath(BigInt(leaf), { path: inclusion.path.slice(0, 10), indices: inclusion.indices.slice(0, 10) }), /path_depth_invalid/u);
  }
  assert.throws(() => buildMerkleTree([commitments[0]!, commitments[0]!]), /commitment_duplicate/u);
  assert.throws(() => buildMerkleTree([fieldHex(0n)]), /field_invalid/u);
  assert.throws(() => inclusionPath(tree, identityCommitment(99n)), /commitment_not_anchored/u);
  assert.throws(() => buildMerkleTree(Array<Hex>(65537).fill(commitments[0]!)), /anchor_capacity_exceeded/u);
});
