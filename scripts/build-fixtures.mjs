#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// Node/Solidity compatibility contract for bb.js 3.0.0-nightly.20251104:
// new UltraHonkBackend(circuit.bytecode, {threads: 1});
// generateProof(witness, {keccakZK: true}); verifyProof(data, {keccakZK: true}).
// `keccak: true` is NOT interchangeable: it disables zero knowledge.
// Proof is the returned Uint8Array, flattened 32-byte field words, with no
// length prefix or public-input prefix. Public inputs are separate bytes32
// big-endian fields in [root, nullifier, scope, signal_hash] order. bb packs
// its 16 pairing-accumulator fields inside the proof, not this public vector.
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { Noir } from '@noir-lang/noir_js';
import { UltraHonkBackend } from '@aztec/bb.js';
import { permute } from '@zkpassport/poseidon2';
import { projectRoot, run } from './build-circuit.mjs';

const field = (value) => `0x${BigInt(value).toString(16).padStart(64, '0')}`;
const h = (a, b, d) => permute([a, b, d, 0n])[0];
const output = run('nargo', ['test', '--program-dir', 'circuits/membership_vote', '--show-output']);
const cases = [...output.matchAll(/PARITY (0x[\da-f]+|\d+) (0x[\da-f]+|\d+) (0x[\da-f]+|\d+) (0x[\da-f]+|\d+)/g)]
  .map((match) => ({ a: field(match[1]), b: field(match[2]), domain: Number(BigInt(match[3])), output: field(match[4]) }));
if (cases.length !== 50) throw new Error(`Expected 50 Noir parity vectors, got ${cases.length}`);
for (const vector of cases) {
  if (field(h(BigInt(vector.a), BigInt(vector.b), BigInt(vector.domain))) !== vector.output) {
    throw new Error('Noir / TypeScript Poseidon2 parity failed');
  }
}
const electionIdentity = { electionSlug: 'fixture', municipalityId: 'example', policyVersion: 'policy-v1', schemaVersion: 'advisory_election_id_v1' };
const electionId = `0x${createHash('sha256').update(JSON.stringify(electionIdentity)).digest('hex')}`;
const scope = h(BigInt(electionId.slice(0, 34)), BigInt(`0x${electionId.slice(34)}`), 4n);
const secret = 42n;
const leaf = h(secret, 0n, 1n);
const path = [];
let empty = 0n;
let root = leaf;
for (let i = 0; i < 16; i++) {
  path.push(field(empty));
  root = h(root, empty, 2n);
  empty = h(empty, empty, 2n);
}
const nullifier = h(secret, scope, 3n);
const signalHash = h(1n, scope, 5n);
const example = { electionId, electionIdentity, secret: field(secret), leaf: field(leaf),
  leafIndex: 0, path, indices: Array(16).fill(field(0n)), root: field(root),
  scope: field(scope), nullifier: field(nullifier), choiceIndex: 1, signalHash: field(signalHash) };
const emitted = output.match(/EXAMPLE (0x[\da-f]+|\d+) (0x[\da-f]+|\d+) (0x[\da-f]+|\d+) (0x[\da-f]+|\d+) (0x[\da-f]+|\d+)/);
if (!emitted || JSON.stringify(emitted.slice(1).map(field)) !== JSON.stringify([
  example.leaf, example.root, example.scope, example.nullifier, example.signalHash,
])) throw new Error('Noir full-depth example differs');
const fixtureDirectory = join(projectRoot, 'test/fixtures/circuit');
mkdirSync(fixtureDirectory, { recursive: true });
writeFileSync(join(fixtureDirectory, 'poseidon2-parity.json'), `${JSON.stringify({
  algorithm: 'poseidon2_permutation_bn254', tool: 'nargo 1.0.0-beta.18', cases, example,
}, null, 2)}\n`);
const circuit = JSON.parse(readFileSync(join(projectRoot, 'artifacts/membership_vote.json'), 'utf8'));
const manifest = JSON.parse(readFileSync(join(projectRoot, 'artifacts/manifest.json'), 'utf8'));
const noir = new Noir(circuit);
const { witness } = await noir.execute({ secret: example.secret, path, indices: example.indices,
  root: example.root, nullifier: example.nullifier, scope: example.scope, signal_hash: example.signalHash });
const backend = new UltraHonkBackend(circuit.bytecode, { threads: 1 });
try {
  const data = await backend.generateProof(witness, { keccakZK: true });
  const expectedInputs = [example.root, example.nullifier, example.scope, example.signalHash];
  if (JSON.stringify(data.publicInputs) !== JSON.stringify(expectedInputs)) {
    throw new Error(`Unexpected public input encoding: ${JSON.stringify(data.publicInputs)}`);
  }
  if (!await backend.verifyProof(data, { keccakZK: true })) throw new Error('bb.js proof verification failed');
  if (data.proof.length !== manifest.proofFields * 32) throw new Error('bb.js / Solidity proof length differs');
  const fixture = { schemaVersion: 'membership_vote_proof_fixture_v1', producer: '@aztec/bb.js',
    bbJsVersion: '3.0.0-nightly.20251104', options: { keccakZK: true },
    electionId, root: example.root, nullifier: example.nullifier, scope: example.scope,
    signalHash: example.signalHash, choiceIndex: 1, publicInputs: data.publicInputs,
    proof: `0x${Buffer.from(data.proof).toString('hex')}`,
    circuitSha256: manifest.artifacts['membership_vote.json'], vkHash: manifest.vkHash };
  const encoded = `${JSON.stringify(fixture, null, 2)}\n`;
  for (const path of [join(fixtureDirectory, 'ballot-proof.json'), join(projectRoot, 'contracts/test/fixtures/ballot-proof.json')]) {
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, encoded);
  }
} finally {
  await backend.destroy();
}
