#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// Rebuild everything in isolation; never mutate committed artifacts during a check.
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildCircuit, projectRoot, sha256 } from './build-circuit.mjs';
import { generateVerifier } from './generate-verifier.mjs';

const work = mkdtempSync(join(tmpdir(), 'membership-vote-check-'));
try {
  const manifest = JSON.parse(readFileSync(join(projectRoot, 'artifacts/manifest.json'), 'utf8'));
  buildCircuit(join(work, 'artifacts'));
  const verifierPath = join(work, 'MembershipVoteVerifier.sol');
  const rebuilt = generateVerifier(join(work, 'artifacts'), verifierPath);
  for (const [file, expected] of Object.entries(manifest.artifacts)) {
    const current = sha256(readFileSync(join(projectRoot, 'artifacts', file)));
    const generated = sha256(readFileSync(join(work, 'artifacts', file)));
    if (current !== expected || generated !== expected) throw new Error(`Artifact drift: ${file}`);
  }
  const verifier = sha256(readFileSync(join(projectRoot, 'contracts/src/MembershipVoteVerifier.sol')));
  if (sha256(readFileSync(verifierPath)) !== manifest.verifierSha256 || verifier !== manifest.verifierSha256) {
    throw new Error('Artifact drift: MembershipVoteVerifier.sol');
  }
  if (JSON.stringify(rebuilt) !== JSON.stringify(manifest)) throw new Error('Artifact drift: manifest metadata');
  console.log('Circuit, verification key, verifier and manifest match their rebuilt SHA-256 values.');
} finally {
  rmSync(work, { recursive: true, force: true });
}
