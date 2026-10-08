#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// ZK is bb's default: deliberately never pass --disable_zk.
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
export function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}
export function run(command, args, cwd = projectRoot) {
  return execFileSync(command, args, { cwd, encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 });
}

export function buildCircuit(outputDirectory = join(projectRoot, 'artifacts')) {
  const nargoVersion = run('nargo', ['--version']).trim();
  const bbVersion = run('bb', ['--version']).trim();
  if (!/^nargo version = 1\.0\.0-beta\.18(?:\r?\n|$)/.test(nargoVersion)) {
    throw new Error(`Expected nargo 1.0.0-beta.18, got ${nargoVersion}`);
  }
  if (bbVersion !== '3.0.0-nightly.20251104') {
    throw new Error(`Expected bb 3.0.0-nightly.20251104, got ${bbVersion}`);
  }
  const work = mkdtempSync(join(tmpdir(), 'membership-vote-build-'));
  try {
    cpSync(join(projectRoot, 'circuits/membership_vote'), join(work, 'membership_vote'), {
      recursive: true, filter: (path) => !path.includes('/target'),
    });
    run('nargo', ['compile', '--force'], join(work, 'membership_vote'));
    mkdirSync(outputDirectory, { recursive: true });
    const artifactPath = join(outputDirectory, 'membership_vote.json');
    const artifact = JSON.parse(readFileSync(join(work, 'membership_vote/target/membership_vote.json'), 'utf8'));
    // nargo embeds absolute source paths. Canonical repository-relative paths keep
    // debugging information while making artifacts independent of temp directory.
    for (const file of Object.values(artifact.file_map)) {
      const source = file.path.indexOf('/membership_vote/src/');
      if (source !== -1) file.path = `circuits${file.path.slice(source)}`;
    }
    writeFileSync(artifactPath, `${JSON.stringify(artifact)}\n`);
    const keyDirectory = join(work, 'key');
    mkdirSync(keyDirectory);
    run('bb', ['write_vk', '-s', 'ultra_honk', '--oracle_hash', 'keccak', '-b', artifactPath, '-o', keyDirectory]);
    const vk = readFileSync(join(keyDirectory, 'vk'));
    writeFileSync(join(outputDirectory, 'membership_vote.vk'), vk);
    const vkHash = readFileSync(join(keyDirectory, 'vk_hash')).toString('hex');
    const manifest = {
      schemaVersion: 'membership_vote_artifacts_v1',
      proofSystem: 'UltraHonk', oracleHash: 'keccak', zeroKnowledge: true,
      publicInputs: ['root', 'nullifier', 'scope', 'signal_hash'],
      artifacts: {
        'membership_vote.json': sha256(readFileSync(artifactPath)),
        'membership_vote.vk': sha256(vk),
      },
      vkHash: `0x${vkHash}`,
      tools: { nargo: nargoVersion, bb: bbVersion,
        noirJs: '1.0.0-beta.18', bbJs: '3.0.0-nightly.20251104' },
    };
    writeFileSync(join(outputDirectory, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`);
    return manifest;
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  buildCircuit();
}
