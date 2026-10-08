import { Noir } from "@noir-lang/noir_js";
import { UltraHonkBackend } from "@aztec/bb.js";
import { fail } from "../shared/errors.ts";
import { electionNullifier, electionScope, signalHash } from "./election.ts";
import { assertField, bytesHex, fieldHex, identityCommitment, type Hex } from "./hash.ts";
import { rootFromPath, type InclusionPath } from "./merkle.ts";
import type { Ballot } from "./ballot.ts";

export type VoteCircuit = ConstructorParameters<typeof Noir>[0];

export class VoteProver {
  private readonly noir: Noir;
  private readonly backend: UltraHonkBackend;

  constructor(circuit: VoteCircuit) {
    this.noir = new Noir(circuit);
    this.backend = new UltraHonkBackend(circuit.bytecode, { threads: 1 });
  }

  async prove(input: Readonly<{ secret: bigint; electionId: Hex; choiceIndex: number; inclusion: InclusionPath; anchorRoot: Hex }>): Promise<Ballot> {
    assertField(input.secret, true);
    const scope = electionScope(input.electionId);
    const root = rootFromPath(BigInt(identityCommitment(input.secret)), input.inclusion);
    if (root !== input.anchorRoot) fail("anchor_root_mismatch");
    const nullifier = electionNullifier(input.secret, scope);
    const signal = signalHash(input.choiceIndex, scope);
    const { witness } = await this.noir.execute({ secret: fieldHex(input.secret), path: input.inclusion.path.map(fieldHex), indices: input.inclusion.indices.map((bit) => fieldHex(BigInt(bit))), root, nullifier, scope, signal_hash: signal });
    const result = await this.backend.generateProof(witness, { keccakZK: true });
    const expected = [root, nullifier, scope, signal];
    if (result.publicInputs.length !== 4 || result.publicInputs.some((value, index) => BigInt(value) !== BigInt(expected[index]!))) fail("proof_public_inputs_mismatch");
    return { schemaVersion: "advisory_ballot_v1", electionId: input.electionId, choiceIndex: input.choiceIndex, nullifier, signalHash: signal, proof: bytesHex(result.proof) };
  }

  async destroy(): Promise<void> {
    await this.backend.destroy();
  }
}
