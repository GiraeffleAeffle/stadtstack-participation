import { UltraHonkBackend } from "@aztec/bb.js";
import type { VoteCircuit } from "./prover.ts";

export interface BallotVerifier {
  verify(proof: Uint8Array, publicInputs: readonly string[]): Promise<boolean>;
}

export class VoteVerifier implements BallotVerifier {
  private readonly backend: UltraHonkBackend;

  constructor(circuit: Pick<VoteCircuit, "bytecode">) {
    this.backend = new UltraHonkBackend(circuit.bytecode, { threads: 1 });
  }

  async verify(proof: Uint8Array, publicInputs: readonly string[]): Promise<boolean> {
    if (publicInputs.length !== 4) return false;
    try {
      return await this.backend.verifyProof({ proof, publicInputs: [...publicInputs] }, { keccakZK: true });
    } catch {
      return false;
    }
  }

  async destroy(): Promise<void> {
    await this.backend.destroy();
  }
}
