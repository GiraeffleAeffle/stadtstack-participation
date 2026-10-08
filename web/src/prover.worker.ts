import { VoteProver, type VoteCircuit } from "../../src/vote/prover.ts";
import type { Hex } from "../../src/vote/hash.ts";
import type { InclusionPath } from "../../src/vote/merkle.ts";
import circuitUrl from "../../artifacts/membership_vote.json?url";

self.onmessage = async (event: MessageEvent<{ secret: bigint; electionId: Hex; choiceIndex: number; inclusion: InclusionPath; anchorRoot: Hex }>) => {
  let prover: VoteProver | undefined;
  try {
    self.postMessage({ progress: "Der private Nachweis wird auf deinem Gerät vorbereitet …" });
    const response = await fetch(circuitUrl, { cache: "no-store", credentials: "omit" });
    if (!response.ok) throw new Error("circuit_unavailable");
    const circuit = await response.json() as VoteCircuit;
    prover = new VoteProver(circuit);
    self.postMessage({ progress: "Dein Gerät berechnet den privaten Nachweis. Das kann eine Weile dauern. Bitte lasse die Seite geöffnet …" });
    const ballot = await prover.prove(event.data);
    self.postMessage({ ballot });
  } catch (error) { self.postMessage({ error: error instanceof Error ? error.message : "proof_invalid" }); }
  finally { await prover?.destroy(); }
};
