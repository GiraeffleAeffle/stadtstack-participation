import { digest } from "../shared/canonical.ts";
import { fail } from "../shared/errors.ts";
import { isHex64 } from "../shared/ids.ts";
import { signalHash } from "./election.ts";
import { parseField, type Hex } from "./hash.ts";
import type { Ballot } from "./intake.ts";
import { assertElectionMatchesChain, type ChainElection, type ElectionMirror } from "./registry-client.ts";

export type Tally = Readonly<{
  schemaVersion: "advisory_tally_v1";
  municipalityId: string;
  policyVersion: string;
  electionId: Hex;
  anchorRoot: Hex;
  metadataHash: Hex;
  scope: Hex;
  window: Readonly<{ opensAt: number; closesAt: number }>;
  choices: readonly Readonly<{ index: number; label: string; count: number }>[];
  totalAccepted: number;
  ballots: readonly Readonly<{ nullifier: Hex; choiceIndex: number; signalHash: Hex; proof: Hex }>[];
  verifier: Readonly<{ circuitSha256: string; vkHash: Hex }>;
}>;

export function buildTally(input: Readonly<{ election: ElectionMirror; chain: ChainElection; ballots: readonly Ballot[]; verifier: Tally["verifier"] }>): Tally {
  assertElectionMatchesChain(input.election, input.chain);
  if (!isHex64(input.verifier.circuitSha256) || !/^0x[0-9a-f]{64}$/u.test(input.verifier.vkHash)) fail("verifier_provenance_invalid");
  const ballots = [...input.ballots].sort((a, b) => BigInt(a.nullifier) < BigInt(b.nullifier) ? -1 : BigInt(a.nullifier) > BigInt(b.nullifier) ? 1 : 0);
  const counts: Record<number, number> = {};
  for (const choice of input.election.metadata.choices) counts[choice.index] = 0;
  for (let i = 0; i < ballots.length; i++) {
    const ballot = ballots[i]!;
    parseField(ballot.nullifier, true);
    if (ballot.electionId !== input.election.electionId || !Object.hasOwn(counts, ballot.choiceIndex) || ballot.signalHash !== signalHash(ballot.choiceIndex, input.election.scope) || !/^0x(?:[0-9a-f]{2})+$/u.test(ballot.proof)) fail("tally_ballot_invalid");
    if (i > 0 && ballot.nullifier === ballots[i - 1]!.nullifier) fail("duplicate_nullifier");
    counts[ballot.choiceIndex]!++;
  }
  return { schemaVersion: "advisory_tally_v1", municipalityId: input.election.metadata.municipalityId, policyVersion: input.election.metadata.policyVersion, electionId: input.election.electionId, anchorRoot: input.chain.anchorRoot, metadataHash: input.chain.metadataHash, scope: input.election.scope, window: { opensAt: Number(input.chain.opensAt), closesAt: Number(input.chain.closesAt) }, choices: [...input.election.metadata.choices].sort((a, b) => a.index - b.index).map((choice) => ({ ...choice, count: counts[choice.index]! })), totalAccepted: ballots.length, ballots: ballots.map(({ nullifier, choiceIndex, signalHash: signal, proof }) => ({ nullifier, choiceIndex, signalHash: signal, proof })), verifier: { ...input.verifier } };
}

export function tallyHash(tally: Tally): Hex {
  return `0x${digest(tally)}`;
}
