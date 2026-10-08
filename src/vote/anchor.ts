import { isSafeNonNegativeInteger } from "../shared/canonical.ts";
import { fail } from "../shared/errors.ts";
import type { EligibleCommitmentSource } from "../shared/seams.ts";
import { validateMetadata, type ElectionMetadata } from "./election.ts";
import { type Hex } from "./hash.ts";
import { buildMerkleTree } from "./merkle.ts";

export type ElectionAnchor = Readonly<{
  schemaVersion: "advisory_election_anchor_v1";
  municipalityId: string;
  policyVersion: string;
  electionId: Hex;
  treeDepth: 16;
  leaves: readonly Hex[];
  root: Hex;
  anchoredAt: number;
}>;

export async function buildAnchor(source: EligibleCommitmentSource, input: Readonly<{ metadata: ElectionMetadata; anchoredAt: number; signal: AbortSignal }>): Promise<ElectionAnchor> {
  const metadata = validateMetadata(input.metadata);
  if (!isSafeNonNegativeInteger(input.anchoredAt)) fail("anchor_time_invalid");
  const commitments = await source.listEligibleCommitments({ municipalityId: metadata.municipalityId, policyVersion: metadata.policyVersion, at: input.anchoredAt, signal: input.signal });
  const tree = buildMerkleTree(commitments);
  return Object.freeze({ schemaVersion: "advisory_election_anchor_v1", municipalityId: metadata.municipalityId, policyVersion: metadata.policyVersion, electionId: metadata.electionId, treeDepth: 16, leaves: tree.leaves, root: tree.root, anchoredAt: input.anchoredAt });
}
