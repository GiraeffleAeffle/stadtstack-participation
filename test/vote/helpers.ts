import { DatabaseSync } from "node:sqlite";
import { buildAnchor, electionId, VoteStore, type ChainElection, type ElectionMetadata, type ElectionMirror, type Hex } from "../../src/vote/index.ts";

export function metadata(slug = "park"): ElectionMetadata {
  const identity = { municipalityId: "test-town", policyVersion: "policy-v1", electionSlug: slug };
  return { schemaVersion: "advisory_election_metadata_v1", ...identity, electionId: electionId(identity), title: "Park consultation", question: "Which improvement should be prioritised?", choices: [{ index: 0, label: "Trees" }, { index: 1, label: "Paths" }], opensAt: 100, closesAt: 200, legalEffect: "advisory_non_binding", participationContract: { id: "park-consultation", version: 1 } };
}

export function chainFor(mirror: ElectionMirror): ChainElection {
  return { municipalityId: mirror.metadata.municipalityId, anchorRoot: mirror.anchorRoot, treeDepth: 16, metadataHash: mirror.metadataHash, scope: BigInt(mirror.scope), opensAt: BigInt(mirror.opensAt), closesAt: BigInt(mirror.closesAt), closed: mirror.state === "closed", tallyHash: `0x${"0".repeat(64)}`, acceptedBallots: 0n };
}

export async function electionFixture(commitments: readonly Hex[], electionMetadata = metadata()) {
  const db = new DatabaseSync(":memory:");
  const store = new VoteStore(db);
  const anchor = await buildAnchor({ async listEligibleCommitments() { return commitments; } }, { metadata: electionMetadata, anchoredAt: 90, signal: new AbortController().signal });
  const draft = store.putElection(electionMetadata, anchor);
  const chain = chainFor({ ...draft, state: "open" });
  const mirror = store.openElection(electionMetadata.electionId, chain);
  return { db, store, anchor, mirror, chain };
}
