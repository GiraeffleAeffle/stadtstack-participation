import type { Address, PublicClient } from "viem";
import { fail } from "../shared/errors.ts";
import { electionScope, metadataHash, validateMetadata, type ElectionMetadata } from "./election.ts";
import type { ElectionAnchor } from "./anchor.ts";
import { parseField, type Hex } from "./hash.ts";
import { buildMerkleTree } from "./merkle.ts";

export const ELECTION_REGISTRY_ABI = [{ type: "function", name: "getElection", stateMutability: "view", inputs: [{ name: "electionId", type: "bytes32" }], outputs: [{ name: "", type: "tuple", components: [
  { name: "municipalityId", type: "string" }, { name: "anchorRoot", type: "bytes32" }, { name: "treeDepth", type: "uint8" }, { name: "metadataHash", type: "bytes32" }, { name: "scope", type: "uint256" }, { name: "opensAt", type: "uint64" }, { name: "closesAt", type: "uint64" }, { name: "closed", type: "bool" }, { name: "tallyHash", type: "bytes32" }, { name: "acceptedBallots", type: "uint256" },
] }] }] as const;

export type ChainElection = Readonly<{ municipalityId: string; anchorRoot: Hex; treeDepth: number; metadataHash: Hex; scope: bigint; opensAt: bigint; closesAt: bigint; closed: boolean; tallyHash: Hex; acceptedBallots: bigint }>;
export type ElectionMirror = Readonly<{ electionId: Hex; metadata: ElectionMetadata; anchorRoot: Hex; metadataHash: Hex; scope: Hex; opensAt: number; closesAt: number; state: "draft" | "open" | "closed" }>;

export async function getElection(client: Pick<PublicClient, "readContract">, address: Address, id: Hex): Promise<ChainElection> {
  return client.readContract({ address, abi: ELECTION_REGISTRY_ABI, functionName: "getElection", args: [id] });
}

/** A mirror is not an authority: every proof-relevant value must match the chain. */
export function assertElectionMatchesChain(mirror: ElectionMirror, chain: ChainElection, anchor?: ElectionAnchor): void {
  const metadata = validateMetadata(mirror.metadata);
  const scope = electionScope(mirror.electionId);
  parseField(mirror.anchorRoot, true);
  if (metadata.electionId !== mirror.electionId || chain.municipalityId !== metadata.municipalityId) fail("chain_municipality_mismatch");
  if (chain.treeDepth !== 16) fail("chain_depth_mismatch");
  if (chain.anchorRoot !== mirror.anchorRoot) fail("chain_root_mismatch");
  if (mirror.metadataHash !== metadataHash(metadata) || chain.metadataHash !== mirror.metadataHash) fail("chain_metadata_mismatch");
  if (mirror.scope !== scope || chain.scope !== BigInt(scope)) fail("chain_scope_mismatch");
  if (mirror.opensAt !== metadata.opensAt || mirror.closesAt !== metadata.closesAt || chain.opensAt !== BigInt(mirror.opensAt) || chain.closesAt !== BigInt(mirror.closesAt)) fail("chain_window_mismatch");
  if (mirror.state !== (chain.closed ? "closed" : "open")) fail("chain_state_mismatch");
  if (anchor && (anchor.schemaVersion !== "advisory_election_anchor_v1" || anchor.electionId !== mirror.electionId || anchor.municipalityId !== metadata.municipalityId || anchor.policyVersion !== metadata.policyVersion || anchor.treeDepth !== 16 || anchor.root !== chain.anchorRoot || buildMerkleTree(anchor.leaves).root !== anchor.root || anchor.leaves.some((leaf, index) => index > 0 && BigInt(leaf) <= BigInt(anchor.leaves[index - 1]!)))) fail("chain_anchor_mismatch");
}
