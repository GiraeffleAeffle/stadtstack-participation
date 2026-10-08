import { fail } from "../shared/errors.ts";
import { DOMAINS, fieldHex, h, parseField, type Hex } from "./hash.ts";

export const TREE_DEPTH = 16;
export const TREE_CAPACITY = 1 << TREE_DEPTH;
export type MerkleTree = Readonly<{ depth: 16; leaves: readonly Hex[]; levels: readonly (readonly bigint[])[]; zeroes: readonly bigint[]; root: Hex }>;
export type InclusionPath = Readonly<{ path: readonly bigint[]; indices: readonly (0 | 1)[] }>;

/** Store only occupied branches; each omitted branch has a precomputed zero root. */
export function buildMerkleTree(commitments: readonly Hex[]): MerkleTree {
  if (commitments.length > TREE_CAPACITY) fail("anchor_capacity_exceeded");
  const fields = commitments.map((value) => parseField(value, true)).sort((a, b) => a < b ? -1 : a > b ? 1 : 0);
  for (let i = 1; i < fields.length; i++) if (fields[i] === fields[i - 1]) fail("commitment_duplicate");
  const zeroes = [0n];
  const levels: bigint[][] = [fields];
  for (let depth = 0; depth < TREE_DEPTH; depth++) {
    zeroes.push(h(zeroes[depth]!, zeroes[depth]!, DOMAINS.merkle));
    const current = levels[depth]!;
    const next: bigint[] = [];
    for (let i = 0; i < current.length; i += 2) next.push(h(current[i]!, current[i + 1] ?? zeroes[depth]!, DOMAINS.merkle));
    levels.push(next);
  }
  return Object.freeze({ depth: TREE_DEPTH, leaves: Object.freeze(fields.map(fieldHex)), levels: Object.freeze(levels.map((level) => Object.freeze(level))), zeroes: Object.freeze(zeroes), root: fieldHex(levels[TREE_DEPTH]![0] ?? zeroes[TREE_DEPTH]!) });
}

export function inclusionPath(tree: MerkleTree, commitment: Hex): InclusionPath {
  let index = tree.leaves.indexOf(commitment);
  if (index < 0) fail("commitment_not_anchored");
  const path: bigint[] = [];
  const indices: (0 | 1)[] = [];
  for (let depth = 0; depth < TREE_DEPTH; depth++) {
    indices.push((index & 1) as 0 | 1);
    path.push(tree.levels[depth]![index ^ 1] ?? tree.zeroes[depth]!);
    index >>= 1;
  }
  return { path, indices };
}

export function rootFromPath(leaf: bigint, inclusion: InclusionPath): Hex {
  if (inclusion.path.length !== TREE_DEPTH || inclusion.indices.length !== TREE_DEPTH) fail("path_depth_invalid");
  let current = leaf;
  for (let depth = 0; depth < TREE_DEPTH; depth++) {
    const bit = inclusion.indices[depth];
    if (bit !== 0 && bit !== 1) fail("path_index_invalid");
    const sibling = inclusion.path[depth]!;
    current = bit === 0 ? h(current, sibling, DOMAINS.merkle) : h(sibling, current, DOMAINS.merkle);
  }
  return fieldHex(current);
}
