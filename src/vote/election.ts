import { digest, exact, isSafeNonNegativeInteger, snapshot } from "../shared/canonical.ts";
import { fail } from "../shared/errors.ts";
import { isBytes32, isMunicipalityId, isPolicyVersion } from "../shared/ids.ts";
import { assertField, DOMAINS, fieldHex, h, type Hex } from "./hash.ts";

export type ElectionMetadata = Readonly<{
  schemaVersion: "advisory_election_metadata_v1";
  municipalityId: string;
  policyVersion: string;
  electionId: Hex;
  electionSlug: string;
  title: string;
  question: string;
  choices: readonly Readonly<{ index: number; label: string }>[];
  opensAt: number;
  closesAt: number;
  legalEffect: "advisory_non_binding";
  participationContract: Readonly<{ id: string; version: number }>;
}>;

export function electionId(input: Readonly<{ municipalityId: string; policyVersion: string; electionSlug: string }>): Hex {
  if (!isMunicipalityId(input.municipalityId) || !isPolicyVersion(input.policyVersion) || !isMunicipalityId(input.electionSlug)) fail("election_identity_invalid");
  return `0x${digest({ schemaVersion: "advisory_election_id_v1", municipalityId: input.municipalityId, policyVersion: input.policyVersion, electionSlug: input.electionSlug })}`;
}

export function electionScope(id: Hex): Hex {
  if (!isBytes32(id)) fail("election_id_invalid");
  const value = BigInt(id);
  const scope = h(value >> 128n, value & ((1n << 128n) - 1n), DOMAINS.scope);
  assertField(scope, true);
  return fieldHex(scope);
}

export function signalHash(choiceIndex: number, scope: Hex): Hex {
  if (!Number.isInteger(choiceIndex) || choiceIndex < 0 || choiceIndex > 255) fail("choice_invalid");
  assertField(BigInt(scope), true);
  return fieldHex(h(BigInt(choiceIndex), BigInt(scope), DOMAINS.signal));
}

export function electionNullifier(secret: bigint, scope: Hex): Hex {
  assertField(secret, true);
  assertField(BigInt(scope), true);
  return fieldHex(h(secret, BigInt(scope), DOMAINS.nullifier));
}

export function validateMetadata(input: unknown): ElectionMetadata {
  const value = exact(snapshot(input), ["schemaVersion", "municipalityId", "policyVersion", "electionId", "electionSlug", "title", "question", "choices", "opensAt", "closesAt", "legalEffect", "participationContract"], "metadata_invalid");
  if (value.schemaVersion !== "advisory_election_metadata_v1" || value.legalEffect !== "advisory_non_binding" || !isMunicipalityId(value.municipalityId) || !isPolicyVersion(value.policyVersion) || !isMunicipalityId(value.electionSlug) || !isBytes32(value.electionId)) fail("metadata_invalid");
  if (value.electionId !== electionId({ municipalityId: value.municipalityId, policyVersion: value.policyVersion, electionSlug: value.electionSlug })) fail("election_id_mismatch");
  for (const text of [value.title, value.question]) if (typeof text !== "string" || !text.trim() || text.length > 2048) fail("metadata_invalid");
  if (!isSafeNonNegativeInteger(value.opensAt) || !isSafeNonNegativeInteger(value.closesAt) || value.opensAt >= value.closesAt) fail("election_window_invalid");
  if (!Array.isArray(value.choices) || value.choices.length < 2 || value.choices.length > 64) fail("choices_invalid");
  const used: Record<number, true> = {};
  for (const item of value.choices) {
    const choice = exact(item, ["index", "label"], "choices_invalid");
    if (!isSafeNonNegativeInteger(choice.index) || choice.index > 255 || used[choice.index] || typeof choice.label !== "string" || !choice.label.trim() || choice.label.length > 1000) fail("choices_invalid");
    used[choice.index] = true;
  }
  const contract = exact(value.participationContract, ["id", "version"], "metadata_invalid");
  if (typeof contract.id !== "string" || !contract.id.trim() || contract.id.length > 512 || !isSafeNonNegativeInteger(contract.version) || contract.version < 1) fail("metadata_invalid");
  return value as ElectionMetadata;
}

export function metadataHash(metadata: ElectionMetadata): Hex {
  return `0x${digest(validateMetadata(metadata))}`;
}
