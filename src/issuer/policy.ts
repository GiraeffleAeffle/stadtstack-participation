import { exact, isSafeNonNegativeInteger, object, snapshot } from "../shared/canonical.ts";
import { fail } from "../shared/errors.ts";
import { isAgs, isHex64, isHttpsOrigin, isMunicipalityId, isPolicyVersion, KEY_ID, SLUG } from "../shared/ids.ts";
import { validateInPersonAttestorsConfig, type InPersonAttestorsConfig } from "../adapters/in-person-attestors.ts";
import { validateRoebelCitizenNftConfig, type RoebelCitizenNftConfig } from "../adapters/roebel-citizen-nft.ts";
import { validateEudiPidConfig, type EudiPidConfig } from "../adapters/eudi-pid.ts";
import type { EligibilityBasis } from "../shared/seams.ts";

export type IssuerPolicy = Readonly<{
  schemaVersion: "municipal_eligibility_issuer_policy_v1"; municipalityId: string; ags: string; policyVersion: string;
  registry: Readonly<{ snapshotId: string; digest: string }> | null;
  issuer: string; issuerKeyId: string; issuerPublicKey: string; publicBaseUrl: string; statusBaseUrl: string; acceptanceBaseUrl: string;
  receiptTtlSeconds: number; statusMaxAgeSeconds: number; maxEventClockSkewSeconds: number; allowedAgentPubkeys: readonly string[];
  basis: EligibilityBasis; adapter: InPersonAttestorsConfig | RoebelCitizenNftConfig | EudiPidConfig;
}>;

export function parseIssuerPolicy(input: unknown): IssuerPolicy {
  const p = exact(snapshot(input), ["schemaVersion", "municipalityId", "ags", "policyVersion", "registry", "issuer", "issuerKeyId", "issuerPublicKey", "publicBaseUrl", "statusBaseUrl", "acceptanceBaseUrl", "receiptTtlSeconds", "statusMaxAgeSeconds", "maxEventClockSkewSeconds", "allowedAgentPubkeys", "basis", "adapter"], "policy_invalid");
  if (p.schemaVersion !== "municipal_eligibility_issuer_policy_v1" || !isMunicipalityId(p.municipalityId) || !isAgs(p.ags) || !isPolicyVersion(p.policyVersion) ||
    typeof p.issuer !== "string" || !p.issuer || p.issuer.trim() !== p.issuer || p.issuer.length > 2048 ||
    typeof p.issuerKeyId !== "string" || !KEY_ID.test(p.issuerKeyId) || !isHex64(p.issuerPublicKey) || !isHttpsOrigin(p.publicBaseUrl) ||
    p.statusBaseUrl !== `${p.publicBaseUrl}/v1/eligibility/status` || p.acceptanceBaseUrl !== `${p.publicBaseUrl}/v1/adoptions` ||
    !isSafeNonNegativeInteger(p.receiptTtlSeconds) || p.receiptTtlSeconds < 60 || p.receiptTtlSeconds > 3600 ||
    !isSafeNonNegativeInteger(p.statusMaxAgeSeconds) || p.statusMaxAgeSeconds < 1 || p.statusMaxAgeSeconds > 300 ||
    !isSafeNonNegativeInteger(p.maxEventClockSkewSeconds) || p.maxEventClockSkewSeconds > 300 ||
    !Array.isArray(p.allowedAgentPubkeys) || !p.allowedAgentPubkeys.length || p.allowedAgentPubkeys.some((key) => !isHex64(key)) ||
    new Set(p.allowedAgentPubkeys).size !== p.allowedAgentPubkeys.length) fail("policy_invalid");
  if (p.registry !== null) {
    const registry = exact(p.registry, ["snapshotId", "digest"], "policy_invalid");
    if (typeof registry.snapshotId !== "string" || !registry.snapshotId || registry.snapshotId.length > 2048 ||
      typeof registry.digest !== "string" || !/^sha256:[0-9a-f]{64}$/u.test(registry.digest)) fail("policy_invalid");
  }
  const basis = exact(p.basis, ["residence", "minimumAgeYears", "nationality", "localityScope"], "policy_invalid");
  if (!["main_residence", "main_or_secondary_residence"].includes(basis.residence as string) ||
    (basis.minimumAgeYears !== null && (!isSafeNonNegativeInteger(basis.minimumAgeYears) || basis.minimumAgeYears > 150)) ||
    !["any", "eu_citizen", "german_citizen"].includes(basis.nationality as string) ||
    (basis.localityScope !== null && (!Array.isArray(basis.localityScope) || !basis.localityScope.length ||
      basis.localityScope.some((id) => typeof id !== "string" || !SLUG.test(id)) || new Set(basis.localityScope).size !== basis.localityScope.length))) fail("policy_invalid");
  const adapterKind = object(p.adapter, "policy_invalid").kind;
  if (adapterKind === "in_person_attestors_v1") {
    const adapter = validateInPersonAttestorsConfig(p.adapter);
    if (adapter.attestors.some((a) => a.publicKey === p.issuerPublicKey)) fail("issuer_attestor_key_collision");
  } else if (adapterKind === "roebel_citizen_nft_v1") validateRoebelCitizenNftConfig(p.adapter);
  else if (adapterKind === "eudi_pid_v1") validateEudiPidConfig(p.adapter, basis as EligibilityBasis);
  else fail("adapter_unknown");
  return p as IssuerPolicy;
}

/** Exact deployment policy consumed by Stadtstack's evidence verifier. */
export function toStadtstackPolicy(policy: IssuerPolicy) {
  const { municipalityId, policyVersion, issuer, issuerKeyId, issuerPublicKey, allowedAgentPubkeys, receiptTtlSeconds, statusBaseUrl, statusMaxAgeSeconds, maxEventClockSkewSeconds } = policy;
  return { municipalityId, policyVersion, issuer, issuerKeyId, issuerPublicKey, allowedAgentPubkeys, receiptTtlSeconds, statusBaseUrl, statusMaxAgeSeconds, maxEventClockSkewSeconds };
}
