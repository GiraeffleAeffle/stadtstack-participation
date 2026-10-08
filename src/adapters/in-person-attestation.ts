import { signCanonical } from "../shared/ed25519.ts";
import { fail } from "../shared/errors.ts";
import { isHex64, isMunicipalityId } from "../shared/ids.ts";
import type { EligibilityBasis } from "../shared/seams.ts";

export const ATTESTATION_SCHEMA = "in_person_residency_attestation_v1";
export const REVOCATION_SCHEMA = "in_person_residency_revocation_v1";
export const ATTESTATION_DOMAIN = "in-person-residency-attestation/v1";
export const REVOCATION_DOMAIN = "in-person-residency-revocation/v1";
// Offered by the UI, not a restriction on the open document-kind wire format.
export const DOCUMENT_KINDS: Readonly<Record<string, string>> = {
  identity_card: "Personalausweis", passport: "Reisepass", residence_permit: "Aufenthaltstitel", residence_register: "Meldebescheinigung",
};
export const DOCUMENT_KIND_PATTERN = /^[a-z][a-z0-9_]{1,63}$/u;
export type AttestationInput = Readonly<{ municipalityId: string; policyVersion: string; subjectPubkey: string; attestorId: string; attestedAt: number; basis: EligibilityBasis; documentKinds: readonly string[] }>;
export type RevocationInput = Readonly<{ municipalityId: string; policyVersion: string; subjectPubkey: string; attestorId: string; revokedAt: number }>;
export type AttestationCore = AttestationInput & Readonly<{ schemaVersion: typeof ATTESTATION_SCHEMA }>;
export type RevocationCore = RevocationInput & Readonly<{ schemaVersion: typeof REVOCATION_SCHEMA }>;
export type SignedAttestation = Readonly<{ core: AttestationCore; signature: string }>;
export type SignedRevocation = Readonly<{ core: RevocationCore; signature: string }>;
export function buildAttestation(input: AttestationInput): AttestationCore {
  return { schemaVersion: ATTESTATION_SCHEMA, ...input, documentKinds: [...input.documentKinds] };
}
export function buildRevocation(input: RevocationInput): RevocationCore {
  return { schemaVersion: REVOCATION_SCHEMA, ...input };
}
export function signAttestation(secretKey: Uint8Array, core: AttestationCore): SignedAttestation {
  return { core, signature: signCanonical(secretKey, { domain: ATTESTATION_DOMAIN, core }) };
}
export function signRevocation(secretKey: Uint8Array, core: RevocationCore): SignedRevocation {
  return { core, signature: signCanonical(secretKey, { domain: REVOCATION_DOMAIN, core }) };
}
export function subjectCode(municipalityId: string, subjectPubkey: string): string {
  if (!isMunicipalityId(municipalityId) || !isHex64(subjectPubkey)) fail("subject_code_invalid");
  return `stadtstack-participation/subject/v1/${municipalityId}/${subjectPubkey}`;
}
export function parseSubjectCode(text: string, expectedMunicipalityId?: string): Readonly<{ municipalityId: string; subjectPubkey: string }> {
  const parts = text.split("/");
  if (parts.length !== 5 || parts[0] !== "stadtstack-participation" || parts[1] !== "subject" || parts[2] !== "v1" || !isMunicipalityId(parts[3]) || !isHex64(parts[4]) || (expectedMunicipalityId !== undefined && parts[3] !== expectedMunicipalityId)) fail("subject_code_invalid");
  return { municipalityId: parts[3], subjectPubkey: parts[4] };
}
export function subjectFingerprint(pubkey: string): string {
  if (!isHex64(pubkey)) fail("subject_code_invalid");
  return `${pubkey.slice(0, 4)} ${pubkey.slice(4, 8)} … ${pubkey.slice(-8, -4)} ${pubkey.slice(-4)}`;
}
