import assert from "node:assert/strict";
import test from "node:test";
import { base64 } from "@scure/base";
import { buildAttestation, buildRevocation, parseSubjectCode, signAttestation, signRevocation, subjectCode, subjectFingerprint } from "../../src/adapters/in-person-attestation.ts";
import type { ClientConfig, EligibilityBasis } from "../../src/shared/seams.ts";
import { authenticatedRequest, basisConditions, errorMessage, operatorNotice } from "../../web/src/common.ts";
import { adopterKey, attestorKeys, municipalityId, policyVersion, setup, subject } from "../issuer/fixtures.ts";
import { identityCommitment } from "../../src/vote/hash.ts";

const clientBasis: EligibilityBasis = { residence: "main_residence", minimumAgeYears: 16, nationality: "any", localityScope: null };
test("subject code round trip and strict rejection including wrong municipality", () => {
  const code = subjectCode(municipalityId, subject);
  assert.deepEqual(parseSubjectCode(code, municipalityId), { municipalityId, subjectPubkey: subject });
  assert.equal(subjectFingerprint("12345678" + "a".repeat(48) + "90abcdef"), "1234 5678 … 90ab cdef");
  for (const invalid of [code.replace("stadtstack-participation", "stadtstack"), code.replace("/v1/", "/v2/"), code.replace(municipalityId, "other-town"), code.replace(subject, subject.toUpperCase()), code.slice(0, -1), `${code}/extra`, ` ${code}`, `${code}\n`, code.replace(municipalityId, "bad_town")]) assert.throws(() => parseSubjectCode(invalid, municipalityId), /subject_code_invalid/u);
  assert.throws(() => subjectCode("Bad-town", subject), /subject_code_invalid/u);
  assert.throws(() => subjectFingerprint(subject.toUpperCase()), /subject_code_invalid/u);
});

test("client-built K attestations and revocations pass real HTTP/adapter and change eligibility", async (t) => {
  const fixture = setup(100); t.after(() => fixture.db.close());
  for (let index = 0; index < 2; index++) {
    const core = buildAttestation({ municipalityId, policyVersion, subjectPubkey: subject, attestorId: `attestor-${index}`, attestedAt: 100, basis: clientBasis, documentKinds: ["identity_card", "residence_register"] });
    const response = await fixture.handler(new Request("https://eligibility.example/v1/attestations", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(signAttestation(attestorKeys[index]!, core)) }));
    assert.equal(response.status, 201);
    const decision = await fixture.adapter.check({ municipalityId, policyVersion, subjectPubkey: subject, now: 100, purpose: { kind: "commitment_enrollment", commitment: identityCommitment(1n) }, requestId: "a".repeat(64), evidence: null, signal: new AbortController().signal });
    assert.equal(decision.state, index === 0 ? "inactive" : "active");
  }
  for (let index = 0; index < 2; index++) {
    const core = buildRevocation({ municipalityId, policyVersion, subjectPubkey: subject, attestorId: `attestor-${index}`, revokedAt: 100 });
    const response = await fixture.handler(new Request("https://eligibility.example/v1/attestation-revocations", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(signRevocation(attestorKeys[index]!, core)) }));
    assert.equal(response.status, 201);
  }
  const revoked = await fixture.adapter.recheck({ municipalityId, policyVersion, subjectPubkey: subject, evidenceRef: subject, now: 100, signal: new AbortController().signal });
  assert.deepEqual(revoked, { state: "inactive", reason: "revoked" });
});

test("browser NIP-98 builder binds POST bytes and GET without payload accepted by issuer", async (t) => {
  const fixture = setup(100); t.after(() => fixture.db.close());
  for (let index = 0; index < 2; index++) fixture.adapter.recordAttestation(signAttestation(attestorKeys[index]!, buildAttestation({ municipalityId, policyVersion, subjectPubkey: subject, attestorId: `attestor-${index}`, attestedAt: 100, basis: clientBasis, documentKinds: ["identity_card"] })), 100);
  const body = { identityCommitment: identityCommitment(42n), evidence: null };
  const init = authenticatedRequest(fixture.policy.publicBaseUrl, "/v1/identity-commitments", "POST", adopterKey, body, 100);
  const request = new Request(fixture.policy.publicBaseUrl + "/v1/identity-commitments", init);
  assert.equal(request.credentials, "omit"); assert.equal(request.cache, "no-store"); assert.equal(request.redirect, "error");
  const response = await fixture.handler(request); assert.equal(response.status, 201);
  const getInit = authenticatedRequest(fixture.policy.publicBaseUrl, "/v1/eligibility/me", "GET", adopterKey, undefined, 100);
  assert.equal(getInit.body, undefined);
  const headers = new Headers(getInit.headers);
  const event = JSON.parse(new TextDecoder().decode(base64.decode(headers.get("authorization")!.slice(6)))) as { tags: string[][] };
  assert.deepEqual(event.tags, [["u", fixture.policy.publicBaseUrl + "/v1/eligibility/me"], ["method", "GET"]]);
  const getResponse = await fixture.handler(new Request(fixture.policy.publicBaseUrl + "/v1/eligibility/me", getInit));
  assert.equal(getResponse.status, 200);
  const data = await getResponse.json() as { subjectPubkey: string; eligibility: { state: string }; enrollment: { identityCommitment: string } };
  assert.equal(data.subjectPubkey, subject); assert.equal(data.eligibility.state, "active"); assert.equal(data.enrollment.identityCommitment, body.identityCommitment);
});

test("client explains basis, recovery lock, duplicate vote and unknown failures without exposing server detail", () => {
  const config: ClientConfig = { schemaVersion: "participation_client_config_v1", municipalityId, ags: "12001001", policyVersion, displayName: "Strausberg", operator: { name: "Stadtstack", isMunicipality: false }, publicBaseUrl: "https://eligibility.example", adapterKind: "in_person_attestors_v1", basis: clientBasis, attestors: null, chain: null };
  assert.deepEqual(basisConditions(config), ["Hauptwohnsitz in Strausberg", "Mindestens 16 Jahre alt"]);
  assert.deepEqual(basisConditions({ ...config, basis: { ...clientBasis, residence: "main_or_secondary_residence", minimumAgeYears: null, nationality: "eu_citizen", localityScope: ["sample-locality"] } }), ["Haupt- oder Nebenwohnsitz in Strausberg", "Staatsangehörigkeit eines EU-Landes", "Wohnsitz im zugelassenen Ortsteil: sample-locality"]);
  // An independent operator must say it is not the administration.
  assert.equal(operatorNotice(config), "Ein unabhängiges Angebot von Stadtstack – kein Angebot der Verwaltung von Strausberg.");
  assert.equal(operatorNotice({ ...config, operator: { name: "Stadt Strausberg", isMunicipality: true } }), "Ein Angebot von Stadt Strausberg.");
  assert.match(errorMessage(new Error("commitment_locked")), /alten Schlüssel/u);
  assert.match(errorMessage(new Error("duplicate_nullifier")), /bereits teilgenommen/u);
  assert.match(errorMessage(new Error("chain_root_mismatch")), /keine Stimme gesendet/u);
  assert.match(errorMessage(new Error("prf_unavailable")), /keinen unsicheren Ersatz/u);
  assert.match(errorMessage(new Error("unknown sensitive failure")), /Betreiber/u);
  assert.ok(!errorMessage(new Error("unknown sensitive failure")).includes("sensitive"));
});

test("all client endpoint error families give a German action without reflecting error codes", () => {
  const families: Readonly<Record<string, readonly string[]>> = {
    "erneut|neu|aktualisiere": ["auth_invalid", "enrollment_request_invalid", "commitment_invalid", "attestation_signature_invalid", "election_unknown", "request_url_invalid", "content_type_invalid", "json_invalid", "election_id_invalid", "eudi_request_invalid", "eudi_transaction_not_found", "eudi_expired", "proof_invalid", "ballot_invalid"],
    "Betreiber|nutzt hier": ["auth_url_invalid", "evidence_already_used", "commitment_already_enrolled", "attestor_adapter_unavailable"],
    "nicht|ungültig": ["attestation_invalid", "body_too_large", "choice_invalid", "signal_mismatch", "field_invalid", "election_id_mismatch", "election_not_open"],
    "warte|später": ["rate_limited", "verification_busy", "auth_replayed", "verifier_unavailable", "verifier_response_invalid", "tally_unavailable"],
    "beendet|danach": ["tally_not_closed"],
    "Passkey": ["auth_required"],
    "bereits": ["duplicate_nullifier"],
    "alten Schlüssel": ["commitment_locked"],
    "Teilnahmeberechtigung": ["eligibility_insufficient_attestations", "eligibility_revoked", "eligibility_expired", "eligibility_evidence_required", "eligibility_eudi_evidence_invalid", "eligibility_eudi_transaction_not_found", "eligibility_transaction_expired", "eligibility_transaction_used", "eligibility_presentation_pending", "eligibility_evidence_expired", "eligibility_policy_mismatch"],
    "versuche|Betreiber": ["internal_error", "eudi_adapter_configuration_invalid", "server_chain_configuration_invalid", "unknown_future_error"],
  };
  for (const [expected, codes] of Object.entries(families)) for (const code of codes) {
    const message = errorMessage(new Error(code));
    assert.match(message, new RegExp(expected, "iu"), code);
    assert.ok(!message.includes(code), code);
  }
});
