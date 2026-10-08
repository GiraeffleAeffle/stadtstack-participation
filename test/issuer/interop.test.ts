import assert from "node:assert/strict";
import test from "node:test";
import { buildAdoptionEventTemplate, type EligibilityReceipt } from "../../src/issuer/artifacts.ts";
import { toStadtstackPolicy } from "../../src/issuer/policy.ts";
import { createCitizenAdoptionAcceptanceReader, createCitizenAdoptionEvidenceVerifier } from "../vendor/stadtstack/citizen-adoption-evidence.ts";
import { adopterKey, attestation, authenticatedRequest, setup, signed, sourceBundle } from "./fixtures.ts";

async function bundleFixture() {
  const context = setup();
  context.adapter.recordAttestation(attestation(0, 90), 100);
  context.adapter.recordAttestation(attestation(1, 95), 100);
  const sources = sourceBundle();
  const response = await context.handler(authenticatedRequest("/v1/eligibility/receipts", { participantSuggestionEvent: sources.participantSuggestionEvent, evidence: null }));
  assert.equal(response.status, 201);
  const eligibilityReceipt = await response.json() as EligibilityReceipt;
  const adoptionEvent = signed(buildAdoptionEventTemplate({ receipt: eligibilityReceipt, participantSuggestionEvent: sources.participantSuggestionEvent, createdAt: 100 }), adopterKey);
  const accepted = await context.handler(new Request("https://eligibility.example/v1/adoptions", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ schemaVersion: "citizen_topic_suggestion_adoption_request_v1", adoptionEvent }) }));
  assert.equal(accepted.status, 201);
  const bundle = { schemaVersion: "eligible_citizen_adopted_topic_suggestion_v1", ...sources, eligibilityReceipt, adoptionEvent };
  const fetcher: typeof fetch = async (input, init) => context.handler(new Request(input, init));
  const verifier = createCitizenAdoptionEvidenceVerifier({ policy: toStadtstackPolicy(context.policy), now: () => new Date(100000), fetch: fetcher,
    acceptance: createCitizenAdoptionAcceptanceReader({ baseUrl: context.policy.acceptanceBaseUrl, fetch: fetcher }) });
  return { ...context, bundle, verifier, fetcher };
}

test("pinned Stadtstack verifier accepts the complete signed issuer bundle through HTTP", async () => {
  const context = await bundleFixture();
  try {
    const verified = await context.verifier.verify(context.bundle);
    assert.equal(verified.schemaVersion, "verified_citizen_adoption_evidence_v1");
    assert.equal(verified.validUntil, 160);
    assert.equal(verified.authorityBinding, "none");
    const acceptance = await context.handler(new Request(`https://eligibility.example/v1/adoptions/${context.bundle.adoptionEvent.id}`));
    assert.deepEqual(await acceptance.json(), verified.adoptionAcceptance);
  } finally { context.db.close(); }
});

test("Stadtstack rejects an expired eligibility receipt", async () => {
  const context = await bundleFixture();
  try {
    const verifier = createCitizenAdoptionEvidenceVerifier({ policy: toStadtstackPolicy(context.policy), now: () => new Date(700000), fetch: context.fetcher,
      acceptance: createCitizenAdoptionAcceptanceReader({ baseUrl: context.policy.acceptanceBaseUrl, fetch: context.fetcher }) });
    await assert.rejects(verifier.verify(context.bundle), /citizen_adoption_receipt_expired/u);
  } finally { context.db.close(); }
});

test("Stadtstack rejects a subject freshly revoked after receipt issuance", async () => {
  const context = await bundleFixture();
  try {
    context.adapter.recordRevocation(attestation(0, 100, undefined, true), 100);
    context.adapter.recordRevocation(attestation(1, 100, undefined, true), 100);
    await assert.rejects(context.verifier.verify(context.bundle), /citizen_adoption_binding_invalid/u);
  } finally { context.db.close(); }
});

test("Stadtstack rejects the wrong deployment issuer key", async () => {
  const context = await bundleFixture();
  try {
    const verifier = createCitizenAdoptionEvidenceVerifier({ policy: { ...toStadtstackPolicy(context.policy), issuerPublicKey: "ff".repeat(32) }, now: () => new Date(100000), fetch: context.fetcher,
      acceptance: createCitizenAdoptionAcceptanceReader({ baseUrl: context.policy.acceptanceBaseUrl, fetch: context.fetcher }) });
    await assert.rejects(verifier.verify(context.bundle), /citizen_adoption_proof_invalid/u);
  } finally { context.db.close(); }
});
