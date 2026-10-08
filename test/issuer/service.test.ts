import assert from "node:assert/strict";
import test from "node:test";
import { parseIssuerPolicy, toStadtstackPolicy } from "../../src/issuer/policy.ts";
import { buildAdoptionEventTemplate, type EligibilityReceipt } from "../../src/issuer/artifacts.ts";
import { canonical } from "../../src/shared/canonical.ts";
import { adopterKey, participantKey, attestation, authenticatedRequest, policyInput, setup, signed, sourceBundle } from "./fixtures.ts";

test("policy exact keys, URL equality, bounds, adapter validation and issuer separation", () => {
  const input = policyInput();
  const policy = parseIssuerPolicy(input);
  assert.equal(Object.keys(toStadtstackPolicy(policy)).length, 10);
  for (const patch of [{ extra: true }, { statusBaseUrl: "https://elsewhere.example/v1/eligibility/status" }, { publicBaseUrl: "https://eligibility.example/" },
    { receiptTtlSeconds: 59 }, { receiptTtlSeconds: 3601 }, { statusMaxAgeSeconds: 0 }, { statusMaxAgeSeconds: 301 }, { maxEventClockSkewSeconds: 301 },
    { adapter: { ...input.adapter, requiredAttestations: 1 } }, { issuerPublicKey: input.adapter.attestors[0]!.publicKey }]) {
    assert.throws(() => parseIssuerPolicy({ ...input, ...patch }));
  }
  parseIssuerPolicy({ ...input, receiptTtlSeconds: 60, statusMaxAgeSeconds: 1, maxEventClockSkewSeconds: 0 });
  parseIssuerPolicy({ ...input, receiptTtlSeconds: 3600, statusMaxAgeSeconds: 300, maxEventClockSkewSeconds: 300 });
});

test("NIP-98 request ids persist single-use protection and bind exact request bodies", async () => {
  const c = setup();
  try {
    c.adapter.recordAttestation(attestation(0, 90), 100); c.adapter.recordAttestation(attestation(1, 95), 100);
    const request = authenticatedRequest("/v1/eligibility/receipts", { participantSuggestionEvent: sourceBundle().participantSuggestionEvent, evidence: null });
    assert.equal((await c.handler(request.clone())).status, 201);
    const replay = await c.handler(request.clone());
    assert.equal(replay.status, 409); assert.deepEqual(await replay.json(), { error: "auth_replayed" });
    const mutated = new Request(request.url, { method: "POST", headers: request.headers, body: "{}" });
    assert.equal((await c.handler(mutated)).status, 401);
    assert.equal(c.db.prepare("SELECT COUNT(*) AS count FROM issuer_auth_events").get()!.count, 1);
  } finally { c.db.close(); }
});

test("fresh status rechecks each call, validates nonce, expires receipts and remains bounded", async () => {
  const c = setup();
  try {
    c.adapter.recordAttestation(attestation(0, 90), 100); c.adapter.recordAttestation(attestation(1, 95), 100);
    const issued = await c.handler(authenticatedRequest("/v1/eligibility/receipts", { participantSuggestionEvent: sourceBundle().participantSuggestionEvent, evidence: null }));
    const receipt = await issued.json() as EligibilityReceipt;
    const url = receipt.statusRef;
    assert.equal((await c.handler(new Request(url))).status, 400);
    const nonce = "aa".repeat(32);
    const request = () => new Request(url, { headers: { "x-stadtstack-status-nonce": nonce } });
    const active = await c.handler(request());
    assert.equal(active.headers.get("cache-control"), "no-store"); assert.equal(active.headers.get("set-cookie"), null);
    const body = await active.json(); assert.equal(body.statusCore.state, "active"); assert.equal(body.statusCore.requestNonce, nonce);
    assert.ok(Buffer.byteLength(canonical(body)) <= 16384);
    c.adapter.recordRevocation(attestation(0, 100, undefined, true), 100); c.adapter.recordRevocation(attestation(1, 100, undefined, true), 100);
    assert.equal((await (await c.handler(request())).json()).statusCore.state, "inactive");
    c.setTime(700);
    assert.equal((await (await c.handler(request())).json()).statusCore.state, "expired");
  } finally { c.db.close(); }
});

test("enrollment supersession obeys open-anchor lock and eligible source rechecks", async () => {
  const c = setup();
  try {
    c.adapter.recordAttestation(attestation(0, 90), 100); c.adapter.recordAttestation(attestation(1, 95), 100);
    const first = `0x${"00".repeat(31)}01`;
    const second = `0x${"00".repeat(31)}02`;
    assert.equal((await c.handler(authenticatedRequest("/v1/identity-commitments", { identityCommitment: first, evidence: null }))).status, 201);
    const sourceInput = { municipalityId: c.policy.municipalityId, policyVersion: c.policy.policyVersion, at: 100, signal: new AbortController().signal };
    assert.deepEqual(await c.issuer.listEligibleCommitments(sourceInput), [first]);
    c.setLocked(true);
    assert.equal((await c.handler(authenticatedRequest("/v1/identity-commitments", { identityCommitment: second, evidence: null }))).status, 409);
    c.setLocked(false); c.setTime(101);
    assert.equal((await c.handler(authenticatedRequest("/v1/identity-commitments", { identityCommitment: second, evidence: null }, 101))).status, 201);
    assert.equal(c.db.prepare("SELECT COUNT(*) AS count FROM issuer_enrollments WHERE active=1").get()!.count, 1);
    assert.deepEqual(await c.issuer.listEligibleCommitments({ ...sourceInput, at: 101 }), [second]);
    c.adapter.recordRevocation(attestation(0, 101, undefined, true), 101); c.adapter.recordRevocation(attestation(1, 101, undefined, true), 101);
    assert.deepEqual(await c.issuer.listEligibleCommitments({ ...sourceInput, at: 101 }), []);
  } finally { c.db.close(); }
});

test("adoption ledger enforces uniqueness, exact bindings and acceptance times", async () => {
  const c = setup();
  try {
    c.adapter.recordAttestation(attestation(0, 90), 100); c.adapter.recordAttestation(attestation(1, 95), 100);
    const suggestion = sourceBundle().participantSuggestionEvent;
    const issued = await c.handler(authenticatedRequest("/v1/eligibility/receipts", { participantSuggestionEvent: suggestion, evidence: null }));
    const receipt = await issued.json() as EligibilityReceipt;
    const template = buildAdoptionEventTemplate({ receipt, participantSuggestionEvent: suggestion, createdAt: 100 });
    const event = signed(template, adopterKey);
    const request = { schemaVersion: "citizen_topic_suggestion_adoption_request_v1", adoptionEvent: event };
    const accepted = c.issuer.acceptAdoption(request);
    assert.deepEqual(c.issuer.adoption(event.id), accepted);
    assert.throws(() => c.issuer.acceptAdoption(request), /adoption_already_accepted/u);
    const changed = signed({ ...template, tags: [...template.tags, ["extra", "tag"]] }, adopterKey);
    assert.throws(() => c.issuer.acceptAdoption({ ...request, adoptionEvent: changed }), /adoption_binding_invalid/u);
    c.setTime(131);
    assert.throws(() => c.issuer.acceptAdoption(request), /adoption_time_or_subject_invalid/u);
    c.setTime(700);
    assert.throws(() => c.issuer.acceptAdoption(request), /adoption_time_or_subject_invalid/u);
  } finally { c.db.close(); }
});

test("HTTP attestor endpoints persist signatures and reject unsupported bodies", async () => {
  const c = setup();
  try {
    for (const path of ["/v1/attestations", "/v1/attestation-revocations"]) {
      const response = await c.handler(new Request(`https://eligibility.example${path}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(attestation(0, 90, undefined, path.includes("revocations"))) }));
      assert.equal(response.status, 201);
    }
    const publicPolicy = await c.handler(new Request("https://eligibility.example/v1/policy"));
    assert.deepEqual(await publicPolicy.json(), c.policy);
    const badType = await c.handler(new Request("https://eligibility.example/v1/attestations", { method: "POST", body: "{}" }));
    assert.equal(badType.status, 415);
  } finally { c.db.close(); }
});

test("receipt issuance rejects invalid suggestions and cannot predate a signed suggestion", async () => {
  const c = setup();
  try {
    c.adapter.recordAttestation(attestation(0, 90), 100); c.adapter.recordAttestation(attestation(1, 95), 100);
    const event = sourceBundle().participantSuggestionEvent;
    const invalid = [
      { ...event, sig: "00".repeat(64) },
      signed({ ...event, kind: 2 }, participantKey),
      signed({ ...event, tags: [...event.tags, ["extra", "tag"]] }, participantKey),
      signed({ ...event, content: `${event.content} ` }, participantKey),
      signed({ ...event, created_at: 101 }, participantKey),
    ];
    for (let i = 0; i < invalid.length; i++) {
      const response = await c.handler(authenticatedRequest("/v1/eligibility/receipts", { participantSuggestionEvent: invalid[i], evidence: { attempt: i } }));
      assert.equal(response.status, 400);
    }
    assert.equal(c.db.prepare("SELECT COUNT(*) AS count FROM issuer_receipts").get()!.count, 0);
    const response = await c.handler(authenticatedRequest("/v1/eligibility/receipts", { participantSuggestionEvent: event, evidence: null }));
    const receipt = await response.json() as EligibilityReceipt;
    assert.ok(receipt.eligibilityCore.issuedAt >= event.created_at);
    assert.equal(receipt.eligibilityCore.expiresAt - receipt.eligibilityCore.issuedAt, c.policy.receiptTtlSeconds);
  } finally { c.db.close(); }
});
