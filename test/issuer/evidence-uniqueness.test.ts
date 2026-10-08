import assert from "node:assert/strict";
import test from "node:test";
import { createHttpHandler } from "../../src/http.ts";
import { parseIssuerPolicy } from "../../src/issuer/policy.ts";
import { IssuerService } from "../../src/issuer/service.ts";
import { IssuerStore } from "../../src/issuer/store.ts";
import { openDatabase } from "../../src/shared/db.ts";
import type { EligibilityAdapter, EligibilityDecision } from "../../src/shared/seams.ts";
import { adopterKey, authenticatedRequest, issuerKey, policyInput, sourceBundle } from "./fixtures.ts";

// Like a wallet or an EU credential: the same evidence, whichever subject key asks.
const sameEvidence: EligibilityDecision = { state: "active", effectiveAt: 0, validUntil: null, evidenceRef: "wallet-0xabc" };
const otherSubjectKey = new Uint8Array(32).fill(77);

function setup() {
  const db = openDatabase(":memory:");
  const policy = parseIssuerPolicy(policyInput());
  const adapter: EligibilityAdapter = { kind: policy.adapter.kind, async check() { return sameEvidence; }, async recheck() { return sameEvidence; } };
  let locked = false;
  const issuer = new IssuerService({ policy, store: new IssuerStore(db), adapter, signingKey: issuerKey, clock: () => 100,
    commitmentLock: { isCommitmentInOpenAnchor: () => locked } });
  return { db, policy, issuer, handler: createHttpHandler({ issuer }), setLocked(value: boolean) { locked = value; } };
}

test("one piece of evidence holds one active enrollment, whichever subject key enrolls it", async () => {
  const c = setup();
  const first = `0x${"00".repeat(31)}01`;
  const second = `0x${"00".repeat(31)}02`;
  const enroll = (commitment: string, key: Uint8Array<ArrayBuffer>, at = 100) => c.handler(authenticatedRequest("/v1/identity-commitments", { identityCommitment: commitment, evidence: null }, at, key));
  assert.equal((await enroll(first, adopterKey)).status, 201);
  c.setLocked(true);
  const blocked = await enroll(second, otherSubjectKey);
  assert.equal(blocked.status, 409);
  assert.deepEqual(await blocked.json(), { error: "commitment_locked" });
  c.setLocked(false);
  assert.equal((await enroll(second, otherSubjectKey, 101)).status, 201);
  const source = { municipalityId: c.policy.municipalityId, policyVersion: c.policy.policyVersion, at: 100, signal: new AbortController().signal };
  assert.deepEqual(await c.issuer.listEligibleCommitments(source), [second]);
});

test("one piece of evidence adopts a suggestion under one subject key only", async () => {
  const c = setup();
  const suggestion = sourceBundle().participantSuggestionEvent;
  const issue = (key: Uint8Array<ArrayBuffer>, at = 100) => c.handler(authenticatedRequest("/v1/eligibility/receipts", { participantSuggestionEvent: suggestion, evidence: null }, at, key));
  assert.equal((await issue(adopterKey)).status, 201);
  const second = await issue(otherSubjectKey);
  assert.equal(second.status, 409);
  assert.deepEqual(await second.json(), { error: "evidence_already_used" });
  assert.equal((await issue(adopterKey, 101)).status, 201, "the same subject may renew its receipt");
});
