import { finalizeEvent, getPublicKey, type EventTemplate } from "nostr-tools/pure";
import { canonical, digest } from "../../src/shared/canonical.ts";
import { ed25519PublicKeyHex, loadEd25519PrivateKey, signCanonical } from "../../src/shared/ed25519.ts";
import { openDatabase } from "../../src/shared/db.ts";
import { nip98Header, nip98Template } from "../../src/shared/nostr.ts";
import { InPersonAttestorsAdapter } from "../../src/adapters/in-person-attestors.ts";
import { parseIssuerPolicy } from "../../src/issuer/policy.ts";
import { IssuerStore } from "../../src/issuer/store.ts";
import { IssuerService } from "../../src/issuer/service.ts";
import { createHttpHandler } from "../../src/http.ts";

export const participantKey = new Uint8Array(32).fill(11);
export const adopterKey = new Uint8Array(32).fill(12);
export const agentKey = new Uint8Array(32).fill(13);
export const subject = getPublicKey(adopterKey);
export const issuerKey = loadEd25519PrivateKey({ seedHex: "51".repeat(32) });
export const attestorKeys = [31, 32, 33].map((n) => loadEd25519PrivateKey({ seedHex: n.toString(16).repeat(32) }));
export const basis = { residence: "main_residence", minimumAgeYears: 16, nationality: "any", localityScope: null };
export const municipalityId = "sample-town";
export const policyVersion = "policy-1";
export const topicId = `urn:stadtstack:topic:municipality:${municipalityId}:park`;

export function signed(template: EventTemplate, key: Uint8Array) {
  return JSON.parse(JSON.stringify(finalizeEvent(template, key)));
}

export function policyInput() {
  return { schemaVersion: "municipal_eligibility_issuer_policy_v1", municipalityId, ags: "12001001", policyVersion, registry: null,
    issuer: "Sample eligibility issuer", issuerKeyId: "issuer-1", issuerPublicKey: ed25519PublicKeyHex(issuerKey), publicBaseUrl: "https://eligibility.example",
    statusBaseUrl: "https://eligibility.example/v1/eligibility/status", acceptanceBaseUrl: "https://eligibility.example/v1/adoptions",
    receiptTtlSeconds: 600, statusMaxAgeSeconds: 60, maxEventClockSkewSeconds: 30, allowedAgentPubkeys: [getPublicKey(agentKey)], basis,
    adapter: { kind: "in_person_attestors_v1", attestors: attestorKeys.map((key, i) => ({ attestorId: `attestor-${i}`, publicKey: ed25519PublicKeyHex(key),
      ownSubjectPubkeys: [getPublicKey(new Uint8Array(32).fill(41 + i))], validFrom: 10, validUntil: 10000 })), requiredAttestations: 2,
      attestationWindowSeconds: 20, validitySeconds: 1000, revocationThreshold: 2 } };
}

export function attestation(index: number, at: number, subjectPubkey = subject, revocation = false) {
  const core = { schemaVersion: revocation ? "in_person_residency_revocation_v1" : "in_person_residency_attestation_v1", municipalityId, policyVersion,
    subjectPubkey, attestorId: `attestor-${index}`, ...(revocation ? { revokedAt: at } : { attestedAt: at, basis, documentKinds: ["identity_card", "residence_register"] }) };
  return { core, signature: signCanonical(attestorKeys[index]!, { domain: revocation ? "in-person-residency-revocation/v1" : "in-person-residency-attestation/v1", core }) };
}

export function setup(at = 100) {
  const db = openDatabase(":memory:");
  const policy = parseIssuerPolicy(policyInput());
  if (policy.adapter.kind !== "in_person_attestors_v1") throw new Error("fixture adapter");
  const adapter = new InPersonAttestorsAdapter(policy.adapter, { db, municipalityId, policyVersion, basis });
  let now = at;
  let locked = false;
  const issuer = new IssuerService({ policy, store: new IssuerStore(db), adapter, signingKey: issuerKey, clock: () => now,
    commitmentLock: { isCommitmentInOpenAnchor: () => locked } });
  const handler = createHttpHandler({ issuer });
  return { db, policy, adapter, issuer, handler, setTime(value: number) { now = value; }, setLocked(value: boolean) { locked = value; } };
}

export function sourceBundle() {
  const participant = getPublicKey(participantKey);
  const sourceId = "ab".repeat(32);
  const sourceDiscussion = signed({ kind: 1, created_at: 80, content: "@mecky Please explain the park proposal.", tags: [["p", getPublicKey(agentKey)], ["q", sourceId, "", participant], ["source-post", sourceId],
    ["t", "stadtstack-civic-discussion"], ["municipality", municipalityId], ["topic", topicId], ["topic-title", "A better park"], ["stance", "root"], ["argument-root", "self"]] }, participantKey);
  const receiptId = `urn:stadtstack:mecky-answer:${"cd".repeat(32)}`;
  const sourceAnswer = signed({ kind: 1, created_at: 81, content: "The town can review this civic proposal.", tags: [["netizen_agent", "Mecky", "1"], ["e", sourceDiscussion.id, "", "reply"], ["p", participant],
    ["mecky-receipt", receiptId], ["municipality", municipalityId], ["topic", topicId], ["evidence", `sha256:${"ef".repeat(32)}`, "https://town.example/park"]] }, agentKey);
  const draftCore = { sourceAnswerId: sourceAnswer.id, sourceAnswerRef: `nostr://event/${sourceAnswer.id}`, sourceAnswerReceiptId: receiptId,
    sourceDiscussionId: sourceDiscussion.id, sourceDiscussionRef: `nostr://event/${sourceDiscussion.id}`, municipalityId, topicId, participantPubkey: participant,
    title: "Improve the municipal park", summary: "Add accessible paths and shaded seating." };
  const participantSuggestionEvent = signed({ kind: 1, created_at: 82, content: canonical({ schemaVersion: "public_participant_topic_suggestion_draft_v1", draftId: `urn:stadtstack:participant-topic-suggestion-draft:${digest(draftCore)}`,
    ...draftCore, entryState: "citizen_adoption_required", authorityBinding: "none", submittedToCivicWorkflow: false }),
    tags: [["schema", "staging_participant_signed_topic_suggestion_v1"], ["municipality", municipalityId], ["topic", topicId], ["e", sourceDiscussion.id, "", "root"], ["mecky-receipt", receiptId], ["credential-class", "staging-participant"]] }, participantKey);
  return { sourceDiscussion, sourceAnswer, participantSuggestionEvent };
}

export function authenticatedRequest(path: string, input: unknown, at = 100, key = adopterKey): Request {
  const url = `https://eligibility.example${path}`;
  const body = Buffer.from(JSON.stringify(input));
  const auth = signed(nip98Template({ url, method: "POST", body, createdAt: at }), key);
  return new Request(url, { method: "POST", body, headers: { "content-type": "application/json", authorization: nip98Header(auth) } });
}
