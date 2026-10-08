import type { KeyObject } from "node:crypto";
import { canonical, digest, exact, object, snapshot } from "../shared/canonical.ts";
import { signCanonical } from "../shared/ed25519.ts";
import { fail } from "../shared/errors.ts";
import { isHex64, isTopicIdFor } from "../shared/ids.ts";
import { verifyNostrEvent, type NostrEvent, type EventTemplate } from "../shared/nostr.ts";
import type { IssuerPolicy } from "./policy.ts";

export type ReceiptCore = Readonly<{ municipalityId: string; eligibilityClass: "municipal_civic_participation"; subjectPubkey: string; participantSuggestionId: string; topicId: string; policyVersion: string; issuer: string; issuedAt: number; expiresAt: number; authorityBinding: "civic_eligibility_only" }>;
export type IssuerProof = Readonly<{ algorithm: "Ed25519"; keyId: string; signature: string }>;
export type EligibilityReceipt = Readonly<{ schemaVersion: "municipal_civic_eligibility_receipt_v1"; eligibilityCore: ReceiptCore; receiptId: string; payloadChecksum: string; statusRef: string; proof: IssuerProof }>;
export type SuggestionDraft = Readonly<{ sourceAnswerId: string; sourceAnswerRef: string; sourceAnswerReceiptId: string; sourceDiscussionId: string; sourceDiscussionRef: string; municipalityId: string; topicId: string; participantPubkey: string; title: string; summary: string }>;

function boundedText(value: unknown, limit: number, multiline = false): string {
  const forbidden = multiline ? /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u : /[\u0000-\u001f\u007f]/u;
  if (typeof value !== "string" || !value || value.trim() !== value || value.length > limit || forbidden.test(value)) fail("suggestion_invalid");
  return value;
}

export function verifySuggestion(input: unknown, municipalityId: string): Readonly<{ event: NostrEvent; draft: SuggestionDraft }> {
  const event = verifyNostrEvent(input, "suggestion_invalid");
  if (event.kind !== 1) fail("suggestion_invalid");
  let draft: Record<string, unknown>;
  try { draft = object(snapshot(JSON.parse(event.content))); } catch { fail("suggestion_invalid"); }
  if (canonical(draft) !== event.content || !isHex64(draft.sourceAnswerId) || !isHex64(draft.sourceDiscussionId) ||
    typeof draft.sourceAnswerReceiptId !== "string" || !/^urn:stadtstack:mecky-answer:[0-9a-f]{64}$/u.test(draft.sourceAnswerReceiptId) ||
    draft.municipalityId !== municipalityId || !isTopicIdFor(draft.topicId, municipalityId) || draft.participantPubkey !== event.pubkey) fail("suggestion_invalid");
  const core: SuggestionDraft = {
    sourceAnswerId: draft.sourceAnswerId, sourceAnswerRef: `nostr://event/${draft.sourceAnswerId}`,
    sourceAnswerReceiptId: draft.sourceAnswerReceiptId, sourceDiscussionId: draft.sourceDiscussionId, sourceDiscussionRef: `nostr://event/${draft.sourceDiscussionId}`,
    municipalityId, topicId: draft.topicId, participantPubkey: event.pubkey,
    title: boundedText(draft.title, 240), summary: boundedText(draft.summary, 2000, true),
  };
  if (canonical(draft) !== canonical({ schemaVersion: "public_participant_topic_suggestion_draft_v1", draftId: `urn:stadtstack:participant-topic-suggestion-draft:${digest(core)}`, ...core,
    entryState: "citizen_adoption_required", authorityBinding: "none", submittedToCivicWorkflow: false }) ||
    canonical(event.tags) !== canonical([["schema", "staging_participant_signed_topic_suggestion_v1"], ["municipality", municipalityId], ["topic", core.topicId],
      ["e", core.sourceDiscussionId, "", "root"], ["mecky-receipt", core.sourceAnswerReceiptId], ["credential-class", "staging-participant"]])) fail("suggestion_invalid");
  return { event, draft: core };
}

export function issueEligibilityReceipt(policy: IssuerPolicy, signingKey: KeyObject, subjectPubkey: string, suggestion: NostrEvent, draft: SuggestionDraft, issuedAt: number): EligibilityReceipt {
  const eligibilityCore: ReceiptCore = { municipalityId: policy.municipalityId, eligibilityClass: "municipal_civic_participation", subjectPubkey,
    participantSuggestionId: suggestion.id, topicId: draft.topicId, policyVersion: policy.policyVersion, issuer: policy.issuer,
    issuedAt, expiresAt: issuedAt + policy.receiptTtlSeconds, authorityBinding: "civic_eligibility_only" };
  const payloadChecksum = digest(eligibilityCore);
  const receiptId = `urn:stadtstack:municipal-civic-eligibility-receipt:${payloadChecksum}`;
  const statusRef = `${policy.statusBaseUrl}/${payloadChecksum}`;
  const schemaVersion = "municipal_civic_eligibility_receipt_v1";
  return { schemaVersion, eligibilityCore, receiptId, payloadChecksum, statusRef,
    proof: { algorithm: "Ed25519", keyId: policy.issuerKeyId, signature: signCanonical(signingKey, { domain: "municipal-civic-eligibility-receipt/v1", schemaVersion, receiptId, payloadChecksum, statusRef }) } };
}

/** The holder signs this template; the issuer never impersonates an adopter. */
export function buildAdoptionEventTemplate(input: Readonly<{ receipt: EligibilityReceipt; participantSuggestionEvent: NostrEvent; createdAt: number }>): EventTemplate {
  const { event, draft } = verifySuggestion(input.participantSuggestionEvent, input.receipt.eligibilityCore.municipalityId);
  const receipt = input.receipt;
  if (receipt.eligibilityCore.participantSuggestionId !== event.id || receipt.eligibilityCore.topicId !== draft.topicId ||
    input.createdAt < receipt.eligibilityCore.issuedAt || input.createdAt >= receipt.eligibilityCore.expiresAt) fail("adoption_binding_invalid");
  const core = { municipalityId: draft.municipalityId, topicId: draft.topicId, participantSuggestionId: event.id, participantSuggestionRef: `nostr://event/${event.id}`,
    participantPubkey: event.pubkey, sourceDiscussionId: draft.sourceDiscussionId, sourceAnswerReceiptId: draft.sourceAnswerReceiptId,
    adopterPubkey: receipt.eligibilityCore.subjectPubkey, eligibilityReceiptId: receipt.receiptId, eligibilityReceiptChecksum: receipt.payloadChecksum, title: draft.title, summary: draft.summary };
  return { kind: 1, created_at: input.createdAt, content: canonical({ schemaVersion: "public_citizen_topic_suggestion_adoption_v1",
    adoptionId: `urn:stadtstack:citizen-topic-suggestion-adoption:${digest(core)}`, ...core,
    entryState: "case_steward_review_required", authorityBinding: "civic_eligibility_only", submittedToCivicWorkflow: false }),
    tags: [["schema", "citizen_adopted_topic_suggestion_v1"], ["municipality", draft.municipalityId], ["topic", draft.topicId], ["e", event.id, "", "adopted-suggestion"],
      ["e", draft.sourceDiscussionId, "", "root"], ["p", event.pubkey], ["eligibility-receipt", receipt.receiptId], ["credential-class", "municipal-civic-eligibility"]] };
}

export function readAdoptionRequest(input: unknown): NostrEvent {
  const request = exact(snapshot(input), ["schemaVersion", "adoptionEvent"], "adoption_request_invalid");
  if (request.schemaVersion !== "citizen_topic_suggestion_adoption_request_v1") fail("adoption_request_invalid");
  const event = verifyNostrEvent(request.adoptionEvent, "adoption_event_invalid");
  if (event.kind !== 1) fail("adoption_event_invalid");
  return event;
}
