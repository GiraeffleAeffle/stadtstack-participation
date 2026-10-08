import { canonical, digest, exact, isSafeNonNegativeInteger, object, snapshot } from "../shared/canonical.ts";
import { ed25519PublicKeyHex, signCanonical } from "../shared/ed25519.ts";
import { fail } from "../shared/errors.ts";
import { isBytes32, isHex64 } from "../shared/ids.ts";
import { verifyNip98, type Nip98Identity } from "../shared/nostr.ts";
import type { Clock, CommitmentLock, EligibilityAdapter, EligibilityDecision, EligibleCommitmentSource } from "../shared/seams.ts";
import { buildAdoptionEventTemplate, issueEligibilityReceipt, readAdoptionRequest, verifySuggestion, type EligibilityReceipt } from "./artifacts.ts";
import { parseIssuerPolicy, type IssuerPolicy } from "./policy.ts";
import { IssuerStore } from "./store.ts";

const FIELD_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
type ReceiptRow = { receipt_json: string; suggestion_json: string; evidence_ref: string };
type EnrollmentRow = { id: number; municipality_id: string; policy_version: string; subject_pubkey: string; commitment: `0x${string}`; evidence_ref: string };
type SuggestionEvidenceRow = { subject_pubkey: string };

export class IssuerService implements EligibleCommitmentSource {
  readonly policy: IssuerPolicy;
  readonly store: IssuerStore;
  readonly adapter: EligibilityAdapter;
  readonly signingKey: Uint8Array;
  readonly clock: Clock;
  readonly commitmentLock: CommitmentLock;

  constructor(options: Readonly<{ policy: IssuerPolicy; store: IssuerStore; adapter: EligibilityAdapter; signingKey: Uint8Array; clock: Clock; commitmentLock: CommitmentLock }>) {
    this.policy = parseIssuerPolicy(options.policy); this.store = options.store; this.adapter = options.adapter;
    this.signingKey = options.signingKey; this.clock = options.clock; this.commitmentLock = options.commitmentLock;
    if (ed25519PublicKeyHex(this.signingKey) !== this.policy.issuerPublicKey || this.adapter.kind !== this.policy.adapter.kind) fail("issuer_configuration_invalid", 500);
  }

  authenticate(request: Request, body: Uint8Array): Nip98Identity {
    const url = new URL(request.url);
    if (url.origin !== this.policy.publicBaseUrl || url.search || url.hash) fail("auth_url_invalid", 401);
    const identity = verifyNip98({ authorization: request.headers.get("authorization"), method: request.method, url: request.url, body,
      now: this.clock(), maxSkewSeconds: this.policy.maxEventClockSkewSeconds });
    this.store.consumeAuth(identity.eventId);
    return identity;
  }

  async issueReceipt(input: unknown, identity: Nip98Identity, signal: AbortSignal): Promise<EligibilityReceipt> {
    const request = exact(snapshot(input), ["participantSuggestionEvent", "evidence"], "receipt_request_invalid");
    const { event, draft } = verifySuggestion(request.participantSuggestionEvent, this.policy.municipalityId);
    const now = this.clock();
    if (now < event.created_at) fail("suggestion_from_future");
    const decision = await this.adapter.check({ municipalityId: this.policy.municipalityId, policyVersion: this.policy.policyVersion,
      subjectPubkey: identity.pubkey, purpose: { kind: "adoption_receipt", participantSuggestionId: event.id, topicId: draft.topicId },
      requestId: identity.eventId, evidence: request.evidence, now, signal });
    this.requireActive(decision, now);
    const receipt = issueEligibilityReceipt(this.policy, this.signingKey, identity.pubkey, event, draft, now);
    this.store.db.exec("BEGIN IMMEDIATE");
    try {
      this.store.db.prepare("INSERT OR IGNORE INTO issuer_suggestion_evidence VALUES (?, ?, ?)").run(event.id, decision.evidenceRef, identity.pubkey);
      const bound = this.store.db.prepare("SELECT subject_pubkey FROM issuer_suggestion_evidence WHERE participant_suggestion_id=? AND evidence_ref=?").get(event.id, decision.evidenceRef) as SuggestionEvidenceRow;
      if (bound.subject_pubkey !== identity.pubkey) fail("evidence_already_used", 409);
      this.store.db.prepare("INSERT OR IGNORE INTO issuer_receipts VALUES (?, ?, ?, ?, ?)").run(receipt.payloadChecksum, receipt.receiptId, canonical(receipt), canonical(event), decision.evidenceRef);
      this.store.db.exec("COMMIT");
    } catch (error) { this.store.db.exec("ROLLBACK"); throw error; }
    return receipt;
  }

  async status(payloadChecksum: string, nonce: string | null, signal: AbortSignal): Promise<unknown> {
    if (!isHex64(payloadChecksum) || !isHex64(nonce)) fail("status_request_invalid");
    const row = this.store.db.prepare("SELECT * FROM issuer_receipts WHERE payload_checksum=?").get(payloadChecksum) as ReceiptRow | undefined;
    if (!row) fail("receipt_not_found", 404);
    const receipt = JSON.parse(row.receipt_json) as EligibilityReceipt;
    const now = this.clock();
    const decision = await this.adapter.recheck({ municipalityId: this.policy.municipalityId, policyVersion: this.policy.policyVersion,
      subjectPubkey: receipt.eligibilityCore.subjectPubkey, evidenceRef: row.evidence_ref, now, signal });
    const active = decision.state === "active" && decision.effectiveAt <= now && (decision.validUntil === null || decision.validUntil > now);
    const statusCore = { schemaVersion: "municipal_civic_eligibility_status_v1", receiptId: receipt.receiptId, payloadChecksum,
      policyVersion: this.policy.policyVersion, state: now >= receipt.eligibilityCore.expiresAt ? "expired" : active ? "active" : "inactive",
      effectiveAt: active ? Math.max(receipt.eligibilityCore.issuedAt, decision.effectiveAt) : now,
      observedAt: now, audience: "stadtstack-case-steward-admission", requestNonce: nonce };
    const statusChecksum = digest(statusCore);
    const result = { statusCore, statusChecksum, proof: { algorithm: "Ed25519", keyId: this.policy.issuerKeyId,
      signature: signCanonical(this.signingKey, { domain: "municipal-civic-eligibility-status/v1", schemaVersion: statusCore.schemaVersion, statusChecksum }) } };
    if (Buffer.byteLength(canonical(result)) > 16384) fail("status_too_large", 500);
    return result;
  }

  acceptAdoption(input: unknown): unknown {
    const event = readAdoptionRequest(input);
    let content: Record<string, unknown>;
    try { content = object(snapshot(JSON.parse(event.content))); } catch { fail("adoption_content_invalid"); }
    if (typeof content.eligibilityReceiptId !== "string") fail("adoption_binding_invalid");
    const row = this.store.db.prepare("SELECT * FROM issuer_receipts WHERE receipt_id=?").get(content.eligibilityReceiptId) as ReceiptRow | undefined;
    if (!row) fail("receipt_not_found", 404);
    const receipt = JSON.parse(row.receipt_json) as EligibilityReceipt;
    const now = this.clock();
    const core = receipt.eligibilityCore;
    if (now < core.issuedAt || now >= core.expiresAt || event.created_at < core.issuedAt || event.created_at >= core.expiresAt ||
      Math.abs(now - event.created_at) > this.policy.maxEventClockSkewSeconds || event.pubkey !== core.subjectPubkey) fail("adoption_time_or_subject_invalid");
    const template = buildAdoptionEventTemplate({ receipt, participantSuggestionEvent: JSON.parse(row.suggestion_json), createdAt: event.created_at });
    if (event.content !== template.content || canonical(event.tags) !== canonical(template.tags)) fail("adoption_binding_invalid");
    const acceptanceCore = { schemaVersion: "citizen_topic_suggestion_adoption_acceptance_receipt_v1", adoptionId: content.adoptionId,
      adoptionEventId: event.id, municipalityId: core.municipalityId, topicId: core.topicId, participantSuggestionId: core.participantSuggestionId,
      adopterPubkey: event.pubkey, eligibilityReceiptId: receipt.receiptId,
      requestChecksum: digest({ schemaVersion: "citizen_topic_suggestion_adoption_request_v1", adoptionEvent: event }),
      eventCreatedAt: event.created_at, receivedAt: now, policyVersion: core.policyVersion, status: "accepted", authorityBinding: "civic_eligibility_only" };
    const acceptance = { ...acceptanceCore, receiptChecksum: digest(acceptanceCore) };
    const inserted = this.store.db.prepare("INSERT OR IGNORE INTO issuer_adoptions VALUES (?, ?, ?, ?, ?, ?)").run(event.id, core.municipalityId, core.participantSuggestionId, event.pubkey, canonical(acceptance), canonical(event));
    if (inserted.changes !== 1) fail("adoption_already_accepted", 409);
    return acceptance;
  }

  adoption(eventId: string): unknown {
    if (!isHex64(eventId)) fail("adoption_id_invalid");
    const row = this.store.db.prepare("SELECT acceptance_json FROM issuer_adoptions WHERE adoption_event_id=?").get(eventId) as { acceptance_json: string } | undefined;
    if (!row) fail("adoption_not_found", 404);
    return JSON.parse(row.acceptance_json);
  }

  async enroll(input: unknown, identity: Nip98Identity, signal: AbortSignal): Promise<unknown> {
    const request = exact(snapshot(input), ["identityCommitment", "evidence"], "enrollment_request_invalid");
    if (!isBytes32(request.identityCommitment) || BigInt(request.identityCommitment) <= 0n || BigInt(request.identityCommitment) >= FIELD_MODULUS) fail("commitment_invalid");
    const now = this.clock();
    const decision = await this.adapter.check({ municipalityId: this.policy.municipalityId, policyVersion: this.policy.policyVersion,
      subjectPubkey: identity.pubkey, purpose: { kind: "commitment_enrollment", commitment: request.identityCommitment }, requestId: identity.eventId, evidence: request.evidence, now, signal });
    const enrolledAt = this.clock();
    this.requireActive(decision, enrolledAt);
    this.store.db.exec("BEGIN IMMEDIATE");
    try {
      const scope = { municipalityId: this.policy.municipalityId, at: enrolledAt };
      const bySubject = this.store.db.prepare("SELECT * FROM issuer_enrollments WHERE municipality_id=? AND subject_pubkey=? AND active=1").get(this.policy.municipalityId, identity.pubkey) as EnrollmentRow | undefined;
      const byEvidence = this.store.db.prepare("SELECT * FROM issuer_enrollments WHERE municipality_id=? AND evidence_ref=? AND active=1").get(this.policy.municipalityId, decision.evidenceRef) as EnrollmentRow | undefined;
      // A new subject key with the same evidence (for example after a lost
      // passkey) supersedes the old enrollment, unless an open poll pins it.
      const current = [bySubject, byEvidence].filter((row, index, rows): row is EnrollmentRow => row !== undefined && rows.findIndex((other) => other?.id === row.id) === index);
      const kept = current.find((row) => row.subject_pubkey === identity.pubkey && row.commitment === request.identityCommitment);
      const superseded = current.filter((row) => row !== kept);
      if (superseded.some((row) => this.commitmentLock.isCommitmentInOpenAnchor({ ...scope, commitment: row.commitment }))) fail("commitment_locked", 409);
      for (const row of superseded) this.store.db.prepare("UPDATE issuer_enrollments SET active=0 WHERE id=?").run(row.id);
      if (kept) {
        this.store.db.prepare("UPDATE issuer_enrollments SET policy_version=?, evidence_ref=? WHERE id=?").run(this.policy.policyVersion, decision.evidenceRef, kept.id);
      } else {
        const insert = this.store.db.prepare("INSERT OR IGNORE INTO issuer_enrollments(municipality_id,policy_version,subject_pubkey,commitment,evidence_ref,enrolled_at,active) VALUES (?,?,?,?,?,?,1)").run(this.policy.municipalityId, this.policy.policyVersion, identity.pubkey, request.identityCommitment, decision.evidenceRef, enrolledAt);
        if (insert.changes !== 1) fail("commitment_already_enrolled", 409);
      }
      this.store.db.exec("COMMIT");
    } catch (error) { this.store.db.exec("ROLLBACK"); throw error; }
    return { identityCommitment: request.identityCommitment, state: "active" };
  }

  async listEligibleCommitments(input: Readonly<{ municipalityId: string; policyVersion: string; at: number; signal: AbortSignal }>): Promise<readonly `0x${string}`[]> {
    if (input.municipalityId !== this.policy.municipalityId || input.policyVersion !== this.policy.policyVersion) fail("policy_mismatch");
    const rows = this.store.db.prepare("SELECT * FROM issuer_enrollments WHERE municipality_id=? AND policy_version=? AND active=1 AND enrolled_at<=?").all(input.municipalityId, input.policyVersion, input.at) as EnrollmentRow[];
    const commitments: `0x${string}`[] = [];
    for (const row of rows) {
      input.signal.throwIfAborted();
      const decision = await this.adapter.recheck({ municipalityId: input.municipalityId, policyVersion: input.policyVersion, subjectPubkey: row.subject_pubkey, evidenceRef: row.evidence_ref, now: input.at, signal: input.signal });
      if (decision.state === "active" && decision.effectiveAt <= input.at && (decision.validUntil === null || decision.validUntil > input.at)) commitments.push(row.commitment);
    }
    return commitments;
  }

  private requireActive(decision: EligibilityDecision, now: number): asserts decision is Extract<EligibilityDecision, { state: "active" }> {
    if (decision.state !== "active" || !isSafeNonNegativeInteger(decision.effectiveAt) || decision.effectiveAt > now ||
      (decision.validUntil !== null && (!isSafeNonNegativeInteger(decision.validUntil) || decision.validUntil <= now)) || typeof decision.evidenceRef !== "string" || !decision.evidenceRef) fail("subject_ineligible", 403);
  }
}
