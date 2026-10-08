// Vendored from GiraeffleAeffle/stadtstack, src/citizen-adoption-evidence.ts
// Commit: 30a677f; MIT licensed. Original SHA-256: 325efe2cb459b1783a2aa5053047572645bba5f64fc77198b9fc73478c213464
// Original source follows unchanged.
import { createHash, createPublicKey, randomBytes, verify as verifySignature } from "node:crypto";
import { types as utilTypes } from "node:util";
import { getEventHash, validateEvent, verifyEvent, type Event as NostrEvent } from "nostr-tools/pure";

/** Deployment policy, never a field in a citizen or staff request. */
export type CitizenAdoptionEvidencePolicy = Readonly<{
  municipalityId: string;
  policyVersion: string;
  issuer: string;
  issuerKeyId: string;
  issuerPublicKey: string;
  allowedAgentPubkeys: readonly string[];
  receiptTtlSeconds: number;
  statusBaseUrl: string;
  statusMaxAgeSeconds: number;
  maxEventClockSkewSeconds: number;
}>;

/** Four complete signed events and one issuer receipt, without duplicated signer claims. */
export type CitizenAdoptionEvidenceBundle = Readonly<{
  schemaVersion: "eligible_citizen_adopted_topic_suggestion_v1";
  sourceDiscussion: NostrEvent;
  sourceAnswer: NostrEvent;
  participantSuggestionEvent: NostrEvent;
  eligibilityReceipt: Readonly<Record<string, unknown>>;
  adoptionEvent: NostrEvent;
}>;

/** This exact-event read must come from the configured issuer's adoption ledger. */
export type CitizenAdoptionAcceptanceReader = Readonly<{
  resolve(input: Readonly<{ adoptionEventId: string; signal: AbortSignal }>): Promise<unknown>;
}>;

/**
 * Verified evidence is not an admission capability. The atomic writer must
 * recheck the deadline and consume the nonce with the root claim/journal/outbox.
 */
export type VerifiedCitizenAdoptionEvidence = Readonly<{
  schemaVersion: "verified_citizen_adoption_evidence_v1";
  bundle: CitizenAdoptionEvidenceBundle;
  adoptionAcceptance: Readonly<Record<string, unknown>>;
  eligibilityStatus: Readonly<Record<string, unknown>>;
  verifiedAt: number;
  validUntil: number;
  authorityBinding: "none";
}>;

const HEX = /^[0-9a-f]{64}$/u;
const SLUG = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const POLICY = /^[a-z0-9][a-z0-9._-]{2,99}$/u;
const EVENT_KEYS = ["id", "pubkey", "created_at", "kind", "tags", "content", "sig"];
const BUNDLE_KEYS = ["schemaVersion", "sourceDiscussion", "sourceAnswer", "participantSuggestionEvent", "eligibilityReceipt", "adoptionEvent"];
const RECEIPT_KEYS = ["schemaVersion", "eligibilityCore", "receiptId", "payloadChecksum", "statusRef", "proof"];
const CORE_KEYS = ["municipalityId", "eligibilityClass", "subjectPubkey", "participantSuggestionId", "topicId", "policyVersion", "issuer", "issuedAt", "expiresAt", "authorityBinding"];
const ACCEPTANCE_KEYS = ["schemaVersion", "adoptionId", "adoptionEventId", "municipalityId", "topicId", "participantSuggestionId", "adopterPubkey", "eligibilityReceiptId", "requestChecksum", "eventCreatedAt", "receivedAt", "policyVersion", "status", "authorityBinding", "receiptChecksum"];

function fail(code: string): never { throw new Error(code); }
function integer(value: unknown): value is number { return typeof value === "number" && Number.isSafeInteger(value) && value >= 0; }
function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail("citizen_adoption_shape_invalid");
  return value as Record<string, unknown>;
}
function exact(value: unknown, keys: readonly string[]): Record<string, unknown> {
  const result = object(value);
  if (Object.keys(result).length !== keys.length || keys.some((key) => !Object.hasOwn(result, key))) fail("citizen_adoption_shape_invalid");
  return result;
}
function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${canonical(record[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}
function digest(value: unknown): string { return createHash("sha256").update(canonical(value), "utf8").digest("hex"); }
function same(actual: unknown, expected: unknown): void {
  if (canonical(actual) !== canonical(expected)) fail("citizen_adoption_binding_invalid");
}

/** Copy only bounded JSON data; never evaluate getters, toJSON, proxies or cached verification symbols. */
function snapshot(input: unknown): unknown {
  let nodes = 0;
  let bytes = 0;
  const account = (size: number) => {
    bytes += size;
    if (bytes > 262_144) fail("citizen_adoption_shape_invalid");
  };
  const visit = (value: unknown, depth: number): unknown => {
    if (++nodes > 6_000 || depth > 16) fail("citizen_adoption_shape_invalid");
    account(2);
    if (value === null || typeof value === "boolean") return value;
    if (typeof value === "number" && Number.isSafeInteger(value)) return value;
    if (typeof value === "string" && value.length <= 65_536) {
      const size = Buffer.byteLength(value, "utf8");
      if (size > 65_536) fail("citizen_adoption_shape_invalid");
      account(size);
      return value;
    }
    if (!value || typeof value !== "object" || utilTypes.isProxy(value)) fail("citizen_adoption_shape_invalid");
    const array = Array.isArray(value);
    if (Object.getPrototypeOf(value) !== (array ? Array.prototype : Object.prototype)) fail("citizen_adoption_shape_invalid");
    const keys = Reflect.ownKeys(value);
    if (keys.length > 6_000 - nodes || keys.some((key) => typeof key !== "string" || key.length > 128)) fail("citizen_adoption_shape_invalid");
    const descriptors = Object.getOwnPropertyDescriptors(value);
    if (array && (value.length > 512 || keys.length !== value.length + 1)) fail("citizen_adoption_shape_invalid");
    const fields = array ? Array.from({ length: value.length }, (_, i) => String(i)) : keys as string[];
    const entries = fields.map((key) => {
      account(Buffer.byteLength(key, "utf8"));
      const descriptor = descriptors[key];
      if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) fail("citizen_adoption_shape_invalid");
      return [key, visit(descriptor.value, depth + 1)] as const;
    });
    return Object.freeze(array ? entries.map(([, child]) => child) : Object.fromEntries(entries));
  };
  const result = visit(input, 0);
  if (Buffer.byteLength(canonical(result), "utf8") > 262_144) fail("citizen_adoption_shape_invalid");
  return result;
}

function event(value: unknown): NostrEvent {
  const parsed = exact(value, EVENT_KEYS);
  if (parsed.kind !== 1 || !integer(parsed.created_at) || typeof parsed.id !== "string" || !HEX.test(parsed.id) ||
    typeof parsed.pubkey !== "string" || !HEX.test(parsed.pubkey) || typeof parsed.sig !== "string" ||
    !/^[0-9a-f]{128}$/u.test(parsed.sig) || typeof parsed.content !== "string" ||
    !Array.isArray(parsed.tags) || parsed.tags.length > 32 ||
    parsed.tags.some((tag) => !Array.isArray(tag) || tag.length > 8 || tag.some((entry) => typeof entry !== "string"))
  ) fail("citizen_adoption_event_invalid");
  // nostr-tools may cache a verification symbol. Verify a separate mutable
  // object so neither untrusted cache state nor a later mutation can be reused.
  const signed = structuredClone(parsed) as NostrEvent;
  if (!validateEvent(signed) || getEventHash(signed) !== signed.id || !verifyEvent(signed)) fail("citizen_adoption_event_invalid");
  return parsed as NostrEvent;
}
function tag(event: NostrEvent, name: string): string[] | undefined {
  const matches = event.tags.filter((entry) => entry[0] === name);
  if (matches.length > 1) fail("citizen_adoption_binding_invalid");
  return matches[0];
}
function content(event: NostrEvent): Record<string, unknown> {
  let parsed: unknown;
  try { parsed = snapshot(JSON.parse(event.content)); } catch { fail("citizen_adoption_content_invalid"); }
  if (canonical(parsed) !== event.content) fail("citizen_adoption_content_invalid");
  return object(parsed);
}
function boundedText(value: unknown, limit: number, multiline = false): string {
  const forbidden = multiline ? /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u : /[\u0000-\u001f\u007f]/u;
  if (typeof value !== "string" || value.trim() !== value || !value || value.length > limit || forbidden.test(value)) fail("citizen_adoption_content_invalid");
  return value;
}

function discussion(root: NostrEvent, policy: Pick<CitizenAdoptionEvidencePolicy, "municipalityId" | "allowedAgentPubkeys">): string {
  const agent = tag(root, "p")?.[1];
  const source = tag(root, "source-post")?.[1];
  const topic = tag(root, "topic")?.[1];
  const title = tag(root, "topic-title")?.[1];
  if (!agent || !policy.allowedAgentPubkeys.includes(agent) || !source || !HEX.test(source) ||
    !topic || topic.split(":").length !== 6 || !topic.startsWith(`urn:stadtstack:topic:municipality:${policy.municipalityId}:`) ||
    !SLUG.test(topic.split(":").at(-1)!) || !title || title.length < 3 || !/@mecky\b/iu.test(root.content)
  ) fail("citizen_adoption_discussion_invalid");
  boundedText(title, 120);
  boundedText(root.content, 2_000, true);
  const expected: string[][] = [["p", agent], ["q", source, "", root.pubkey], ["source-post", source]];
  if (tag(root, "source-app-post")) {
    const sourcePost = tag(root, "source-app-post")![1];
    const comment = tag(root, "source-app-comment")?.[1];
    const mention = tag(root, "source-conversation-mention")?.[1];
    const reply = tag(root, "source-mecky-reply")?.[1];
    const receipt = tag(root, "source-mecky-receipt")?.[1];
    const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
    if (!sourcePost || !uuid.test(sourcePost) || (comment !== undefined && !uuid.test(comment)) ||
      mention !== source || !reply || !HEX.test(reply) ||
      (receipt !== undefined && !/^urn:stadtstack:mecky-answer:[0-9a-f]{64}$/u.test(receipt))
    ) fail("citizen_adoption_discussion_invalid");
    expected.push(["source-app-post", sourcePost]);
    if (comment) expected.push(["source-app-comment", comment]);
    expected.push(["source-conversation-mention", mention], ["source-mecky-reply", reply]);
    if (receipt) expected.push(["source-mecky-receipt", receipt]);
  }
  expected.push(["t", "stadtstack-civic-discussion"], ["municipality", policy.municipalityId],
    ["topic", topic], ["topic-title", title], ["stance", "root"], ["argument-root", "self"]);
  same(root.tags, expected);
  return topic;
}

function sources(bundle: Pick<CitizenAdoptionEvidenceBundle, "sourceDiscussion" | "sourceAnswer" | "participantSuggestionEvent" | "adoptionEvent">, policy: Pick<CitizenAdoptionEvidencePolicy, "municipalityId" | "allowedAgentPubkeys">) {
  const root = event(bundle.sourceDiscussion);
  const answer = event(bundle.sourceAnswer);
  const suggestion = event(bundle.participantSuggestionEvent);
  const adoption = event(bundle.adoptionEvent);
  const topicId = discussion(root, policy);
  const receiptId = tag(answer, "mecky-receipt")?.[1];
  const evidence = answer.tags.filter((entry) => entry[0] === "evidence");
  if (answer.pubkey !== tag(root, "p")![1] || answer.created_at < root.created_at ||
    !receiptId || !/^urn:stadtstack:mecky-answer:[0-9a-f]{64}$/u.test(receiptId) ||
    evidence.length < 1 || evidence.length > 3 || new Set(evidence.map((entry) => entry[1])).size !== evidence.length ||
    evidence.some((entry) => {
      if (entry.length !== 3 || !/^sha256:[0-9a-f]{64}$/u.test(entry[1]!)) return true;
      try { const url = new URL(entry[2]!); return url.protocol !== "https:" || Boolean(url.username || url.password); }
      catch { return true; }
    })
  ) fail("citizen_adoption_answer_invalid");
  const agent = tag(answer, "netizen_agent");
  if (!agent || agent.length !== 3) fail("citizen_adoption_answer_invalid");
  boundedText(agent[1], 120);
  boundedText(agent[2], 120);
  boundedText(answer.content, 2_000, true);
  const expectedAnswerTags = [agent, ["e", root.id, "", "reply"], ["p", root.pubkey]];
  for (const name of ["source-app-post", "source-app-comment"]) {
    const selected = tag(root, name);
    if (selected) expectedAnswerTags.push(selected);
  }
  expectedAnswerTags.push(["mecky-receipt", receiptId], ["municipality", policy.municipalityId], ["topic", topicId], ...evidence);
  same(answer.tags, expectedAnswerTags);
  if (suggestion.pubkey !== root.pubkey || suggestion.created_at <= answer.created_at ||
    suggestion.created_at <= root.created_at || adoption.created_at < suggestion.created_at
  ) fail("citizen_adoption_binding_invalid");
  const draft = content(suggestion);
  const draftCore = {
    sourceAnswerId: answer.id, sourceAnswerRef: `nostr://event/${answer.id}`,
    sourceAnswerReceiptId: receiptId, sourceDiscussionId: root.id, sourceDiscussionRef: `nostr://event/${root.id}`,
    municipalityId: policy.municipalityId, topicId, participantPubkey: root.pubkey,
    title: boundedText(draft.title, 240), summary: boundedText(draft.summary, 2_000, true),
  };
  same(draft, { schemaVersion: "public_participant_topic_suggestion_draft_v1",
    draftId: `urn:stadtstack:participant-topic-suggestion-draft:${digest(draftCore)}`, ...draftCore,
    entryState: "citizen_adoption_required", authorityBinding: "none", submittedToCivicWorkflow: false });
  same(suggestion.tags, [
    ["schema", "staging_participant_signed_topic_suggestion_v1"], ["municipality", policy.municipalityId],
    ["topic", topicId], ["e", root.id, "", "root"], ["mecky-receipt", receiptId], ["credential-class", "staging-participant"],
  ]);
  return { root, answer, suggestion, adoption, draftCore, topicId };
}

async function responseJson(response: Response, signal: AbortSignal): Promise<unknown> {
  if (!response.ok || response.headers.get("content-type")?.split(";")[0]?.trim() !== "application/json" || !response.body) fail("citizen_adoption_status_unavailable");
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      signal.throwIfAborted();
      const chunk = await reader.read();
      if (chunk.done) break;
      size += chunk.value.byteLength;
      if (size > 16_384) fail("citizen_adoption_status_unavailable");
      chunks.push(chunk.value);
    }
    return snapshot(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks))));
  } finally { await reader.cancel().catch(() => {}); }
}

/** HTTPS transport for the deployment-trusted ledger; its checksum alone is not authority.
 * The caller supplies the verifier's abort budget, never a URL or credential. */
export function createCitizenAdoptionAcceptanceReader(config: Readonly<{
  baseUrl: string;
  fetch?: typeof fetch;
}>): CitizenAdoptionAcceptanceReader {
  const baseUrl = config.baseUrl;
  let base: URL;
  try { base = new URL(baseUrl); } catch { fail("citizen_adoption_acceptance_config_invalid"); }
  const request = config.fetch ?? globalThis.fetch;
  if (typeof baseUrl !== "string" || baseUrl.length > 2_048 ||
    base.protocol !== "https:" || base.username || base.password || base.hash || base.search ||
    base.pathname.endsWith("/") || base.href !== baseUrl || typeof request !== "function"
  ) fail("citizen_adoption_acceptance_config_invalid");
  return Object.freeze({
    async resolve({ adoptionEventId, signal }): Promise<unknown> {
      if (typeof adoptionEventId !== "string" || !HEX.test(adoptionEventId)) fail("citizen_adoption_acceptance_invalid");
      signal.throwIfAborted();
      try {
        const response = await request(`${baseUrl}/${adoptionEventId}`, {
          method: "GET", redirect: "error", credentials: "omit", cache: "no-store", signal,
          headers: { accept: "application/json" },
        });
        if (response.status !== 200 || response.redirected) {
          void response.body?.cancel().catch(() => {});
          fail("citizen_adoption_acceptance_unavailable");
        }
        const receipt = exact(await responseJson(response, signal), ACCEPTANCE_KEYS);
        if (receipt.adoptionEventId !== adoptionEventId) fail("citizen_adoption_acceptance_invalid");
        return receipt;
      } catch { fail("citizen_adoption_acceptance_unavailable"); }
    },
  });
}

export function verifyCitizenAdoptionPolicy(input: unknown): CitizenAdoptionEvidencePolicy {
  const policy = snapshot(input) as CitizenAdoptionEvidencePolicy;
  exact(policy, ["municipalityId", "policyVersion", "issuer", "issuerKeyId", "issuerPublicKey", "allowedAgentPubkeys",
    "receiptTtlSeconds", "statusBaseUrl", "statusMaxAgeSeconds", "maxEventClockSkewSeconds"]);
  let statusBase: URL;
  try { statusBase = new URL(policy.statusBaseUrl); } catch { fail("citizen_adoption_policy_invalid"); }
  if (typeof policy.municipalityId !== "string" || !SLUG.test(policy.municipalityId) ||
    typeof policy.policyVersion !== "string" || !POLICY.test(policy.policyVersion) ||
    typeof policy.issuer !== "string" || !policy.issuer || policy.issuer.trim() !== policy.issuer ||
    typeof policy.issuerKeyId !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$/u.test(policy.issuerKeyId) ||
    typeof policy.issuerPublicKey !== "string" || !HEX.test(policy.issuerPublicKey) ||
    !Array.isArray(policy.allowedAgentPubkeys) || !policy.allowedAgentPubkeys.length ||
    policy.allowedAgentPubkeys.some((key) => typeof key !== "string" || !HEX.test(key)) || new Set(policy.allowedAgentPubkeys).size !== policy.allowedAgentPubkeys.length ||
    !integer(policy.receiptTtlSeconds) || policy.receiptTtlSeconds < 60 || policy.receiptTtlSeconds > 3_600 ||
    !integer(policy.statusMaxAgeSeconds) || policy.statusMaxAgeSeconds < 1 || policy.statusMaxAgeSeconds > 300 ||
    !integer(policy.maxEventClockSkewSeconds) || policy.maxEventClockSkewSeconds > 300 ||
    statusBase.protocol !== "https:" || statusBase.username || statusBase.password || statusBase.hash || statusBase.search ||
    statusBase.pathname.endsWith("/") || statusBase.href !== policy.statusBaseUrl
  ) fail("citizen_adoption_policy_invalid");
  return policy;
}

function issuerProof(policy: CitizenAdoptionEvidencePolicy) {
  const key = createPublicKey({ key: Buffer.concat([
    Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(policy.issuerPublicKey, "hex"),
  ]), format: "der", type: "spki" });
  return (value: unknown, message: unknown) => {
    const parsed = exact(value, ["algorithm", "keyId", "signature"]);
    if (parsed.algorithm !== "Ed25519" || parsed.keyId !== policy.issuerKeyId || typeof parsed.signature !== "string" ||
      !/^[A-Za-z0-9_-]{86}$/u.test(parsed.signature)
    ) fail("citizen_adoption_proof_invalid");
    const signature = Buffer.from(parsed.signature, "base64url");
    if (signature.toString("base64url") !== parsed.signature || !verifySignature(null, Buffer.from(canonical(message)), key, signature)) fail("citizen_adoption_proof_invalid");
  };
}

/** Bounded immutable transport snapshot; carries no verification claim. */
export function readCitizenAdoptionBundle(input: unknown): CitizenAdoptionEvidenceBundle {
  const parsed = exact(snapshot(input), BUNDLE_KEYS);
  if (parsed.schemaVersion !== "eligible_citizen_adopted_topic_suggestion_v1") fail("citizen_adoption_bundle_invalid");
  return parsed as CitizenAdoptionEvidenceBundle;
}

function inspectBundle(input: unknown, policy: CitizenAdoptionEvidencePolicy, startedAt: number) {
  const proof = issuerProof(policy);
  const bundle = readCitizenAdoptionBundle(input);
  const source = sources(bundle, policy);
  const receipt = exact(bundle.eligibilityReceipt, RECEIPT_KEYS);
  const core = exact(receipt.eligibilityCore, CORE_KEYS);
  if (!integer(core.issuedAt) || !integer(core.expiresAt) || core.expiresAt - core.issuedAt !== policy.receiptTtlSeconds ||
    core.issuedAt > startedAt || core.expiresAt <= startedAt || core.issuedAt < source.suggestion.created_at
  ) fail("citizen_adoption_receipt_expired");
  same(core, {
    municipalityId: policy.municipalityId, eligibilityClass: "municipal_civic_participation",
    subjectPubkey: source.adoption.pubkey, participantSuggestionId: source.suggestion.id, topicId: source.topicId,
    policyVersion: policy.policyVersion, issuer: policy.issuer, issuedAt: core.issuedAt, expiresAt: core.expiresAt,
    authorityBinding: "civic_eligibility_only",
  });
  const payloadChecksum = digest(core);
  const receiptId = `urn:stadtstack:municipal-civic-eligibility-receipt:${payloadChecksum}`;
  const statusRef = `${policy.statusBaseUrl}/${payloadChecksum}`;
  same({ ...receipt, proof: null }, {
    schemaVersion: "municipal_civic_eligibility_receipt_v1", eligibilityCore: core,
    receiptId, payloadChecksum, statusRef, proof: null,
  });
  proof(receipt.proof, { domain: "municipal-civic-eligibility-receipt/v1",
    schemaVersion: "municipal_civic_eligibility_receipt_v1", receiptId, payloadChecksum, statusRef });
  const adoptionCore = {
    municipalityId: policy.municipalityId, topicId: source.topicId,
    participantSuggestionId: source.suggestion.id, participantSuggestionRef: `nostr://event/${source.suggestion.id}`,
    participantPubkey: source.root.pubkey, sourceDiscussionId: source.root.id,
    sourceAnswerReceiptId: source.draftCore.sourceAnswerReceiptId, adopterPubkey: source.adoption.pubkey,
    eligibilityReceiptId: receiptId, eligibilityReceiptChecksum: payloadChecksum,
    title: source.draftCore.title, summary: source.draftCore.summary,
  };
  const adoptionId = `urn:stadtstack:citizen-topic-suggestion-adoption:${digest(adoptionCore)}`;
  same(content(source.adoption), { schemaVersion: "public_citizen_topic_suggestion_adoption_v1", adoptionId,
    ...adoptionCore, entryState: "case_steward_review_required", authorityBinding: "civic_eligibility_only", submittedToCivicWorkflow: false });
  same(source.adoption.tags, [
    ["schema", "citizen_adopted_topic_suggestion_v1"], ["municipality", policy.municipalityId], ["topic", source.topicId],
    ["e", source.suggestion.id, "", "adopted-suggestion"], ["e", source.root.id, "", "root"], ["p", source.root.pubkey],
    ["eligibility-receipt", receiptId], ["credential-class", "municipal-civic-eligibility"],
  ]);
  return { bundle, source, core, receiptId, payloadChecksum, statusRef, adoptionId, startedAt };
}

type InspectedBundle = ReturnType<typeof inspectBundle>;

function inspectAcceptance(value: unknown, checked: InspectedBundle, policy: CitizenAdoptionEvidencePolicy) {
  const acceptance = exact(snapshot(value), ACCEPTANCE_KEYS);
  const { source, core, receiptId, adoptionId, startedAt } = checked;
  if (!integer(acceptance.receivedAt) || acceptance.receivedAt > startedAt ||
    acceptance.receivedAt < (core.issuedAt as number) || acceptance.receivedAt >= (core.expiresAt as number) ||
    source.adoption.created_at < (core.issuedAt as number) || source.adoption.created_at >= (core.expiresAt as number) ||
    Math.abs(acceptance.receivedAt - source.adoption.created_at) > policy.maxEventClockSkewSeconds
  ) fail("citizen_adoption_acceptance_invalid");
  const acceptanceCore = {
    schemaVersion: "citizen_topic_suggestion_adoption_acceptance_receipt_v1",
    adoptionId, adoptionEventId: source.adoption.id, municipalityId: policy.municipalityId,
    topicId: source.topicId, participantSuggestionId: source.suggestion.id, adopterPubkey: source.adoption.pubkey,
    eligibilityReceiptId: receiptId,
    requestChecksum: digest({ schemaVersion: "citizen_topic_suggestion_adoption_request_v1", adoptionEvent: source.adoption }),
    eventCreatedAt: source.adoption.created_at, receivedAt: acceptance.receivedAt,
    policyVersion: policy.policyVersion, status: "accepted", authorityBinding: "civic_eligibility_only",
  };
  same(acceptance, { ...acceptanceCore, receiptChecksum: digest(acceptanceCore) });
  return acceptance;
}

function inspectStatus(value: unknown, checked: InspectedBundle, policy: CitizenAdoptionEvidencePolicy, requestedAt: number, verifiedAt: number, requestNonce: string) {
  const status = exact(snapshot(value), ["statusCore", "statusChecksum", "proof"]);
  const { core, receiptId, payloadChecksum, startedAt } = checked;
  const proof = issuerProof(policy);
  const observed = exact(status.statusCore, ["schemaVersion", "receiptId", "payloadChecksum", "policyVersion", "state", "effectiveAt", "observedAt", "audience", "requestNonce"]);
  if (verifiedAt < requestedAt || requestedAt < startedAt || verifiedAt >= (core.expiresAt as number) ||
    !integer(observed.observedAt) || !integer(observed.effectiveAt) ||
    observed.observedAt < requestedAt || observed.observedAt > verifiedAt ||
    observed.effectiveAt > observed.observedAt || observed.effectiveAt < (core.issuedAt as number) ||
    verifiedAt - observed.observedAt >= policy.statusMaxAgeSeconds
  ) fail("citizen_adoption_status_stale");
  same(observed, { schemaVersion: "municipal_civic_eligibility_status_v1", receiptId, payloadChecksum,
    policyVersion: policy.policyVersion, state: "active", effectiveAt: observed.effectiveAt, observedAt: observed.observedAt,
    audience: "stadtstack-case-steward-admission", requestNonce });
  if (status.statusChecksum !== digest(observed)) fail("citizen_adoption_status_invalid");
  proof(status.proof, { domain: "municipal-civic-eligibility-status/v1",
    schemaVersion: "municipal_civic_eligibility_status_v1", statusChecksum: status.statusChecksum });
  return { status, validUntil: Math.min(core.expiresAt as number, (observed.observedAt as number) + policy.statusMaxAgeSeconds) };
}

/** Replays recorded cryptographic evidence at its original verification time.
 * This is not a ledger lookup or a fresh-status capability. Only the writer's
 * configured verifier may supply evidence for a new admission. */
export function verifyRecordedCitizenAdoptionEvidence(input: unknown, policyInput: CitizenAdoptionEvidencePolicy): VerifiedCitizenAdoptionEvidence {
  const parsed = exact(snapshot(input), ["schemaVersion", "bundle", "adoptionAcceptance", "eligibilityStatus", "verifiedAt", "validUntil", "authorityBinding"]);
  if (parsed.schemaVersion !== "verified_citizen_adoption_evidence_v1" || parsed.authorityBinding !== "none" ||
    !integer(parsed.verifiedAt) || !integer(parsed.validUntil)) fail("citizen_adoption_record_invalid");
  const policy = verifyCitizenAdoptionPolicy(policyInput);
  const checked = inspectBundle(parsed.bundle, policy, parsed.verifiedAt);
  const adoptionAcceptance = inspectAcceptance(parsed.adoptionAcceptance, checked, policy);
  const observed = object(object(parsed.eligibilityStatus).statusCore);
  if (!integer(observed.observedAt) || observed.observedAt < (adoptionAcceptance.receivedAt as number) || typeof observed.requestNonce !== "string" || !HEX.test(observed.requestNonce)) fail("citizen_adoption_record_invalid");
  // A persisted observation precedes verification; the original network
  // verifier already checked it against its own randomly generated nonce.
  const { status, validUntil } = inspectStatus(parsed.eligibilityStatus,
    { ...checked, startedAt: observed.observedAt }, policy, observed.observedAt, parsed.verifiedAt, observed.requestNonce);
  if (validUntil !== parsed.validUntil) fail("citizen_adoption_record_invalid");
  return Object.freeze({ schemaVersion: "verified_citizen_adoption_evidence_v1", bundle: checked.bundle,
    adoptionAcceptance, eligibilityStatus: status, verifiedAt: parsed.verifiedAt, validUntil, authorityBinding: "none" });
}

export type CitizenAdoptionVerificationDependencies = Readonly<{
  policy: CitizenAdoptionEvidencePolicy;
  acceptance: CitizenAdoptionAcceptanceReader;
  fetch?: typeof fetch;
  now?: () => Date;
  timeoutMs?: number;
}>;

export function createCitizenAdoptionEvidenceVerifier(dependencies: CitizenAdoptionVerificationDependencies): Readonly<{ verify(bundle: unknown): Promise<VerifiedCitizenAdoptionEvidence> }> {
  const policy = verifyCitizenAdoptionPolicy(dependencies.policy);
  const timeoutMs = dependencies.timeoutMs ?? 10_000;
  if (!integer(timeoutMs) || timeoutMs < 1 || timeoutMs > 10_000 ||
    typeof dependencies.acceptance?.resolve !== "function" || typeof (dependencies.fetch ?? globalThis.fetch) !== "function" ||
    (dependencies.now !== undefined && typeof dependencies.now !== "function")) fail("citizen_adoption_policy_invalid");
  const request = dependencies.fetch ?? globalThis.fetch;
  const readAcceptance = dependencies.acceptance.resolve.bind(dependencies.acceptance);
  const now = dependencies.now ?? (() => new Date());
  const timestamp = () => {
    const value = Math.floor(now().getTime() / 1_000);
    if (!integer(value)) fail("citizen_adoption_time_invalid");
    return value;
  };
  const inspect = async (input: unknown, signal: AbortSignal, checkBudget: () => void): Promise<VerifiedCitizenAdoptionEvidence> => {
    const startedAt = timestamp();
    const checked = inspectBundle(input, policy, startedAt);
    checkBudget();
    let resolved: unknown;
    try { resolved = await readAcceptance({ adoptionEventId: checked.source.adoption.id, signal }); }
    catch { fail("citizen_adoption_acceptance_unavailable"); }
    checkBudget();
    let acceptance: Record<string, unknown>;
    try { acceptance = exact(snapshot(resolved), ACCEPTANCE_KEYS); }
    catch { fail("citizen_adoption_acceptance_unavailable"); }
    acceptance = inspectAcceptance(acceptance, checked, policy);
    const requestNonce = randomBytes(32).toString("hex");
    const requestedAt = timestamp();
    if (requestedAt < startedAt || requestedAt >= (checked.core.expiresAt as number)) fail("citizen_adoption_receipt_expired");
    let resolvedStatus: unknown;
    try {
      resolvedStatus = await responseJson(await request(checked.statusRef, {
        method: "GET", redirect: "error", credentials: "omit", cache: "no-store", signal,
        headers: { accept: "application/json", "x-stadtstack-status-nonce": requestNonce },
      }), signal);
      exact(resolvedStatus, ["statusCore", "statusChecksum", "proof"]);
    } catch { fail("citizen_adoption_status_unavailable"); }
    checkBudget();
    const verifiedAt = timestamp();
    const { status, validUntil } = inspectStatus(resolvedStatus, checked, policy, requestedAt, verifiedAt, requestNonce);
    checkBudget();
    return Object.freeze({ schemaVersion: "verified_citizen_adoption_evidence_v1", bundle: checked.bundle,
      adoptionAcceptance: acceptance, eligibilityStatus: status, verifiedAt, validUntil, authorityBinding: "none" });
  };

  return Object.freeze({
    async verify(bundle: unknown): Promise<VerifiedCitizenAdoptionEvidence> {
      const controller = new AbortController();
      const deadline = performance.now() + timeoutMs;
      const checkBudget = () => {
        if (controller.signal.aborted || performance.now() >= deadline) fail("citizen_adoption_verification_timeout");
      };
      let timer: ReturnType<typeof setTimeout> | undefined;
      try {
        return await Promise.race([
          new Promise<never>((_, reject) => {
            timer = setTimeout(() => {
              controller.abort();
              reject(new Error("citizen_adoption_verification_timeout"));
            }, timeoutMs);
          }),
          inspect(bundle, controller.signal, checkBudget),
        ]);
      } finally { if (timer) clearTimeout(timer); controller.abort(); }
    },
  });
}

/** A separate staging protocol. It never produces municipal eligibility. */
export type SyntheticAdoptionEvidencePolicy = Readonly<{
  municipalityId: string;
  policyVersion: string;
  allowedAgentPubkeys: readonly string[];
  testCitizenNftContract: string;
  challengeTtlSeconds: 300;
  maxEventClockSkewSeconds: number;
  environment: "staging";
  testOnly: true;
}>;
export type SyntheticAdoptionEvidenceBundle = Readonly<{
  schemaVersion: "synthetic_citizen_adoption_case_input_v1";
  sourceDiscussion: NostrEvent;
  sourceAnswer: NostrEvent;
  participantSuggestionEvent: NostrEvent;
  proofEvent: NostrEvent;
}>;
export type SyntheticAdoptionAcceptanceReader = Readonly<{
  resolve(input: Readonly<{ participantSuggestionId: string; adopterPubkey: string; signal: AbortSignal }>): Promise<unknown>;
}>;
export type VerifiedSyntheticAdoptionEvidence = Readonly<{
  schemaVersion: "verified_synthetic_adoption_evidence_v1";
  bundle: SyntheticAdoptionEvidenceBundle;
  projection: Readonly<Record<string, unknown>>;
  verifiedAt: number;
  environment: "staging";
  testOnly: true;
  authorityBinding: "none";
}>;
export type SyntheticAdoptionVerificationDependencies = Readonly<{
  policy: SyntheticAdoptionEvidencePolicy;
  acceptance: SyntheticAdoptionAcceptanceReader;
  now?: () => Date;
  timeoutMs?: number;
}>;

export function verifySyntheticAdoptionPolicy(input: unknown): SyntheticAdoptionEvidencePolicy {
  const policy = exact(snapshot(input), ["municipalityId", "policyVersion", "allowedAgentPubkeys",
    "testCitizenNftContract", "challengeTtlSeconds", "maxEventClockSkewSeconds", "environment", "testOnly"]);
  if (policy.environment !== "staging" || policy.testOnly !== true || policy.challengeTtlSeconds !== 300 ||
    typeof policy.municipalityId !== "string" || !SLUG.test(policy.municipalityId) ||
    typeof policy.policyVersion !== "string" || !POLICY.test(policy.policyVersion) ||
    typeof policy.testCitizenNftContract !== "string" || !/^0x[0-9a-f]{40}$/u.test(policy.testCitizenNftContract) ||
    policy.testCitizenNftContract === `0x${"0".repeat(40)}` ||
    !integer(policy.maxEventClockSkewSeconds) || policy.maxEventClockSkewSeconds > 300 ||
    !Array.isArray(policy.allowedAgentPubkeys) || !policy.allowedAgentPubkeys.length ||
    policy.allowedAgentPubkeys.some((key) => typeof key !== "string" || !HEX.test(key)) ||
    new Set(policy.allowedAgentPubkeys).size !== policy.allowedAgentPubkeys.length) fail("synthetic_adoption_policy_invalid");
  return policy as SyntheticAdoptionEvidencePolicy;
}

export function readSyntheticAdoptionBundle(input: unknown): SyntheticAdoptionEvidenceBundle {
  const parsed = exact(snapshot(input), ["schemaVersion", "sourceDiscussion", "sourceAnswer", "participantSuggestionEvent", "proofEvent"]);
  if (parsed.schemaVersion !== "synthetic_citizen_adoption_case_input_v1") fail("synthetic_adoption_bundle_invalid");
  return parsed as SyntheticAdoptionEvidenceBundle;
}

function inspectSyntheticBundle(input: unknown, policy: SyntheticAdoptionEvidencePolicy) {
  const bundle = readSyntheticAdoptionBundle(input);
  // Share only signature/source provenance checks with municipal adoption.
  // The fourth event is a test challenge, never an eligibility adoption.
  const source = sources({ ...bundle, adoptionEvent: bundle.proofEvent }, policy);
  const challenge = content(bundle.proofEvent);
  if (!integer(challenge.issuedAt) || !integer(challenge.expiresAt) ||
    challenge.expiresAt - challenge.issuedAt !== policy.challengeTtlSeconds ||
    challenge.issuedAt < source.suggestion.created_at || source.adoption.created_at < challenge.issuedAt ||
    source.adoption.created_at >= challenge.expiresAt || typeof challenge.challengeId !== "string" ||
    !/^[0-9a-f]{32}$/u.test(challenge.challengeId)) fail("synthetic_adoption_challenge_invalid");
  same(challenge, { schemaVersion: "staging_test_citizen_pass_v1",
    audience: "roebel-staging-synthetic-citizen-adoption", authorityBinding: "none", chainId: 100,
    challengeId: challenge.challengeId, environment: "staging", expiresAt: challenge.expiresAt, issuedAt: challenge.issuedAt,
    municipalityId: policy.municipalityId, participantSuggestionId: source.suggestion.id,
    policyVersion: policy.policyVersion, subjectPubkey: source.adoption.pubkey,
    testCitizenNftContract: policy.testCitizenNftContract, testOnly: true, topicId: source.topicId });
  same(source.adoption.tags, [["schema", "staging_test_citizen_pass_proof_v1"], ["challenge", challenge.challengeId],
    ["e", source.suggestion.id, "", "synthetic-adoption-test"], ["municipality", policy.municipalityId], ["test-only", "true"]]);
  const tracerCore = {
    municipalityId: policy.municipalityId, topicId: source.topicId, participantSuggestionId: source.suggestion.id,
    participantSuggestionRef: `nostr://event/${source.suggestion.id}`, participantPubkey: source.root.pubkey,
    sourceDiscussionId: source.root.id, sourceAnswerReceiptId: source.draftCore.sourceAnswerReceiptId,
    adopterPubkey: source.adoption.pubkey, proofEventId: source.adoption.id,
    title: source.draftCore.title, summary: source.draftCore.summary,
  };
  const tracer = { schemaVersion: "synthetic_citizen_adoption_tracer_v1",
    tracerId: `urn:stadtstack:synthetic-citizen-adoption-tracer:${digest(tracerCore)}`, ...tracerCore,
    entryState: "synthetic_journey_preview_only", environment: "staging", testOnly: true,
    authorityBinding: "none", submittedToCivicWorkflow: false };
  return { bundle, source, challenge, tracer };
}

function inspectSyntheticProjection(input: unknown, checked: ReturnType<typeof inspectSyntheticBundle>,
  policy: SyntheticAdoptionEvidencePolicy, verifiedAt: number) {
  const projection = object(snapshot(input));
  const acceptance = object(projection.acceptanceReceipt);
  const { source, challenge, tracer } = checked;
  if (!integer(verifiedAt) || !integer(acceptance.receivedAt) || acceptance.receivedAt > verifiedAt ||
    acceptance.receivedAt < (challenge.issuedAt as number) || acceptance.receivedAt >= (challenge.expiresAt as number) ||
    Math.abs(acceptance.receivedAt - source.adoption.created_at) > policy.maxEventClockSkewSeconds ||
    typeof acceptance.requestChecksum !== "string" || !HEX.test(acceptance.requestChecksum)) fail("synthetic_adoption_acceptance_invalid");
  // The request checksum covers private wallet/session transport, which stays
  // at the ledger. It is opaque here, not reconstructed or treated as a proof.
  const core = { schemaVersion: "synthetic_citizen_adoption_tracer_acceptance_v1", tracerId: tracer.tracerId,
    proofEventId: source.adoption.id, municipalityId: policy.municipalityId, topicId: source.topicId,
    participantSuggestionId: source.suggestion.id, adopterPubkey: source.adoption.pubkey,
    requestChecksum: acceptance.requestChecksum, eventCreatedAt: source.adoption.created_at, receivedAt: acceptance.receivedAt,
    policyVersion: policy.policyVersion, status: "accepted_for_synthetic_preview", environment: "staging", testOnly: true, authorityBinding: "none" };
  same(projection, { schemaVersion: "public_synthetic_citizen_adoption_projection_v1",
    participantSuggestionId: source.suggestion.id, proofEvent: source.adoption, tracer,
    acceptanceReceipt: { ...core, receiptChecksum: digest(core) },
    labels: { citizenship: "Test-Bürger-Pass – keine reale Bürgerberechtigung",
      civicWorkflow: "Nur synthetische Vorschau – kein CivicCase und keine Verwaltungsbefürwortung",
      governance: "Keine bindende Abstimmung, kein Beschluss, keine Treasury-Wirkung und keine Zahlung" },
    entryState: "synthetic_journey_preview_only", environment: "staging", testOnly: true, authorityBinding: "none",
    submittedToCivicWorkflow: false, civicCaseCreated: false, administrativeEndorsement: false,
    bindingVote: false, councilDecision: false, treasuryEffect: false, paymentEffect: false });
  return projection;
}

/** Replay validates the saved test protocol, not fresh eligibility or admission authority. */
export function verifyRecordedSyntheticAdoptionEvidence(input: unknown, policyInput: SyntheticAdoptionEvidencePolicy): VerifiedSyntheticAdoptionEvidence {
  const parsed = exact(snapshot(input), ["schemaVersion", "bundle", "projection", "verifiedAt", "environment", "testOnly", "authorityBinding"]);
  if (parsed.schemaVersion !== "verified_synthetic_adoption_evidence_v1" || parsed.environment !== "staging" ||
    parsed.testOnly !== true || parsed.authorityBinding !== "none" || !integer(parsed.verifiedAt)) fail("synthetic_adoption_record_invalid");
  const policy = verifySyntheticAdoptionPolicy(policyInput);
  const checked = inspectSyntheticBundle(parsed.bundle, policy);
  const projection = inspectSyntheticProjection(parsed.projection, checked, policy, parsed.verifiedAt);
  return Object.freeze({ schemaVersion: "verified_synthetic_adoption_evidence_v1", bundle: checked.bundle,
    projection, verifiedAt: parsed.verifiedAt, environment: "staging", testOnly: true, authorityBinding: "none" });
}

/** The ledger reader is deployment-owned; HTTP callers supply only signed events. */
export function createSyntheticAdoptionEvidenceVerifier(dependencies: SyntheticAdoptionVerificationDependencies) {
  const policy = verifySyntheticAdoptionPolicy(dependencies.policy);
  const timeoutMs = dependencies.timeoutMs ?? 10_000;
  if (!integer(timeoutMs) || timeoutMs < 1 || timeoutMs > 10_000 || typeof dependencies.acceptance?.resolve !== "function" ||
    (dependencies.now !== undefined && typeof dependencies.now !== "function")) fail("synthetic_adoption_policy_invalid");
  const resolve = dependencies.acceptance.resolve.bind(dependencies.acceptance);
  const now = dependencies.now ?? (() => new Date());
  return Object.freeze({ async verify(input: unknown): Promise<VerifiedSyntheticAdoptionEvidence> {
    const startedAt = Math.floor(now().getTime() / 1_000);
    if (!integer(startedAt)) fail("synthetic_adoption_time_invalid");
    const deadline = performance.now() + timeoutMs;
    const checked = inspectSyntheticBundle(input, policy);
    if (performance.now() >= deadline) fail("synthetic_adoption_verification_timeout");
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      const projection = await Promise.race([
        new Promise<never>((_, reject) => { timer = setTimeout(() => {
          controller.abort(); reject(new Error("synthetic_adoption_verification_timeout"));
        }, Math.max(0, deadline - performance.now())); }),
        resolve({ participantSuggestionId: checked.source.suggestion.id, adopterPubkey: checked.source.adoption.pubkey, signal: controller.signal }),
      ]);
      const verifiedAt = Math.floor(now().getTime() / 1_000);
      if (performance.now() >= deadline) fail("synthetic_adoption_verification_timeout");
      if (!integer(verifiedAt) || verifiedAt < startedAt) fail("synthetic_adoption_time_invalid");
      const inspected = inspectSyntheticProjection(projection, checked, policy, verifiedAt);
      if (performance.now() >= deadline) fail("synthetic_adoption_verification_timeout");
      return Object.freeze({ schemaVersion: "verified_synthetic_adoption_evidence_v1", bundle: checked.bundle,
        projection: inspected, verifiedAt,
        environment: "staging", testOnly: true, authorityBinding: "none" });
    } finally { if (timer) clearTimeout(timer); controller.abort(); }
  } });
}

export function createSyntheticAdoptionAcceptanceReader(config: Readonly<{ baseUrl: string; fetch?: typeof fetch }>): SyntheticAdoptionAcceptanceReader {
  const baseUrl = config.baseUrl;
  let base: URL;
  try { base = new URL(baseUrl); } catch { fail("synthetic_adoption_acceptance_config_invalid"); }
  const request = config.fetch ?? globalThis.fetch;
  if (typeof baseUrl !== "string" || baseUrl.length > 2_048 || base.protocol !== "https:" || base.username || base.password ||
    base.hash || base.search || base.pathname.endsWith("/") || base.href !== baseUrl || typeof request !== "function") fail("synthetic_adoption_acceptance_config_invalid");
  return Object.freeze({ async resolve({ participantSuggestionId, adopterPubkey, signal }) {
    if (typeof participantSuggestionId !== "string" || typeof adopterPubkey !== "string" || !HEX.test(participantSuggestionId) || !HEX.test(adopterPubkey)) fail("synthetic_adoption_acceptance_invalid");
    signal.throwIfAborted();
    try {
      const response = await request(`${baseUrl}/${participantSuggestionId}/adopter/${adopterPubkey}`, {
        method: "GET", redirect: "error", credentials: "omit", cache: "no-store", signal, headers: { accept: "application/json" },
      });
      if (response.status !== 200 || response.redirected) {
        void response.body?.cancel().catch(() => {}); fail("synthetic_adoption_acceptance_unavailable");
      }
      const projection = object(await responseJson(response, signal));
      if (projection.participantSuggestionId !== participantSuggestionId || object(projection.tracer).adopterPubkey !== adopterPubkey) fail("synthetic_adoption_acceptance_invalid");
      return projection;
    } catch { fail("synthetic_adoption_acceptance_unavailable"); }
  } });
}
