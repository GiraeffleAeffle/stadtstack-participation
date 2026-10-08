import test from "node:test";
import assert from "node:assert/strict";
import { createHash, createHmac } from "node:crypto";
import { getPublicKey } from "nostr-tools/pure";
import { ed25519 } from "@noble/curves/ed25519.js";
import { EudiPidAdapter, migrate, type EudiPidConfig, type EudiPidRuntime, type EudiRequest } from "../../src/adapters/eudi-pid.ts";
import { createEudiHttpHandlers } from "../../src/adapters/eudi-http.ts";
import { canonical, object } from "../../src/shared/canonical.ts";
import { openDatabase } from "../../src/shared/db.ts";
import { nip98Header, nip98Template } from "../../src/shared/nostr.ts";
import type { EligibilityBasis, EligibilityCheckInput } from "../../src/shared/seams.ts";
import { parseIssuerPolicy } from "../../src/issuer/policy.ts";
import { IssuerStore } from "../../src/issuer/store.ts";
import { IssuerService } from "../../src/issuer/service.ts";
import { createHttpHandler } from "../../src/http.ts";
import { adopterKey, agentKey, authenticatedRequest, issuerKey, policyInput, signed, subject } from "../issuer/fixtures.ts";

const now = 1_791_417_600; // 2026-10-08T00:00:00Z
const config: EudiPidConfig = { kind: "eudi_pid_v1", verifierBaseUrl: "https://verifier-backend.eudiw.dev",
  acceptedVcts: ["urn:eudi:pid:1", "urn:eudi:pid:de:1"], acceptedAddresses: [{ postalCode: "15344", locality: "Strausberg" }],
  transactionTtlSeconds: 300, validitySeconds: 3600 };
const basis: EligibilityBasis = { residence: "main_residence", minimumAgeYears: 16, nationality: "any", localityScope: null };
const uniquenessKey = new Uint8Array(32).fill(98);
const municipalityId = "strausberg";
const policyVersion = "pilot-1";
const signal = new AbortController().signal;
type PresentationOptions = { claims?: Record<string, unknown>; payload?: Record<string, unknown>; binding?: Record<string, unknown>; holder?: number; nested?: boolean; unreferenced?: boolean };

function encode(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

function presentation(nonce: string, options: PresentationOptions = {}): string {
  const claims: Record<string, unknown> = { family_name: "Müller", given_name: "Anna Maria", birthdate: "1990-03-01",
    address: { postal_code: "15344", locality: "Strausberg" }, ...options.claims };
  const disclosures: string[] = [];
  const hashes: string[] = [];
  if (options.nested) {
    const nestedHashes: string[] = [];
    for (const [name, value] of Object.entries(object(claims.address))) {
      const disclosure = encode([`salt-${name}`, name, value]);
      disclosures.push(disclosure);
      nestedHashes.push(createHash("sha256").update(disclosure).digest("base64url"));
    }
    claims.address = { _sd: nestedHashes };
  }
  for (const [name, value] of Object.entries(claims)) {
    if (value === undefined) continue;
    const disclosure = encode([`salt-${name}`, name, value]);
    disclosures.push(disclosure);
    if (!options.unreferenced) hashes.push(createHash("sha256").update(disclosure).digest("base64url"));
  }
  const publicKey = ed25519.getPublicKey(new Uint8Array(32).fill(options.holder ?? 1));
  const payload = { vct: "urn:eudi:pid:1", iss: "https://test-pid.example", exp: now + 7200,
    cnf: { jwk: { kty: "OKP", crv: "Ed25519", x: Buffer.from(publicKey).toString("base64url") } },
    _sd_alg: "sha-256", _sd: hashes, ...options.payload };
  const issuerJwt = `${encode({ alg: "EdDSA", typ: "dc+sd-jwt" })}.${encode(payload)}.synthetic`;
  const sdJwt = `${issuerJwt}~${disclosures.join("~")}~`;
  const binding = { nonce, aud: "test-verifier", iat: now, sd_hash: createHash("sha256").update(sdJwt).digest("base64url"), ...options.binding };
  return `${sdJwt}${encode({ typ: "kb+jwt", alg: "EdDSA" })}.${encode(binding)}.synthetic`;
}

function setup(options: { config?: EudiPidConfig; basis?: EligibilityBasis; timeoutMs?: number } = {}) {
  const db = openDatabase(":memory:");
  const transactions = new Map<string, string>();
  const requests: Record<string, unknown>[] = [];
  let sequence = 0;
  let nextPresentation: PresentationOptions = {};
  let pollMode: "ready" | "pending" | "empty-pending" | "error" | "rejected" | "missing" | "timeout" | "mismatch" = "ready";
  let initFailure = false;
  const fetcher: typeof fetch = async (url, init) => {
    assert.equal(init?.redirect, "error");
    assert.equal(init?.credentials, "omit");
    const path = new URL(String(url)).pathname;
    if (path === "/ui/presentations") {
      if (initFailure) return new Response("{}", { status: 503 });
      const body = object(JSON.parse(String(init?.body)));
      requests.push(body);
      assert.ok(typeof body.nonce === "string");
      const id = `transaction-${++sequence}`;
      transactions.set(id, body.nonce);
      return Response.json({ transaction_id: id, client_id: "test-verifier", request_uri: `https://verifier-backend.eudiw.dev/wallet/request.jwt/${id}` });
    }
    const transactionId = path.split("/").at(-1)!;
    const nonce = transactions.get(transactionId)!;
    if (pollMode === "pending") return Response.json({ error: "PresentationNotSubmitted" }, { status: 400 });
    if (pollMode === "empty-pending") return new Response(null, { status: 400 });
    if (pollMode === "error") return Response.json({}, { status: 503 });
    if (pollMode === "rejected") return Response.json({ error: "InvalidResponseCode" }, { status: 400 });
    if (pollMode === "missing") return Response.json({}, { status: 404 });
    if (pollMode === "timeout") throw new DOMException("Verifier deadline elapsed", "TimeoutError");
    return Response.json({ ...(pollMode === "mismatch" ? { transaction_id: "other-transaction" } : {}), vp_token: { pid: [presentation(nonce, nextPresentation)] } });
  };
  const runtime: EudiPidRuntime = { db, municipalityId, policyVersion, basis: options.basis ?? basis, uniquenessKey, fetch: fetcher, timeoutMs: options.timeoutMs ?? 1000 };
  const adapter = new EudiPidAdapter(options.config ?? config, runtime);
  const checkInput: EligibilityCheckInput = { municipalityId, policyVersion, subjectPubkey: subject,
    purpose: { kind: "commitment_enrollment", commitment: `0x${"01".repeat(32)}` }, requestId: "ab".repeat(32), evidence: {}, now, signal };
  return { db, adapter, runtime, requests, checkInput,
    setPresentation(value: PresentationOptions) { nextPresentation = value; },
    setPollMode(value: typeof pollMode) { pollMode = value; },
    failInit() { initFailure = true; },
    async ready(subjectPubkey = subject): Promise<EudiRequest> {
      const request = await adapter.start(subjectPubkey, now, signal);
      assert.deepEqual(await adapter.poll(request.transactionId, subjectPubkey, now, signal), { state: "ready" });
      return request;
    },
  };
}

test("Strausberg PID is active; uniqueness is stable across rotating holder keys and persistent restarts", async (t) => {
  const f = setup(); t.after(() => f.db.close());
  const first = await f.ready();
  const decision = await f.adapter.check({ ...f.checkInput, evidence: { transactionId: first.transactionId } });
  assert.equal(decision.state, "active");
  if (decision.state !== "active") return;
  const expected = createHmac("sha256", uniquenessKey).update(`stadtstack-participation/eudi-person/v1/strausberg:${canonical({ familyName: "müller", givenName: "anna maria", birthdate: "1990-03-01" })}`).digest("hex");
  assert.equal(decision.evidenceRef, expected);
  f.setPresentation({ holder: 2, nested: true, payload: { vct: "urn:eudi:pid:de:1" } });
  const second = await f.ready();
  const repeated = await f.adapter.check({ ...f.checkInput, evidence: { transactionId: second.transactionId } });
  assert.equal(repeated.state, "active");
  if (repeated.state === "active") assert.equal(repeated.evidenceRef, decision.evidenceRef);
  const restarted = new EudiPidAdapter(config, f.runtime);
  migrate(f.db);
  assert.deepEqual(await restarted.recheck({ ...f.checkInput, evidenceRef: expected }), decision);
  assert.deepEqual(await restarted.recheck({ ...f.checkInput, evidenceRef: expected, now: now + 3600 }), { state: "inactive", reason: "evidence_expired" });
  const stored = JSON.stringify(f.db.prepare("SELECT * FROM eudi_transactions").all()) + JSON.stringify(f.db.prepare("SELECT * FROM eudi_decisions").all());
  for (const privateValue of ["Müller", "Anna", "1990-03-01", "15344", "Strausberg", "vp_token", "cnf", "jwk"]) assert.equal(stored.includes(privateValue), false);
  assert.equal(f.requests[0]!.nonce === f.requests[1]!.nonce, false);
});

test("names normalize NFC, case and whitespace, while different people produce different references", async (t) => {
  const f = setup(); t.after(() => f.db.close());
  const references: string[] = [];
  for (const claims of [{}, { family_name: "  MU\u0308LLER  ", given_name: " ANNA\t  MARIA\n", address: { postal_code: " 15344 ", locality: " STRAUSBERG " } }, { given_name: "Else" }]) {
    f.setPresentation({ claims });
    const request = await f.ready();
    const decision = await f.adapter.check({ ...f.checkInput, evidence: { transactionId: request.transactionId } });
    assert.equal(decision.state, "active");
    if (decision.state === "active") references.push(decision.evidenceRef);
  }
  assert.equal(references[0], references[1]);
  assert.notEqual(references[0], references[2]);
});

test("DCQL requests exactly five necessary person/residence claims", async (t) => {
  const f = setup(); t.after(() => f.db.close());
  const request = await f.adapter.start(subject, now, signal);
  assert.equal(request.expiresAt, now + 300);
  const wallet = new URL(request.walletUrl);
  assert.equal(wallet.protocol, "eudi-openid4vp:");
  assert.equal(wallet.searchParams.get("client_id"), "test-verifier");
  assert.deepEqual(f.requests[0]!.dcql_query, { credentials: [{ id: "pid", format: "dc+sd-jwt", meta: { vct_values: config.acceptedVcts },
    claims: [{ path: ["family_name"] }, { path: ["given_name"] }, { path: ["birthdate"] }, { path: ["address", "postal_code"] }, { path: ["address", "locality"] }] }] });
});

const rejectedPresentations: readonly [string, PresentationOptions, string][] = [
  ["outside address", { claims: { address: { postal_code: "10115", locality: "Berlin" } } }, "address_not_accepted"],
  ["missing postal code", { claims: { address: { locality: "Strausberg" } } }, "address_claim_missing"],
  ["missing address", { claims: { address: undefined } }, "address_claim_missing"],
  ["under age", { claims: { birthdate: "2011-01-01" } }, "under_minimum_age"],
  ["birthday tomorrow", { claims: { birthdate: "2010-10-09" } }, "under_minimum_age"],
  ["invalid calendar date", { claims: { birthdate: "2000-02-30" } }, "age_claim_invalid"],
  ["non-ISO birthdate", { claims: { birthdate: "1.3.1990" } }, "age_claim_invalid"],
  ["future birthdate", { claims: { birthdate: "2027-01-01" } }, "age_claim_invalid"],
  ["missing birthdate", { claims: { birthdate: undefined } }, "birthdate_claim_missing"],
  ["missing given name", { claims: { given_name: undefined } }, "name_claim_missing"],
  ["missing family name", { claims: { family_name: undefined } }, "name_claim_missing"],
  ["blank name", { claims: { given_name: "  \t" } }, "name_claim_missing"],
  ["missing cnf", { payload: { cnf: undefined } }, "holder_binding_missing"],
  ["missing holder jwk", { payload: { cnf: {} } }, "holder_binding_missing"],
  ["malformed holder jwk", { payload: { cnf: { jwk: { kty: "OKP", crv: "Ed25519", x: "invalid" } } } }, "holder_binding_invalid"],
  ["wrong vct", { payload: { vct: "urn:other:credential" } }, "credential_type_invalid"],
  ["expired credential", { payload: { exp: now } }, "credential_expired"],
  ["wrong nonce", { binding: { nonce: "other-request" } }, "presentation_binding_invalid"],
  ["wrong audience", { binding: { aud: "other-verifier" } }, "presentation_binding_invalid"],
  ["wrong SD digest", { binding: { sd_hash: "substituted" } }, "presentation_binding_invalid"],
  ["future binding", { binding: { iat: now + 1 } }, "presentation_binding_invalid"],
  ["unreferenced disclosures", { unreferenced: true }, "address_claim_missing"],
];
for (const [name, options, reason] of rejectedPresentations) {
  test(`rejects ${name} without persisting claims`, async (t) => {
    const f = setup(); t.after(() => f.db.close());
    f.setPresentation(options);
    const request = await f.adapter.start(subject, now, signal);
    assert.deepEqual(await f.adapter.poll(request.transactionId, subject, now, signal), { state: "failed", reason });
    assert.deepEqual(await f.adapter.check({ ...f.checkInput, evidence: { transactionId: request.transactionId } }), { state: "inactive", reason });
    assert.equal(f.db.prepare("SELECT * FROM eudi_decisions").all().length, 0);
  });
}

test("birthdate age boundary and credential expiry cap enrollment validity", async (t) => {
  const f = setup(); t.after(() => f.db.close());
  f.setPresentation({ claims: { birthdate: "2010-10-08" }, payload: { exp: now + 30 } });
  const request = await f.ready();
  const decision = await f.adapter.check({ ...f.checkInput, evidence: { transactionId: request.transactionId } });
  assert.equal(decision.state, "active");
  if (decision.state !== "active") return;
  assert.equal(decision.validUntil, now + 30);
  assert.deepEqual(await f.adapter.recheck({ ...f.checkInput, evidenceRef: decision.evidenceRef, now: now + 29 }), decision);
  assert.deepEqual(await f.adapter.recheck({ ...f.checkInput, evidenceRef: decision.evidenceRef, now: now + 30 }), { state: "inactive", reason: "evidence_expired" });
});

test("transaction subject binding, half-open TTL, single consumption and policy isolation", async (t) => {
  const f = setup(); t.after(() => f.db.close());
  const request = await f.ready();
  const other = getPublicKey(agentKey);
  await assert.rejects(f.adapter.poll(request.transactionId, other, now, signal), { code: "eudi_transaction_not_found", status: 404 });
  assert.deepEqual(await f.adapter.check({ ...f.checkInput, subjectPubkey: other, evidence: { transactionId: request.transactionId } }), { state: "inactive", reason: "eudi_transaction_not_found" });
  assert.deepEqual(await f.adapter.check({ ...f.checkInput, policyVersion: "other-policy", evidence: { transactionId: request.transactionId } }), { state: "inactive", reason: "policy_mismatch" });
  const input = { ...f.checkInput, evidence: { transactionId: request.transactionId } };
  const outcomes = await Promise.all([f.adapter.check(input), f.adapter.check(input)]);
  assert.equal(outcomes.filter((decision) => decision.state === "active").length, 1);
  assert.deepEqual(outcomes[1], { state: "inactive", reason: "transaction_used" });
  assert.deepEqual(await f.adapter.check({ ...f.checkInput, evidence: { transactionId: request.transactionId, extra: true } }), { state: "inactive", reason: "eudi_evidence_invalid" });
  assert.deepEqual(await f.adapter.poll(request.transactionId, subject, request.expiresAt, signal), { state: "expired" });
  assert.deepEqual(await f.adapter.check({ ...f.checkInput, now: request.expiresAt, evidence: { transactionId: request.transactionId } }), { state: "inactive", reason: "transaction_expired" });
});

test("a late verifier response cannot revive an expired pending transaction", async (t) => {
  const f = setup(); t.after(() => f.db.close());
  let release!: () => void;
  let entered!: () => void;
  const held = new Promise<void>((resolve) => { release = resolve; });
  const reached = new Promise<void>((resolve) => { entered = resolve; });
  const adapter = new EudiPidAdapter(config, { ...f.runtime, fetch: async (url, init) => {
    const response = await f.runtime.fetch!(url, init);
    if (new URL(String(url)).pathname !== "/ui/presentations") {
      entered();
      await held;
    }
    return response;
  } });
  const request = await adapter.start(subject, now, signal);
  const late = adapter.poll(request.transactionId, subject, now, signal);
  await reached;
  assert.deepEqual(await adapter.poll(request.transactionId, subject, request.expiresAt, signal), { state: "expired" });
  release();
  assert.deepEqual(await late, { state: "expired" });
  assert.deepEqual(await adapter.check({ ...f.checkInput, evidence: { transactionId: request.transactionId } }), { state: "inactive", reason: "transaction_expired" });
});

for (const [mode, expected] of [
  ["pending", { state: "pending" }], ["empty-pending", { state: "pending" }], ["error", { state: "failed", reason: "verifier_unavailable" }],
  ["timeout", { state: "failed", reason: "verifier_unavailable" }], ["rejected", { state: "failed", reason: "verifier_rejected" }],
  ["missing", { state: "failed", reason: "verifier_transaction_expired" }], ["mismatch", { state: "failed", reason: "transaction_mismatch" }],
] as const) {
  test(`verifier ${mode} fails closed or remains pending`, async (t) => {
    const f = setup(); t.after(() => f.db.close());
    const request = await f.adapter.start(subject, now, signal);
    f.setPollMode(mode);
    assert.deepEqual(await f.adapter.poll(request.transactionId, subject, now, signal), expected);
    if (expected.state !== "pending") {
      f.setPollMode("ready");
      assert.deepEqual(await f.adapter.poll(request.transactionId, subject, now, signal), expected);
    }
  });
}

test("unavailable verifier cannot initialize a stored transaction", async (t) => {
  const f = setup(); t.after(() => f.db.close());
  f.failInit();
  await assert.rejects(f.adapter.start(subject, now, signal), { code: "verifier_unavailable", status: 502 });
  assert.equal(f.db.prepare("SELECT * FROM eudi_transactions").all().length, 0);
});

test("policy strictly rejects unsupported bases and impossible EUDI configurations", () => {
  const input = { ...policyInput(), basis, adapter: config };
  assert.equal(parseIssuerPolicy(input).adapter.kind, "eudi_pid_v1");
  for (const adapter of [{ ...config, verifierBaseUrl: "http://verifier.example" }, { ...config, acceptedVcts: [] },
    { ...config, acceptedAddresses: [] }, { ...config, acceptedAddresses: [{ postalCode: "15344", locality: " " }] },
    { ...config, acceptedAddresses: [...config.acceptedAddresses, { postalCode: " 15344 ", locality: "STRAUSBERG" }] },
    { ...config, acceptedAddresses: [{ postalCode: "15344", locality: "Strausberg", extra: true }] },
    { ...config, transactionTtlSeconds: 0 }, { ...config, transactionTtlSeconds: 901 }, { ...config, validitySeconds: 0 },
    { ...config, ageSource: "birthdate" }]) assert.throws(() => parseIssuerPolicy({ ...input, adapter }), { code: "adapter_config_invalid" });
  for (const unsupported of [{ ...basis, residence: "main_or_secondary_residence" }, { ...basis, nationality: "german_citizen" },
    { ...basis, nationality: "eu_citizen" }, { ...basis, localityScope: ["neighbourhood"] }])
    assert.throws(() => parseIssuerPolicy({ ...input, basis: unsupported }), { code: "eudi_basis_unsupported" });
  assert.equal(parseIssuerPolicy({ ...input, basis: { ...basis, minimumAgeYears: null } }).adapter.kind, "eudi_pid_v1");
});

test("issuer HTTP flow supersedes an old enrollment for the same person with a different holder key", async (t) => {
  const f = setup(); t.after(() => f.db.close());
  const policy = parseIssuerPolicy({ ...policyInput(), municipalityId, policyVersion, basis, adapter: config });
  let at = now;
  const issuer = new IssuerService({ policy, store: new IssuerStore(f.db), adapter: f.adapter, signingKey: issuerKey,
    clock: () => now, commitmentLock: { isCommitmentInOpenAnchor: () => false } });
  const handler = createHttpHandler({ issuer, eudiHandlers: createEudiHttpHandlers({ issuer, adapter: f.adapter }) });
  const unauthenticated = await handler(new Request(`${policy.publicBaseUrl}/v1/eudi/requests`, {
    method: "POST", headers: { "content-type": "application/json" }, body: "{}",
  }));
  assert.equal(unauthenticated.status, 401);
  assert.deepEqual(await unauthenticated.json(), { error: "auth_required" });
  const invalidBody = await handler(authenticatedRequest("/v1/eudi/requests", { extra: true }, at++));
  assert.equal(invalidBody.status, 400);
  assert.deepEqual(await invalidBody.json(), { error: "eudi_request_invalid" });
  async function pollRequest(transactionId: string, key = adopterKey): Promise<Response> {
    const url = `${policy.publicBaseUrl}/v1/eudi/requests/${transactionId}`;
    const auth = signed(nip98Template({ url, method: "GET", body: new Uint8Array(), createdAt: at++ }), key);
    return handler(new Request(url, { headers: { authorization: nip98Header(auth) } }));
  }
  const first = await handler(authenticatedRequest("/v1/eudi/requests", {}, at++, adopterKey));
  assert.equal(first.status, 201);
  assert.equal(first.headers.get("cache-control"), "no-store");
  const transaction = object(await first.json());
  assert.deepEqual(Object.keys(transaction).sort(), ["expiresAt", "transactionId", "walletUrl"]);
  assert.equal(typeof transaction.transactionId, "string");
  const transactionId = transaction.transactionId as string;
  const other = await pollRequest(transactionId, agentKey);
  assert.equal(other.status, 404);
  assert.deepEqual(await other.json(), { error: "eudi_transaction_not_found" });
  assert.deepEqual(await (await pollRequest(transactionId)).json(), { state: "ready" });
  const wrongSubjectEnrollment = await handler(authenticatedRequest("/v1/identity-commitments", {
    identityCommitment: `0x${"00".repeat(31)}09`, evidence: { transactionId },
  }, at++, agentKey));
  assert.equal(wrongSubjectEnrollment.status, 403);
  assert.deepEqual(await wrongSubjectEnrollment.json(), { error: "subject_ineligible" });
  const commitment1 = `0x${"00".repeat(31)}01`;
  const enrollment1 = await handler(authenticatedRequest("/v1/identity-commitments", { identityCommitment: commitment1, evidence: { transactionId } }, at++));
  assert.equal(enrollment1.status, 201);
  f.setPresentation({ holder: 7 });
  const second = await handler(authenticatedRequest("/v1/eudi/requests", {}, at++, agentKey));
  assert.equal(second.status, 201);
  const secondTransaction = object(await second.json());
  assert.equal(typeof secondTransaction.transactionId, "string");
  const secondId = secondTransaction.transactionId as string;
  assert.deepEqual(await (await pollRequest(secondId, agentKey)).json(), { state: "ready" });
  const commitment2 = `0x${"00".repeat(31)}02`;
  const enrollment2 = await handler(authenticatedRequest("/v1/identity-commitments", { identityCommitment: commitment2, evidence: { transactionId: secondId } }, at++, agentKey));
  assert.equal(enrollment2.status, 201);
  const rows = f.db.prepare("SELECT subject_pubkey,commitment FROM issuer_enrollments WHERE municipality_id=? AND active=1").all(municipalityId);
  assert.deepEqual(rows.map((row) => ({ ...row })), [{ subject_pubkey: getPublicKey(agentKey), commitment: commitment2 }]);
  const replay = authenticatedRequest("/v1/eudi/requests", {}, at++, adopterKey);
  const copy = replay.clone();
  assert.equal((await handler(replay)).status, 201);
  const rejected = await handler(copy);
  assert.equal(rejected.status, 409);
  assert.deepEqual(await rejected.json(), { error: "auth_replayed" });
});
