import assert from "node:assert/strict";
import test from "node:test";
import { createClientConfig, createHttpHandler } from "../../src/http.ts";
import { IssuerService } from "../../src/issuer/service.ts";
import { nip98Header, nip98Template } from "../../src/shared/nostr.ts";
import { createVoteHttpHandlers } from "../../src/vote/http.ts";
import { VoteStore } from "../../src/vote/store.ts";
import { buildAnchor } from "../../src/vote/anchor.ts";
import { digest } from "../../src/shared/canonical.ts";
import type { Tally } from "../../src/vote/tally.ts";
import { adopterKey, attestation, authenticatedRequest, setup, signed, subject } from "../issuer/fixtures.ts";
import { chainFor, metadata } from "../vote/helpers.ts";

function meRequest(at: number): Request {
  const url = "https://eligibility.example/v1/eligibility/me";
  return new Request(url, { headers: { authorization: nip98Header(signed(nip98Template({ url, method: "GET", body: new Uint8Array(0), createdAt: at }), adopterKey)) } });
}

test("client config exposes only public adapter keys and validates all-or-none chain configuration", async () => {
  const c = setup();
  try {
    const config = createClientConfig(c.policy, { DISPLAY_NAME: "Beispielstadt", OPERATOR_NAME: "Stadtstack" });
    assert.deepEqual(config, { schemaVersion: "participation_client_config_v1", municipalityId: c.policy.municipalityId, ags: c.policy.ags,
      policyVersion: c.policy.policyVersion, displayName: "Beispielstadt", operator: { name: "Stadtstack", isMunicipality: false }, publicBaseUrl: c.policy.publicBaseUrl,
      adapterKind: c.policy.adapter.kind, basis: c.policy.basis,
      attestors: c.policy.adapter.kind === "in_person_attestors_v1" ? c.policy.adapter.attestors.map(({ attestorId, publicKey }) => ({ attestorId, publicKey })) : null, chain: null });
    const handler = createHttpHandler({ issuer: c.issuer, clientConfig: config });
    const response = await handler(new Request(`${c.policy.publicBaseUrl}/v1/client-config`));
    assert.equal(response.status, 200); assert.deepEqual(await response.json(), config);
    const valid = { DISPLAY_NAME: "Stadt", OPERATOR_NAME: "Stadtstack", CHAIN_ID: "10200", REGISTRY_ADDRESS: `0x${"aB".repeat(20)}`, PUBLIC_RPC_URL: "https://rpc.chiadochain.net" };
    const chain = createClientConfig(c.policy, valid).chain;
    assert.deepEqual(chain, { chainId: 10200, registryAddress: `0x${"ab".repeat(20)}`, rpcUrl: "https://rpc.chiadochain.net/" });
    assert.equal(createClientConfig(c.policy, { ...valid, PUBLIC_RPC_URL: "http://localhost:8545" }).chain?.rpcUrl, "http://localhost:8545/");
    assert.deepEqual(createClientConfig(c.policy, { ...valid, OPERATOR_NAME: "Stadt Beispiel", OPERATOR_IS_MUNICIPALITY: "true" }).operator, { name: "Stadt Beispiel", isMunicipality: true });
    // Without a named operator the page could pass for an official service.
    for (const environment of [ {}, { DISPLAY_NAME: " ", OPERATOR_NAME: "Stadtstack" }, { DISPLAY_NAME: "Stadt" }, { DISPLAY_NAME: "Stadt", OPERATOR_NAME: " " },
      { ...valid, OPERATOR_IS_MUNICIPALITY: "yes" }, { DISPLAY_NAME: "Stadt", OPERATOR_NAME: "Stadtstack", CHAIN_ID: "10200" },
      { ...valid, CHAIN_ID: "0" }, { ...valid, CHAIN_ID: "1.5" }, { ...valid, CHAIN_ID: "9007199254740992" },
      { ...valid, REGISTRY_ADDRESS: "0x12" }, { ...valid, PUBLIC_RPC_URL: "http://rpc.example" },
      { ...valid, PUBLIC_RPC_URL: "https://user:password@rpc.example" }, { ...valid, PUBLIC_RPC_URL: "not a url" },
      { ...valid, PUBLIC_RPC_URL: "https://rpc.example/#fragment" } ]) assert.throws(() => createClientConfig(c.policy, environment));
    const nftPolicy = { ...c.policy, adapter: { kind: "roebel_citizen_nft_v1", chainId: 100, contractAddress: `0x${"11".repeat(20)}` as `0x${string}`,
      expectedCodeHash: `0x${"22".repeat(32)}` as `0x${string}`, blockTag: "finalized", walletProofMaxAgeSeconds: 300 } } as const;
    assert.equal(createClientConfig(nftPolicy, { DISPLAY_NAME: "Stadt", OPERATOR_NAME: "Stadtstack" }).attestors, null);
  } finally { c.db.close(); }
});

test("eligibility me previews attestations, reports enrollment, rechecks revocation and consumes GET authentication once", async () => {
  const c = setup();
  try {
    const initial = meRequest(100);
    const response = await c.handler(initial.clone());
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { subjectPubkey: subject, eligibility: { state: "inactive", reason: "insufficient_attestations" }, enrollment: null });
    const replay = await c.handler(initial.clone());
    assert.equal(replay.status, 409); assert.deepEqual(await replay.json(), { error: "auth_replayed" });
    c.adapter.recordAttestation(attestation(0, 90), 100); c.adapter.recordAttestation(attestation(1, 95), 100);
    c.setTime(101);
    const active = await c.handler(meRequest(101));
    assert.deepEqual(await active.json(), { subjectPubkey: subject, eligibility: { state: "active", effectiveAt: 95, validUntil: 1090 }, enrollment: null });
    const commitment = `0x${"00".repeat(31)}01`;
    assert.equal((await c.handler(authenticatedRequest("/v1/identity-commitments", { identityCommitment: commitment, evidence: null }, 101))).status, 201);
    c.setTime(102);
    const enrolled = await c.handler(meRequest(102));
    assert.deepEqual(await enrolled.json(), { subjectPubkey: subject, eligibility: { state: "active", effectiveAt: 95, validUntil: 1090 }, enrollment: { identityCommitment: commitment, enrolledAt: 101 } });
    c.adapter.recordRevocation(attestation(0, 102, subject, true), 102); c.adapter.recordRevocation(attestation(1, 102, subject, true), 102);
    c.setTime(103);
    const revoked = await c.handler(meRequest(103));
    assert.deepEqual((await revoked.json()).eligibility, { state: "inactive", reason: "revoked" });
    assert.equal((await c.handler(new Request("https://eligibility.example/v1/eligibility/me"))).status, 401);
  } finally { c.db.close(); }
});

test("eligibility me requires fresh evidence when the adapter cannot preview", async () => {
  const c = setup();
  try {
    const issuer = new IssuerService({ policy: c.policy, store: c.issuer.store, signingKey: c.issuer.signingKey, clock: c.issuer.clock,
      commitmentLock: c.issuer.commitmentLock, adapter: { kind: c.adapter.kind,
        check: c.adapter.check.bind(c.adapter), recheck: c.adapter.recheck.bind(c.adapter) } });
    const handler = createHttpHandler({ issuer });
    assert.deepEqual(await (await handler(meRequest(100))).json(), { subjectPubkey: subject, eligibility: { state: "inactive", reason: "evidence_required" }, enrollment: null });
  } finally { c.db.close(); }
});

test("elections list includes open and closed mirrors newest first and excludes drafts", async () => {
  const c = setup();
  try {
    const store = new VoteStore(c.db);
    const mirrors = [];
    for (const [slug, opensAt, state] of [["older", 100, "open"], ["newest", 300, "open"], ["hidden", 400, "draft"], ["closed", 200, "closed"]] as const) {
      const data = { ...metadata(slug), opensAt, closesAt: opensAt + 100 };
      const anchor = await buildAnchor({ async listEligibleCommitments() { return [`0x${"0".repeat(63)}1`]; } }, { metadata: data, anchoredAt: 90, signal: new AbortController().signal });
      let mirror = store.putElection(data, anchor);
      if (state !== "draft") mirror = store.openElection(data.electionId, chainFor({ ...mirror, state: "open" }));
      if (state === "closed") {
        const tally: Tally = { schemaVersion: "advisory_tally_v1", municipalityId: data.municipalityId, policyVersion: data.policyVersion,
          electionId: data.electionId, anchorRoot: mirror.anchorRoot, metadataHash: mirror.metadataHash, scope: mirror.scope,
          window: { opensAt: data.opensAt, closesAt: data.closesAt }, choices: data.choices.map((choice) => ({ ...choice, count: 0 })), totalAccepted: 0, ballots: [],
          verifier: { circuitSha256: "11".repeat(32), vkHash: `0x${"22".repeat(32)}` } };
        const tallyHash = `0x${digest(tally)}` as const;
        store.putTally(data.electionId, tally, tallyHash);
        mirror = store.closeElection(data.electionId, { ...chainFor({ ...mirror, state: "closed" }), tallyHash });
      }
      if (state !== "draft") mirrors.push(mirror);
    }
    const handler = createHttpHandler({ issuer: c.issuer, voteHandlers: createVoteHttpHandlers({ store, clock: () => 350, verifier: { async verify() { return true; } } }) });
    const response = await handler(new Request("https://eligibility.example/v1/elections"));
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { elections: mirrors.sort((a, b) => b.opensAt - a.opensAt) });
  } finally { c.db.close(); }
});
