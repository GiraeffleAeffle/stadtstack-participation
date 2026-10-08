import assert from "node:assert/strict";
import test from "node:test";
import { InPersonAttestorsAdapter, validateInPersonAttestorsConfig } from "../../src/adapters/in-person-attestors.ts";
import { attestation, basis, municipalityId, policyInput, policyVersion, setup, subject } from "../issuer/fixtures.ts";

const signal = new AbortController().signal;
async function decision(adapter: InPersonAttestorsAdapter, now: number) {
  return adapter.recheck({ municipalityId, policyVersion, subjectPubkey: subject, evidenceRef: subject, now, signal });
}

test("K-1 attestations do not qualify; K qualify with earliest-attestation expiry", async () => {
  const c = setup();
  try {
    c.adapter.recordAttestation(attestation(0, 90), 100);
    assert.equal((await decision(c.adapter, 100)).state, "inactive");
    c.adapter.recordAttestation(attestation(1, 100), 100);
    assert.deepEqual(await decision(c.adapter, 100), { state: "active", effectiveAt: 100, validUntil: 1090, evidenceRef: subject });
    assert.equal((await decision(c.adapter, 1090)).state, "inactive");
    assert.equal((await decision(c.adapter, 1089)).state, "active");
  } finally { c.db.close(); }
});

for (const gap of [20, 21]) {
  test(`attestation window boundary gap ${gap}`, async () => {
    const c = setup();
    try {
      c.adapter.recordAttestation(attestation(0, 80), 100);
      c.adapter.recordAttestation(attestation(1, 80 + gap), 101);
      assert.equal((await decision(c.adapter, 101)).state, gap === 20 ? "active" : "inactive");
    } finally { c.db.close(); }
  });
}

test("self-attestation and invalid attestor validity boundaries are rejected", () => {
  const c = setup();
  try {
    const own = policyInput().adapter.attestors[0]!.ownSubjectPubkeys[0]!;
    assert.throws(() => c.adapter.recordAttestation(attestation(0, 90, own), 100), /attestation_invalid/u);
    assert.throws(() => c.adapter.recordAttestation(attestation(0, 9), 100), /attestation_invalid/u);
    c.adapter.recordAttestation(attestation(0, 10), 100);
    assert.throws(() => c.adapter.recordAttestation(attestation(0, 10000), 10000), /attestation_invalid/u);
    c.adapter.recordAttestation(attestation(0, 9999), 10000);
    assert.throws(() => c.adapter.recordAttestation(attestation(1, 101), 100), /attestation_invalid/u);
  } finally { c.db.close(); }
});

test("single-attestor stacking cannot extend expiry; K fresh attestations renew", async () => {
  const c = setup();
  try {
    c.adapter.recordAttestation(attestation(0, 90), 100);
    c.adapter.recordAttestation(attestation(1, 95), 100);
    c.adapter.recordAttestation(attestation(0, 100), 100);
    assert.deepEqual(await decision(c.adapter, 100), { state: "active", effectiveAt: 95, validUntil: 1090, evidenceRef: subject });
    c.adapter.recordAttestation(attestation(0, 110), 110);
    assert.equal((await decision(c.adapter, 1090)).state, "inactive");
    c.adapter.recordAttestation(attestation(1, 115), 115);
    assert.deepEqual(await decision(c.adapter, 115), { state: "active", effectiveAt: 115, validUntil: 1110, evidenceRef: subject });
  } finally { c.db.close(); }
});

test("latest per attestor prevents using an older convenient window", async () => {
  const c = setup();
  try {
    c.adapter.recordAttestation(attestation(0, 70), 100);
    c.adapter.recordAttestation(attestation(0, 95), 100);
    c.adapter.recordAttestation(attestation(1, 75), 100);
    assert.equal((await decision(c.adapter, 100)).state, "active");
    // Existing grants survive a single new attestation but do not renew.
    c.adapter.recordAttestation(attestation(0, 200), 200);
    assert.deepEqual(await decision(c.adapter, 200), { state: "active", effectiveAt: 75, validUntil: 1070, evidenceRef: subject });
  } finally { c.db.close(); }
});

test("R distinct revocations, no duplicate stacking, and K re-attestations after revocation", async () => {
  const c = setup();
  try {
    c.adapter.recordAttestation(attestation(0, 90), 100);
    c.adapter.recordAttestation(attestation(1, 95), 100);
    c.adapter.recordRevocation(attestation(0, 96, subject, true), 100);
    c.adapter.recordRevocation(attestation(0, 97, subject, true), 100);
    assert.equal((await decision(c.adapter, 100)).state, "active");
    c.adapter.recordRevocation(attestation(1, 100, subject, true), 100);
    assert.equal((await decision(c.adapter, 100)).state, "inactive");
    c.adapter.recordAttestation(attestation(0, 101), 110);
    assert.equal((await decision(c.adapter, 110)).state, "inactive");
    c.adapter.recordAttestation(attestation(1, 110), 110);
    assert.equal((await decision(c.adapter, 110)).state, "active");
    c.adapter.recordRevocation(attestation(2, 110, subject, true), 110);
    assert.equal((await decision(c.adapter, 110)).state, "active");
  } finally { c.db.close(); }
});

test("exact adapter config, policy basis and signature are mandatory", () => {
  const c = setup();
  try {
    const config = policyInput().adapter;
    assert.throws(() => validateInPersonAttestorsConfig({ ...config, requiredAttestations: 1 }), /attestor_config_invalid/u);
    assert.throws(() => validateInPersonAttestorsConfig({ ...config, extra: true }), /attestor_config_invalid/u);
    const good = attestation(0, 90);
    assert.throws(() => c.adapter.recordAttestation({ ...good, signature: "a".repeat(86) }, 100), /attestation_signature_invalid/u);
    assert.throws(() => c.adapter.recordAttestation({ ...good, core: { ...good.core, basis: { ...basis, minimumAgeYears: 18 } } }, 100), /attestation_invalid/u);
    assert.throws(() => c.adapter.recordAttestation({ ...good, core: { ...good.core, documentKinds: ["document number 123"] } }, 100), /attestation_invalid/u);
  } finally { c.db.close(); }
});

test("a fresh third attestor cannot reuse the previous cohort's latest member", async () => {
  const c = setup();
  try {
    c.adapter.recordAttestation(attestation(0, 90), 100);
    c.adapter.recordAttestation(attestation(1, 95), 100);
    c.adapter.recordAttestation(attestation(2, 100), 100);
    // Candidates at 100 and 95 satisfy the window, but 95 is the previous
    // cohort's effectiveAt: renewal needs strictly newer members, not >=.
    assert.deepEqual(await decision(c.adapter, 100), { state: "active", effectiveAt: 95, validUntil: 1090, evidenceRef: subject });
    c.adapter.recordAttestation(attestation(0, 101), 101);
    assert.deepEqual(await decision(c.adapter, 101), { state: "active", effectiveAt: 101, validUntil: 1100, evidenceRef: subject });
    assert.equal((await decision(c.adapter, 1100)).state, "inactive");
  } finally { c.db.close(); }
});
