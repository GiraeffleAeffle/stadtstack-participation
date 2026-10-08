import assert from "node:assert/strict";
import { createPublicKey, generateKeyPairSync, verify } from "node:crypto";
import { describe, it } from "node:test";
import { finalizeEvent, generateSecretKey } from "nostr-tools/pure";
import { canonical, snapshot } from "../../src/shared/canonical.ts";
import { ed25519PublicKeyHex, loadEd25519PrivateKey, signCanonical, verifyCanonical } from "../../src/shared/ed25519.ts";
import { nip98Header, nip98Template, verifyNip98 } from "../../src/shared/nostr.ts";

describe("canonical JSON", () => {
  it("sorts keys recursively and is independent of insertion order", () => {
    assert.equal(canonical({ b: 1, a: { d: [2, { y: 1, x: 0 }], c: "é" } }), '{"a":{"c":"é","d":[2,{"x":0,"y":1}]},"b":1}');
    assert.equal(canonical({ x: 1, y: 2 }), canonical({ y: 2, x: 1 }));
  });

  it("rejects values a canonical encoding cannot represent", () => {
    assert.throws(() => snapshot({ amount: 1.5 }), /shape_invalid/);
    assert.throws(() => snapshot({ big: 2 ** 60 }), /shape_invalid/);
    assert.throws(() => snapshot(new Map()), /shape_invalid/);
    assert.throws(() => snapshot({ get secret() { return 1; } }), /shape_invalid/);
  });
});

describe("Ed25519 canonical signatures", () => {
  const key = loadEd25519PrivateKey({ seedHex: "11".repeat(32) });
  const publicKey = ed25519PublicKeyHex(key);

  it("verifies regardless of key order and rejects any change", () => {
    const signature = signCanonical(key, { a: 1, b: "x" });
    assert.equal(signature.length, 86);
    assert.equal(verifyCanonical(publicKey, { b: "x", a: 1 }, signature), true);
    assert.equal(verifyCanonical(publicKey, { a: 2, b: "x" }, signature), false);
    assert.equal(verifyCanonical(ed25519PublicKeyHex(loadEd25519PrivateKey({ seedHex: "22".repeat(32) })), { a: 1, b: "x" }, signature), false);
    assert.equal(verifyCanonical(publicKey, { a: 1, b: "x" }, `${signature}=`), false);
  });

  it("loads an OpenSSL-style PKCS#8 PEM and produces signatures Node's own Ed25519 accepts", () => {
    const { privateKey } = generateKeyPairSync("ed25519");
    const loaded = loadEd25519PrivateKey({ pem: privateKey.export({ format: "pem", type: "pkcs8" }).toString() });
    const nodePublicKey = createPublicKey(privateKey);
    assert.equal(ed25519PublicKeyHex(loaded), Buffer.from(nodePublicKey.export({ format: "der", type: "spki" })).subarray(12).toString("hex"));
    const message = { domain: "test/v1", value: 7 };
    const signature = Buffer.from(signCanonical(loaded, message), "base64url");
    assert.equal(verify(null, Buffer.from(canonical(message)), nodePublicKey, signature), true);
    assert.throws(() => loadEd25519PrivateKey({ pem: generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey.export({ format: "pem", type: "pkcs8" }).toString() }), /signing_key_invalid/);
  });
});

describe("NIP-98 request authentication", () => {
  const secret = generateSecretKey();
  const url = "https://issuer.example/v1/eligibility/receipts";
  const body = new TextEncoder().encode('{"hello":"world"}');
  const now = 1_800_000_000;
  const header = nip98Header(finalizeEvent(nip98Template({ url, method: "POST", body, createdAt: now }), secret));
  const request = { authorization: header, method: "POST", url, body, now, maxSkewSeconds: 60 };

  it("returns the signer for the exact method, URL and body", () => {
    const identity = verifyNip98(request);
    assert.match(identity.pubkey, /^[0-9a-f]{64}$/u);
    assert.equal(identity.createdAt, now);
  });

  it("rejects another URL, method, body or a stale timestamp", () => {
    assert.throws(() => verifyNip98({ ...request, url: "https://issuer.example/v1/adoptions" }), /auth_invalid/);
    assert.throws(() => verifyNip98({ ...request, method: "PUT" }), /auth_invalid/);
    assert.throws(() => verifyNip98({ ...request, body: new TextEncoder().encode("{}") }), /auth_invalid/);
    assert.throws(() => verifyNip98({ ...request, now: now + 61 }), /auth_invalid/);
    assert.throws(() => verifyNip98({ ...request, authorization: null }), /auth_required/);
  });
});
