import assert from "node:assert/strict";
import { hkdfSync, createHash } from "node:crypto";
import test from "node:test";
import { credentialCreationOptions, deriveIdentitySecret, FIELD_MODULUS, prfInput, secretFromPrf } from "../../src/vote/index.ts";

test("PRF secret uses municipality-scoped SHA256 input and 64-byte HKDF", async () => {
  const output = new Uint8Array(32).fill(7);
  const expanded = new Uint8Array(hkdfSync("sha256", output, "stadtstack-participation", "person-secret/v1/test-town", 64));
  const expected = BigInt(`0x${Buffer.from(expanded).toString("hex")}`) % FIELD_MODULUS;
  assert.equal(await secretFromPrf(output, "test-town"), expected);
  assert.notEqual(await secretFromPrf(output, "other-town"), expected);
  assert.deepEqual(await prfInput("test-town"), new Uint8Array(createHash("sha256").update("stadtstack-participation/person-secret/v1/test-town").digest()));
  await assert.rejects(secretFromPrf(new Uint8Array(31), "test-town"), /prf_unavailable/u);
});

test("credential creation requests PRF and required user verification", async () => {
  const options = await credentialCreationOptions({ challenge: new Uint8Array(32), rp: { name: "Town" }, user: { id: new Uint8Array([1]), name: "holder", displayName: "Holder" }, pubKeyCredParams: [{ type: "public-key", alg: -7 }], authenticatorSelection: { userVerification: "discouraged" } }, "test-town");
  assert.equal(options.authenticatorSelection?.userVerification, "required");
  // DOM declarations do not yet describe the PRF extension requested by our helper.
  const extensions = options.extensions as { prf: { eval: { first: Uint8Array } } };
  assert.deepEqual(extensions.prf.eval.first, await prfInput("test-town"));
});

test("assertion requires PRF and required verification without fallback storage", async () => {
  let captured: CredentialRequestOptions | undefined;
  const credentials: Pick<CredentialsContainer, "get"> = { async get(options) {
    captured = options;
    return { id: "credential", type: "public-key", getClientExtensionResults() { return { prf: { results: { first: new Uint8Array(32).fill(9).buffer } } }; } } as unknown as PublicKeyCredential;
  } };
  const secret = await deriveIdentitySecret({ municipalityId: "test-town", credentialId: new Uint8Array([1]), credentials });
  assert.equal(secret, await secretFromPrf(new Uint8Array(32).fill(9), "test-town"));
  assert.equal(captured?.publicKey?.userVerification, "required");
  // Captured WebAuthn options have the same extension typing gap.
  const extensions = captured?.publicKey?.extensions as { prf: { eval: { first: Uint8Array } } };
  assert.deepEqual(extensions.prf.eval.first, await prfInput("test-town"));
  for (const get of [async () => null, async () => ({ id: "credential", type: "public-key", getClientExtensionResults() { return {}; } }) as unknown as PublicKeyCredential, async () => { throw new Error("unsupported"); }]) {
    await assert.rejects(deriveIdentitySecret({ municipalityId: "test-town", credentialId: new Uint8Array([1]), credentials: { get } }), /prf_unavailable/u);
  }
});
