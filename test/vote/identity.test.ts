import assert from "node:assert/strict";
import { hkdfSync, createHash } from "node:crypto";
import test from "node:test";
import { getPublicKey } from "nostr-tools/pure";
import { attestorPrfSalt, attestorSeedFromPrf, credentialCreationOptions, deriveAttestorSecretKey, deriveParticipantKeys, FIELD_MODULUS, nostrSecretKeyFromPrf, participantPrfSalts, secretFromPrf } from "../../src/vote/index.ts";

const SECP256K1_ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const expand = (output: Uint8Array, info: string, length: number) => Buffer.from(hkdfSync("sha256", output, "stadtstack-participation", info, length));
const salt = (label: string) => new Uint8Array(createHash("sha256").update(`stadtstack-participation/${label}`).digest());
const prfCredentials = (results: Record<string, ArrayBuffer>, onGet?: (options: CredentialRequestOptions | undefined) => void): Pick<CredentialsContainer, "get"> => ({
  async get(options) {
    onGet?.(options);
    return { id: "credential", type: "public-key", getClientExtensionResults() { return { prf: { results } }; } } as unknown as PublicKeyCredential;
  },
});

test("each purpose has its own municipality-scoped salt and HKDF label", async () => {
  const output = new Uint8Array(32).fill(7);
  assert.equal(await secretFromPrf(output, "test-town"), BigInt(`0x${expand(output, "person-secret/v1/test-town", 64).toString("hex")}`) % FIELD_MODULUS);
  const nostrScalar = BigInt(`0x${expand(output, "nostr-subject/v1/test-town", 48).toString("hex")}`) % (SECP256K1_ORDER - 1n) + 1n;
  assert.equal(Buffer.from(await nostrSecretKeyFromPrf(output, "test-town")).toString("hex"), nostrScalar.toString(16).padStart(64, "0"));
  assert.deepEqual(Buffer.from(await attestorSeedFromPrf(output, "test-town")), expand(output, "attestor-key/v1/test-town", 32));
  const salts = await participantPrfSalts("test-town");
  assert.deepEqual(salts.first, salt("person-secret/v1/test-town"));
  assert.deepEqual(salts.second, salt("nostr-subject/v1/test-town"));
  assert.deepEqual(await attestorPrfSalt("test-town"), salt("attestor-key/v1/test-town"));
  assert.notEqual(await secretFromPrf(output, "other-town"), await secretFromPrf(output, "test-town"));
  await assert.rejects(secretFromPrf(new Uint8Array(31), "test-town"), /prf_unavailable/u);
});

test("credential creation requires user verification and requests the role's PRF salts", async () => {
  const base = { challenge: new Uint8Array(32), rp: { name: "Town" }, user: { id: new Uint8Array([1]), name: "holder", displayName: "Holder" }, pubKeyCredParams: [{ type: "public-key" as const, alg: -7 }], authenticatorSelection: { userVerification: "discouraged" as const } };
  const participant = await credentialCreationOptions(base, "test-town", "participant");
  assert.equal(participant.authenticatorSelection?.userVerification, "required");
  assert.equal(participant.rp.id, undefined);
  // DOM declarations do not describe the PRF extension yet.
  assert.deepEqual((participant.extensions as { prf: { eval: unknown } }).prf.eval, await participantPrfSalts("test-town"));
  const attestor = await credentialCreationOptions(base, "test-town", "attestor");
  assert.deepEqual((attestor.extensions as { prf: { eval: unknown } }).prf.eval, { first: await attestorPrfSalt("test-town") });
});

test("one assertion yields the voting secret and a valid Nostr key; missing PRF output fails closed", async () => {
  let captured: CredentialRequestOptions | undefined;
  const first = new Uint8Array(32).fill(9).buffer;
  const second = new Uint8Array(32).fill(3).buffer;
  const keys = await deriveParticipantKeys({ municipalityId: "test-town", credentials: prfCredentials({ first, second }, (options) => { captured = options; }) });
  assert.equal(keys.votingSecret, await secretFromPrf(new Uint8Array(first), "test-town"));
  assert.match(getPublicKey(keys.nostrSecretKey), /^[0-9a-f]{64}$/u);
  assert.equal(captured?.publicKey?.userVerification, "required");
  assert.equal(captured?.publicKey?.rpId, undefined);
  assert.equal(captured?.publicKey?.allowCredentials, undefined);
  for (const credentials of [
    prfCredentials({ first }),
    prfCredentials({}),
    { async get() { return null; } },
    { async get() { throw new Error("unsupported"); } },
  ]) {
    await assert.rejects(deriveParticipantKeys({ municipalityId: "test-town", credentials }), /prf_unavailable/u);
  }
  const attestorKey = await deriveAttestorSecretKey({ municipalityId: "test-town", credentials: prfCredentials({ first }) });
  assert.deepEqual(attestorKey, await attestorSeedFromPrf(new Uint8Array(first), "test-town"));
});
