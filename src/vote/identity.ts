import { fail } from "../shared/errors.ts";
import { isMunicipalityId } from "../shared/ids.ts";
import { FIELD_MODULUS } from "./hash.ts";

/**
 * Client key material comes from the WebAuthn PRF extension of one passkey,
 * scoped to one municipality. Salts and HKDF labels are normative (DESIGN.md).
 * No helper accepts an rpId: the browser binds the passkey to the exact
 * origin host, so no sibling subdomain can evaluate the same PRF.
 */
const SECP256K1_ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const encoder = new TextEncoder();
type Purpose = "person-secret" | "nostr-subject" | "attestor-key";
type PrfSalts = Readonly<{ first: Uint8Array<ArrayBuffer>; second?: Uint8Array<ArrayBuffer> }>;
type PrfResults = Readonly<{ first: Uint8Array; second?: Uint8Array }>;

async function prfSalt(purpose: Purpose, municipalityId: string): Promise<Uint8Array<ArrayBuffer>> {
  if (!isMunicipalityId(municipalityId)) fail("municipality_invalid");
  return new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(`stadtstack-participation/${purpose}/v1/${municipalityId}`)));
}

async function expand(output: Uint8Array, purpose: Purpose, municipalityId: string, bytes: number): Promise<Uint8Array> {
  if (!isMunicipalityId(municipalityId)) fail("municipality_invalid");
  if (output.byteLength !== 32) fail("prf_unavailable");
  const key = await crypto.subtle.importKey("raw", new Uint8Array(output), "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: encoder.encode("stadtstack-participation"), info: encoder.encode(`${purpose}/v1/${municipalityId}`) }, key, bytes * 8));
}

function bigEndian(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
}

/** PRF salts for a participant: `first` yields the voting secret, `second` the Nostr subject key. */
export async function participantPrfSalts(municipalityId: string): Promise<Required<PrfSalts>> {
  return { first: await prfSalt("person-secret", municipalityId), second: await prfSalt("nostr-subject", municipalityId) };
}

/** PRF salt for an attestor's Ed25519 signing key in one municipality. */
export async function attestorPrfSalt(municipalityId: string): Promise<Uint8Array<ArrayBuffer>> {
  return prfSalt("attestor-key", municipalityId);
}

/** Voting secret in [1, r-1]: 512 expanded bits reduced modulo the BN254 scalar field. */
export async function secretFromPrf(output: Uint8Array, municipalityId: string): Promise<bigint> {
  const secret = bigEndian(await expand(output, "person-secret", municipalityId, 64)) % FIELD_MODULUS;
  if (secret === 0n) fail("prf_unavailable");
  return secret;
}

/** Nostr (secp256k1) secret key in [1, n-1], from 384 expanded bits. */
export async function nostrSecretKeyFromPrf(output: Uint8Array, municipalityId: string): Promise<Uint8Array> {
  const scalar = bigEndian(await expand(output, "nostr-subject", municipalityId, 48)) % (SECP256K1_ORDER - 1n) + 1n;
  const key = new Uint8Array(32);
  for (let index = 31, rest = scalar; index >= 0; index--, rest >>= 8n) key[index] = Number(rest & 0xffn);
  return key;
}

/** Ed25519 secret key (RFC 8032 seed) for an attestor. */
export async function attestorSeedFromPrf(output: Uint8Array, municipalityId: string): Promise<Uint8Array> {
  return expand(output, "attestor-key", municipalityId, 32);
}

type PrfExtension = AuthenticationExtensionsClientInputs & { prf: { eval: PrfSalts } };

/** Creation options that require user verification and request PRF for the role's salts. */
export async function credentialCreationOptions(options: PublicKeyCredentialCreationOptions, municipalityId: string, role: "participant" | "attestor"): Promise<PublicKeyCredentialCreationOptions> {
  const salts = role === "participant" ? await participantPrfSalts(municipalityId) : { first: await attestorPrfSalt(municipalityId) };
  const extensions: PrfExtension = { ...options.extensions, prf: { eval: salts } };
  return { ...options, authenticatorSelection: { ...options.authenticatorSelection, userVerification: "required" }, extensions };
}

type AssertionInput = Readonly<{ credentialId?: Uint8Array<ArrayBuffer>; credentials?: Pick<CredentialsContainer, "get"> }>;

function prfBytes(value: unknown): Uint8Array | undefined {
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  return undefined;
}

async function evaluatePrf(input: AssertionInput, salts: PrfSalts): Promise<PrfResults> {
  const credentials = input.credentials ?? globalThis.navigator?.credentials;
  if (!credentials) fail("prf_unavailable");
  const extensions: PrfExtension = { prf: { eval: salts } };
  let assertion: Credential | null;
  try {
    assertion = await credentials.get({ publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      ...(input.credentialId ? { allowCredentials: [{ type: "public-key", id: input.credentialId }] } : {}),
      userVerification: "required",
      extensions,
    } });
  } catch {
    fail("prf_unavailable");
  }
  if (!assertion || !("getClientExtensionResults" in assertion) || typeof assertion.getClientExtensionResults !== "function") fail("prf_unavailable");
  const results: unknown = assertion.getClientExtensionResults();
  const prf = results && typeof results === "object" && "prf" in results ? results.prf : undefined;
  const values = prf && typeof prf === "object" && "results" in prf ? prf.results : undefined;
  if (!values || typeof values !== "object") fail("prf_unavailable");
  const first = prfBytes("first" in values ? values.first : undefined);
  const second = prfBytes("second" in values ? values.second : undefined);
  if (!first || (salts.second && !second)) fail("prf_unavailable");
  return { first, ...(second ? { second } : {}) };
}

/** One passkey assertion yields the voting secret and the Nostr subject key. No fallback exists. */
export async function deriveParticipantKeys(input: AssertionInput & Readonly<{ municipalityId: string }>): Promise<Readonly<{ votingSecret: bigint; nostrSecretKey: Uint8Array }>> {
  const results = await evaluatePrf(input, await participantPrfSalts(input.municipalityId));
  return { votingSecret: await secretFromPrf(results.first, input.municipalityId), nostrSecretKey: await nostrSecretKeyFromPrf(results.second!, input.municipalityId) };
}

/** One passkey assertion yields the attestor's Ed25519 secret key. */
export async function deriveAttestorSecretKey(input: AssertionInput & Readonly<{ municipalityId: string }>): Promise<Uint8Array> {
  const results = await evaluatePrf(input, { first: await attestorPrfSalt(input.municipalityId) });
  return attestorSeedFromPrf(results.first, input.municipalityId);
}
