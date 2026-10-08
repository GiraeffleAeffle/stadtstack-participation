import { fail } from "../shared/errors.ts";
import { isMunicipalityId } from "../shared/ids.ts";
import { FIELD_MODULUS } from "./hash.ts";

const encoder = new TextEncoder();

export async function prfInput(municipalityId: string): Promise<Uint8Array<ArrayBuffer>> {
  if (!isMunicipalityId(municipalityId)) fail("municipality_invalid");
  return new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(`stadtstack-participation/person-secret/v1/${municipalityId}`)));
}

/** Expand 512 bits before reduction; no random or persisted fallback exists. */
export async function secretFromPrf(output: Uint8Array, municipalityId: string): Promise<bigint> {
  if (!isMunicipalityId(municipalityId)) fail("municipality_invalid");
  if (output.byteLength !== 32) fail("prf_unavailable");
  const key = await crypto.subtle.importKey("raw", new Uint8Array(output), "HKDF", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: encoder.encode("stadtstack-participation"), info: encoder.encode(`person-secret/v1/${municipalityId}`) }, key, 512);
  let secret = 0n;
  for (const byte of new Uint8Array(bits)) secret = (secret << 8n) | BigInt(byte);
  secret %= FIELD_MODULUS;
  if (secret === 0n) fail("prf_unavailable");
  return secret;
}

type PrfInputs = AuthenticationExtensionsClientInputs & { prf: { eval: { first: Uint8Array<ArrayBuffer> } } };

export async function credentialCreationOptions(options: PublicKeyCredentialCreationOptions, municipalityId: string): Promise<PublicKeyCredentialCreationOptions> {
  return { ...options, authenticatorSelection: { ...options.authenticatorSelection, userVerification: "required" }, extensions: { ...options.extensions, prf: { eval: { first: await prfInput(municipalityId) } } } as PrfInputs };
}

export async function deriveIdentitySecret(input: Readonly<{ municipalityId: string; credentialId: Uint8Array<ArrayBuffer>; rpId?: string; credentials?: Pick<CredentialsContainer, "get"> }>): Promise<bigint> {
  const credentials = input.credentials ?? globalThis.navigator?.credentials;
  if (!credentials) fail("prf_unavailable");
  let assertion: Credential | null;
  try {
    assertion = await credentials.get({ publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      allowCredentials: [{ type: "public-key", id: input.credentialId }],
      ...(input.rpId ? { rpId: input.rpId } : {}),
      userVerification: "required",
      extensions: { prf: { eval: { first: await prfInput(input.municipalityId) } } } as PrfInputs,
    } });
  } catch {
    fail("prf_unavailable");
  }
  if (!assertion || !("getClientExtensionResults" in assertion) || typeof assertion.getClientExtensionResults !== "function") fail("prf_unavailable");
  const extensions = assertion.getClientExtensionResults() as { prf?: { results?: { first?: ArrayBuffer } } };
  const output = extensions.prf?.results?.first;
  if (!(output instanceof ArrayBuffer)) fail("prf_unavailable");
  return secretFromPrf(new Uint8Array(output), input.municipalityId);
}
