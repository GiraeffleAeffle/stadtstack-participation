import { createPrivateKey, createPublicKey, sign, verify, type KeyObject } from "node:crypto";
import { canonical } from "./canonical.ts";
import { fail } from "./errors.ts";
import { HEX64 } from "./ids.ts";

const PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const SIGNATURE_BASE64URL = /^[A-Za-z0-9_-]{86}$/u;

/** Load an Ed25519 private key from a 32-byte hex seed or a PKCS#8 PEM. */
export function loadEd25519PrivateKey(source: Readonly<{ seedHex: string } | { pem: string }>): KeyObject {
  if ("seedHex" in source) {
    if (!HEX64.test(source.seedHex)) fail("signing_key_invalid", 500);
    return createPrivateKey({ key: Buffer.concat([PKCS8_ED25519_PREFIX, Buffer.from(source.seedHex, "hex")]), format: "der", type: "pkcs8" });
  }
  const key = createPrivateKey(source.pem);
  if (key.asymmetricKeyType !== "ed25519") fail("signing_key_invalid", 500);
  return key;
}

/** Raw 32-byte public key as lowercase hex, the form Stadtstack policies pin. */
export function ed25519PublicKeyHex(privateKey: KeyObject): string {
  const der = createPublicKey(privateKey).export({ format: "der", type: "spki" });
  return Buffer.from(der.subarray(SPKI_ED25519_PREFIX.length)).toString("hex");
}

export function ed25519PublicKeyFromHex(publicKeyHex: string): KeyObject {
  if (!HEX64.test(publicKeyHex)) fail("public_key_invalid");
  return createPublicKey({ key: Buffer.concat([SPKI_ED25519_PREFIX, Buffer.from(publicKeyHex, "hex")]), format: "der", type: "spki" });
}

/** Sign the canonical JSON of `message`; returns unpadded base64url (86 chars). */
export function signCanonical(privateKey: KeyObject, message: unknown): string {
  return sign(null, Buffer.from(canonical(message), "utf8"), privateKey).toString("base64url");
}

/** Verify an unpadded base64url Ed25519 signature over canonical JSON. */
export function verifyCanonical(publicKeyHex: string, message: unknown, signature: unknown): boolean {
  if (typeof signature !== "string" || !SIGNATURE_BASE64URL.test(signature)) return false;
  const bytes = Buffer.from(signature, "base64url");
  if (bytes.toString("base64url") !== signature) return false;
  return verify(null, Buffer.from(canonical(message), "utf8"), ed25519PublicKeyFromHex(publicKeyHex), bytes);
}
