import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { base64, base64urlnopad } from "@scure/base";
import { canonical } from "./canonical.ts";
import { fail } from "./errors.ts";
import { HEX64 } from "./ids.ts";

const PKCS8_ED25519_PREFIX = "302e020100300506032b657004220420";
const SIGNATURE_BASE64URL = /^[A-Za-z0-9_-]{86}$/u;

/**
 * Load a 32-byte Ed25519 secret key (the RFC 8032 seed) from hex or from an
 * unencrypted PKCS#8 PEM. Works in Node and in browsers.
 */
export function loadEd25519PrivateKey(source: Readonly<{ seedHex: string } | { pem: string }>): Uint8Array {
  if ("seedHex" in source) {
    if (!HEX64.test(source.seedHex)) fail("signing_key_invalid", 500);
    return hexToBytes(source.seedHex);
  }
  const body = /^-----BEGIN PRIVATE KEY-----\s*([A-Za-z0-9+/=\s]+?)\s*-----END PRIVATE KEY-----\s*$/u.exec(source.pem)?.[1];
  let der: Uint8Array;
  try { der = base64.decode((body ?? "").replace(/\s+/gu, "")); } catch { fail("signing_key_invalid", 500); }
  if (der.length !== 48 || bytesToHex(der.subarray(0, 16)) !== PKCS8_ED25519_PREFIX) fail("signing_key_invalid", 500);
  return der.slice(16);
}

/** Raw 32-byte public key as lowercase hex, the form Stadtstack policies pin. */
export function ed25519PublicKeyHex(secretKey: Uint8Array): string {
  return bytesToHex(ed25519.getPublicKey(secretKey));
}

/** Sign the canonical JSON of `message`; returns unpadded base64url (86 chars). */
export function signCanonical(secretKey: Uint8Array, message: unknown): string {
  return base64urlnopad.encode(ed25519.sign(utf8ToBytes(canonical(message)), secretKey));
}

/** Verify an unpadded base64url Ed25519 signature over canonical JSON. */
export function verifyCanonical(publicKeyHex: string, message: unknown, signature: unknown): boolean {
  if (!HEX64.test(publicKeyHex) || typeof signature !== "string" || !SIGNATURE_BASE64URL.test(signature)) return false;
  let bytes: Uint8Array;
  try { bytes = base64urlnopad.decode(signature); } catch { return false; }
  try {
    return ed25519.verify(bytes, utf8ToBytes(canonical(message)), hexToBytes(publicKeyHex));
  } catch {
    return false;
  }
}
