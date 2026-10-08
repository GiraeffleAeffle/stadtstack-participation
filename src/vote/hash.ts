import { permute } from "@zkpassport/poseidon2";
import { fail } from "../shared/errors.ts";
import { isBytes32 } from "../shared/ids.ts";

export const FIELD_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
export type Hex = `0x${string}`;
export const DOMAINS = Object.freeze({ identity: 1n, merkle: 2n, nullifier: 3n, scope: 4n, signal: 5n });

export function assertField(value: bigint, nonzero = false): void {
  if (typeof value !== "bigint" || value < (nonzero ? 1n : 0n) || value >= FIELD_MODULUS) fail("field_invalid");
}

/** Circuit compression, including the domain tag in the permutation state. */
export function h(a: bigint, b: bigint, domain: bigint): bigint {
  assertField(a);
  assertField(b);
  assertField(domain);
  return permute([a, b, domain, 0n])[0]!;
}

export function fieldHex(value: bigint): Hex {
  assertField(value);
  return `0x${value.toString(16).padStart(64, "0")}`;
}

export function parseField(value: unknown, nonzero = false): bigint {
  if (!isBytes32(value)) fail("field_invalid");
  const field = BigInt(value);
  assertField(field, nonzero);
  return field;
}

export function identityCommitment(secret: bigint): Hex {
  assertField(secret, true);
  return fieldHex(h(secret, 0n, DOMAINS.identity));
}

export function proofBytes(value: string): Uint8Array {
  if (!/^0x(?:[0-9a-f]{2})+$/u.test(value)) fail("proof_invalid");
  const bytes = new Uint8Array((value.length - 2) / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = Number.parseInt(value.slice(2 + i * 2, 4 + i * 2), 16);
  return bytes;
}

export function bytesHex(bytes: Uint8Array): Hex {
  return `0x${Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}
