import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";
import { fail } from "./errors.ts";

/** Canonical JSON, byte-identical to Stadtstack's: keys sorted recursively. */
export function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${canonical(record[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

export function sha256Hex(input: string | Uint8Array): string {
  return bytesToHex(sha256(typeof input === "string" ? utf8ToBytes(input) : input));
}

/** Lowercase SHA-256 hex of the UTF-8 canonical JSON. */
export function digest(value: unknown): string {
  return sha256Hex(canonical(value));
}

export type SnapshotLimits = Readonly<{
  maxBytes: number;
  maxNodes: number;
  maxDepth: number;
  maxStringBytes: number;
  maxArrayLength: number;
}>;

export const DEFAULT_SNAPSHOT_LIMITS: SnapshotLimits = Object.freeze({
  maxBytes: 262_144,
  maxNodes: 6_000,
  maxDepth: 16,
  maxStringBytes: 65_536,
  maxArrayLength: 512,
});

// Node exposes proxy detection without an import, so this module also loads in
// browsers. There it is unavailable, and the copy-once snapshot below already
// prevents a proxy from changing values between validation and use.
type NodeProcess = Readonly<{ getBuiltinModule(id: "node:util"): Readonly<{ types: Readonly<{ isProxy(value: unknown): boolean }> }> }>;

function isNodeProcess(value: unknown): value is NodeProcess {
  return typeof value === "object" && value !== null && "getBuiltinModule" in value && typeof value.getBuiltinModule === "function";
}

const runtimeProcess: unknown = Reflect.get(globalThis, "process");
const isProxy = isNodeProcess(runtimeProcess) ? runtimeProcess.getBuiltinModule("node:util").types.isProxy : undefined;

/**
 * Copy untrusted JSON-shaped data into frozen plain objects within fixed
 * limits. Getters, proxies, symbols, prototypes and non-integer numbers are
 * rejected, so later checks see exactly the data that was validated.
 */
export function snapshot(input: unknown, code = "shape_invalid", limits: SnapshotLimits = DEFAULT_SNAPSHOT_LIMITS): unknown {
  let nodes = 0;
  let bytes = 0;
  const account = (size: number) => {
    bytes += size;
    if (bytes > limits.maxBytes) fail(code);
  };
  const visit = (value: unknown, depth: number): unknown => {
    if (++nodes > limits.maxNodes || depth > limits.maxDepth) fail(code);
    account(2);
    if (value === null || typeof value === "boolean") return value;
    if (typeof value === "number") {
      if (!Number.isSafeInteger(value)) fail(code);
      return value;
    }
    if (typeof value === "string") {
      const size = utf8ToBytes(value).length;
      if (size > limits.maxStringBytes) fail(code);
      account(size);
      return value;
    }
    if (typeof value !== "object" || isProxy?.(value)) fail(code);
    const array = Array.isArray(value);
    if (Object.getPrototypeOf(value) !== (array ? Array.prototype : Object.prototype)) fail(code);
    const keys = Reflect.ownKeys(value);
    if (keys.some((key) => typeof key !== "string" || key.length > 128)) fail(code);
    const descriptors = Object.getOwnPropertyDescriptors(value);
    if (array && (value.length > limits.maxArrayLength || keys.length !== value.length + 1)) fail(code);
    const fields = array ? Array.from({ length: value.length }, (_, index) => String(index)) : (keys as string[]);
    const entries = fields.map((key) => {
      account(utf8ToBytes(key).length);
      const descriptor = descriptors[key];
      if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) fail(code);
      return [key, visit(descriptor.value, depth + 1)] as const;
    });
    return Object.freeze(array ? entries.map(([, child]) => child) : Object.fromEntries(entries));
  };
  const result = visit(input, 0);
  if (utf8ToBytes(canonical(result)).length > limits.maxBytes) fail(code);
  return result;
}

export function object(value: unknown, code = "shape_invalid"): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail(code);
  return value as Record<string, unknown>;
}

/** Require exactly these keys, no more and no fewer. */
export function exact(value: unknown, keys: readonly string[], code = "shape_invalid"): Record<string, unknown> {
  const result = object(value, code);
  if (Object.keys(result).length !== keys.length || keys.some((key) => !Object.hasOwn(result, key))) fail(code);
  return result;
}

export function isSafeNonNegativeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}
