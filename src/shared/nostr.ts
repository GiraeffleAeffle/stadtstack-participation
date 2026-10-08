import { utf8ToBytes } from "@noble/hashes/utils.js";
import { base64 } from "@scure/base";
import { getEventHash, validateEvent, verifyEvent, type Event as NostrEvent, type EventTemplate } from "nostr-tools/pure";
import { exact, isSafeNonNegativeInteger, sha256Hex, snapshot } from "./canonical.ts";
import { fail } from "./errors.ts";
import { HEX64 } from "./ids.ts";

export type { NostrEvent, EventTemplate };

const EVENT_KEYS = ["id", "pubkey", "created_at", "kind", "tags", "content", "sig"];
export const NIP98_KIND = 27235;

/** Validate shape and Schnorr signature of an untrusted event; returns a frozen copy. */
export function verifyNostrEvent(value: unknown, code = "event_invalid"): NostrEvent {
  const parsed = exact(snapshot(value, code), EVENT_KEYS, code);
  if (!isSafeNonNegativeInteger(parsed.created_at) || !isSafeNonNegativeInteger(parsed.kind) ||
    typeof parsed.id !== "string" || !HEX64.test(parsed.id) ||
    typeof parsed.pubkey !== "string" || !HEX64.test(parsed.pubkey) ||
    typeof parsed.sig !== "string" || !/^[0-9a-f]{128}$/u.test(parsed.sig) ||
    typeof parsed.content !== "string" || !Array.isArray(parsed.tags) || parsed.tags.length > 32 ||
    parsed.tags.some((tag) => !Array.isArray(tag) || tag.length > 8 || tag.some((entry) => typeof entry !== "string"))
  ) fail(code);
  // nostr-tools caches a verification symbol on the object it checks. Verify a
  // separate clone so neither cached state nor later mutation can be reused.
  const signed = structuredClone(parsed) as NostrEvent;
  if (!validateEvent(signed) || getEventHash(signed) !== signed.id || !verifyEvent(signed)) fail(code);
  return parsed as NostrEvent;
}

export type Nip98Request = Readonly<{
  authorization: string | null;
  method: string;
  url: string;
  body: Uint8Array;
  now: number;
  maxSkewSeconds: number;
}>;

export type Nip98Identity = Readonly<{ pubkey: string; eventId: string; createdAt: number }>;

/**
 * Verify a NIP-98 `Authorization: Nostr <base64>` header for exactly this
 * method, URL and body. Replay protection (single-use event ids) is the
 * caller's job because it needs durable storage.
 */
export function verifyNip98(request: Nip98Request): Nip98Identity {
  const header = request.authorization;
  if (typeof header !== "string" || !header.startsWith("Nostr ") || header.length > 16_384) fail("auth_required", 401);
  let decoded: unknown;
  try {
    decoded = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(base64.decode(header.slice(6))));
  } catch {
    fail("auth_invalid", 401);
  }
  let event: NostrEvent;
  try { event = verifyNostrEvent(decoded, "auth_invalid"); } catch { fail("auth_invalid", 401); }
  const expectedTags = [["u", request.url], ["method", request.method.toUpperCase()]];
  if (request.body.byteLength > 0) expectedTags.push(["payload", sha256Hex(request.body)]);
  if (event.kind !== NIP98_KIND || event.content !== "" ||
    JSON.stringify(event.tags) !== JSON.stringify(expectedTags) ||
    Math.abs(request.now - event.created_at) > request.maxSkewSeconds
  ) fail("auth_invalid", 401);
  return Object.freeze({ pubkey: event.pubkey, eventId: event.id, createdAt: event.created_at });
}

/** Unsigned NIP-98 template for a client to sign with its Nostr key. */
export function nip98Template(input: Readonly<{ url: string; method: string; body: Uint8Array; createdAt: number }>): EventTemplate {
  const tags = [["u", input.url], ["method", input.method.toUpperCase()]];
  if (input.body.byteLength > 0) tags.push(["payload", sha256Hex(input.body)]);
  return { kind: NIP98_KIND, created_at: input.createdAt, tags, content: "" };
}

/** `Authorization` header value for a signed NIP-98 event. */
export function nip98Header(event: NostrEvent): string {
  return `Nostr ${base64.encode(utf8ToBytes(JSON.stringify(event)))}`;
}
