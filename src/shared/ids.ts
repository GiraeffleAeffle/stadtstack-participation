export const HEX64 = /^[0-9a-f]{64}$/u;
export const SLUG = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
export const POLICY_VERSION = /^[a-z0-9][a-z0-9._-]{2,99}$/u;
export const AGS = /^[0-9]{8}$/u;
export const KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$/u;
export const BYTES32 = /^0x[0-9a-f]{64}$/u;
export const EVM_ADDRESS = /^0x[0-9a-f]{40}$/u;

export function isHex64(value: unknown): value is string {
  return typeof value === "string" && HEX64.test(value);
}

export function isMunicipalityId(value: unknown): value is string {
  return typeof value === "string" && SLUG.test(value);
}

export function isPolicyVersion(value: unknown): value is string {
  return typeof value === "string" && POLICY_VERSION.test(value);
}

export function isAgs(value: unknown): value is string {
  return typeof value === "string" && AGS.test(value);
}

export function isBytes32(value: unknown): value is `0x${string}` {
  return typeof value === "string" && BYTES32.test(value);
}

export function topicIdPrefix(municipalityId: string): string {
  return `urn:stadtstack:topic:municipality:${municipalityId}:`;
}

/** True for `urn:stadtstack:topic:municipality:<municipalityId>:<slug>`. */
export function isTopicIdFor(value: unknown, municipalityId: string): value is string {
  if (typeof value !== "string" || !value.startsWith(topicIdPrefix(municipalityId))) return false;
  const parts = value.split(":");
  return parts.length === 6 && SLUG.test(parts[5]!);
}

/** HTTPS origin URL with no credentials, path, query, fragment or trailing slash. */
export function isHttpsOrigin(value: unknown): value is string {
  if (typeof value !== "string" || value.length > 2_048) return false;
  let url: URL;
  try { url = new URL(value); } catch { return false; }
  return url.protocol === "https:" && !url.username && !url.password && !url.search && !url.hash &&
    url.pathname === "/" && !value.endsWith("/") && url.origin === value;
}
