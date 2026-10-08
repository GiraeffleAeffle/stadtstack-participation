import { snapshot } from "./canonical.ts";
import { fail, isCodedError } from "./errors.ts";

const HEADERS = Object.freeze({ "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });

/** JSON response without cookies or caching. */
export function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: HEADERS });
}

/** Map coded errors to their status; anything else is an opaque 500. */
export function errorResponse(error: unknown): Response {
  if (isCodedError(error)) return jsonResponse(error.status, { error: error.code });
  return jsonResponse(500, { error: "internal_error" });
}

/** Read at most `maxBytes` of the request body without trusting Content-Length. */
export async function readBody(request: Request, maxBytes: number): Promise<Uint8Array> {
  if (!request.body) return new Uint8Array(0);
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const chunk = await reader.read();
      if (chunk.done) break;
      size += chunk.value.byteLength;
      if (size > maxBytes) fail("body_too_large", 413);
      chunks.push(chunk.value);
    }
  } finally {
    await reader.cancel().catch(() => {});
  }
  return new Uint8Array(Buffer.concat(chunks));
}

/** Parse UTF-8 JSON into a bounded frozen snapshot. */
export function parseJsonBody(bytes: Uint8Array, code = "body_invalid"): unknown {
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    fail(code);
  }
  return snapshot(parsed, code);
}
