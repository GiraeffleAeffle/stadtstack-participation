import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { request as httpRequest, type IncomingHttpHeaders } from "node:http";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createClientConfig, createHttpHandler, createStaticHttpHandlers } from "../../src/http.ts";
import { startServer, type ServerRuntime } from "../../src/server.ts";
import { policyInput, setup } from "../issuer/fixtures.ts";

const SECURITY_HEADERS: Readonly<Record<string, string>> = {
  "cross-origin-opener-policy": "same-origin", "cross-origin-embedder-policy": "require-corp",
  "referrer-policy": "no-referrer", "x-content-type-options": "nosniff",
};

function rawResponse(port: number, path: string): Promise<Readonly<{ status: number; headers: IncomingHttpHeaders; body: string }>> {
  const { promise, resolve, reject } = Promise.withResolvers<Readonly<{ status: number; headers: IncomingHttpHeaders; body: string }>>();
  const request = httpRequest({ host: "127.0.0.1", port, path, method: "GET" }, (response) => {
    let body = "";
    response.setEncoding("utf8"); response.on("data", (chunk: string) => { body += chunk; });
    response.on("end", () => resolve({ status: response.statusCode!, headers: response.headers, body }));
    response.on("error", reject);
  });
  request.on("error", reject); request.end();
  return promise;
}
test("static clients and hashed assets have correct media types, isolation, CSP and caching", async () => {
  const directory = await mkdtemp(join(tmpdir(), "stadtstack-web-"));
  const c = setup();
  try {
    await mkdir(join(directory, "assets"));
    await writeFile(join(directory, "index.html"), "<!doctype html><title>Mitmachen</title>");
    await writeFile(join(directory, "pruefung.html"), "<!doctype html><title>Prüfung</title>");
    await writeFile(join(directory, "assets", "client-AbCdef12.js"), "console.log('app');");
    await writeFile(join(directory, "assets", "proof-AbCdef12.wasm"), new Uint8Array([0, 97, 115, 109]));
    await writeFile(join(directory, "assets", "styles-AbCdef12.css"), "body{color:black}");
    await mkdir(join(directory, "assets", "crs"));
    await writeFile(join(directory, "assets", "crs", "g1.dat"), new Uint8Array([1, 2, 3]));
    await writeFile(join(directory, "assets", "membership_vote-AbCdef12.json"), "{}");
    const config = createClientConfig(c.policy, { DISPLAY_NAME: "Beispielstadt", OPERATOR_NAME: "Stadtstack", CHAIN_ID: "10200", REGISTRY_ADDRESS: `0x${"11".repeat(20)}`, PUBLIC_RPC_URL: "https://rpc.chiadochain.net/path" });
    const handle = createHttpHandler({ issuer: c.issuer, clientConfig: config, staticHandlers: await createStaticHttpHandlers(directory) });
    for (const [path, contentType, cacheControl] of [["/", "text/html; charset=utf-8", "no-store"], ["/pruefung", "text/html; charset=utf-8", "no-store"],
      ["/assets/client-AbCdef12.js", "text/javascript; charset=utf-8", "public, max-age=31536000, immutable"],
      ["/assets/proof-AbCdef12.wasm", "application/wasm", "public, max-age=31536000, immutable"],
      ["/assets/styles-AbCdef12.css", "text/css; charset=utf-8", "public, max-age=31536000, immutable"],
      ["/assets/membership_vote-AbCdef12.json", "application/json", "public, max-age=31536000, immutable"],
      ["/assets/crs/g1.dat", "application/octet-stream", "no-store"]] as const) {
      const response = await handle(new Request(`https://eligibility.example${path}`));
      assert.equal(response.status, 200); assert.equal(response.headers.get("content-type"), contentType); assert.equal(response.headers.get("cache-control"), cacheControl);
      for (const [name, value] of Object.entries(SECURITY_HEADERS)) assert.equal(response.headers.get(name), value);
      assert.match(response.headers.get("content-security-policy")!, /connect-src 'self' https:\/\/rpc\.chiadochain\.net;/u);
      assert.match(response.headers.get("content-security-policy")!, /script-src 'self' 'wasm-unsafe-eval'/u);
      assert.match(response.headers.get("permissions-policy")!, /camera=\(self\)/u);
      assert.match(response.headers.get("permissions-policy")!, /publickey-credentials-get=\(self\)/u);
      assert.equal(response.headers.get("set-cookie"), null);
    }
    // Monitors probe with HEAD: same status and headers, no body.
    const head = await handle(new Request("https://eligibility.example/", { method: "HEAD" }));
    assert.equal(head.status, 200); assert.equal(head.headers.get("content-type"), "text/html; charset=utf-8"); assert.equal((await head.arrayBuffer()).byteLength, 0);
    // Assets created after startup are not added to the allowlist.
    await writeFile(join(directory, "assets", "late-AbCdef12.js"), "unexpected");
    for (const path of ["/unknown", "/assets/unknown.js", "/assets/late-AbCdef12.js", "/assets/%63lient-AbCdef12.js", "/index.html"]) {
      const response = await handle(new Request(`https://eligibility.example${path}`));
      assert.equal(response.status, 404); assert.equal(response.headers.get("referrer-policy"), "no-referrer");
    }
    const api = await handle(new Request("https://eligibility.example/v1/policy"));
    assert.equal(api.status, 200); assert.equal(api.headers.get("cache-control"), "no-store");
  } finally { c.db.close(); await rm(directory, { recursive: true, force: true }); }
});

test("missing dist logs once and preserves API, health and security headers while HTML is 404", async () => {
  const directory = await mkdtemp(join(tmpdir(), "stadtstack-missing-"));
  const c = setup();
  try {
    const logs: string[] = [];
    const staticHandlers = await createStaticHttpHandlers(join(directory, "missing"), (message) => logs.push(message));
    const handle = createHttpHandler({ issuer: c.issuer, staticHandlers });
    for (const path of ["/", "/pruefung", "/assets/app-abcdefgh.js"]) {
      const response = await handle(new Request(`https://eligibility.example${path}`));
      assert.equal(response.status, 404); assert.equal(response.headers.get("x-content-type-options"), "nosniff");
    }
    assert.equal(logs.length, 1);
    const before = c.db.prepare("SELECT COUNT(*) AS count FROM issuer_auth_events").get()!.count;
    const health = await handle(new Request("https://eligibility.example/healthz"));
    assert.equal(health.status, 200); assert.deepEqual(await health.json(), { ok: true });
    assert.equal(c.db.prepare("SELECT COUNT(*) AS count FROM issuer_auth_events").get()!.count, before);
    assert.equal((await handle(new Request("https://eligibility.example/v1/policy"))).status, 200);
  } finally { c.db.close(); await rm(directory, { recursive: true, force: true }); }
});

test("server rejects raw and encoded traversal before URL normalization including security headers", async () => {
  const directory = await mkdtemp(join(tmpdir(), "stadtstack-traversal-"));
  let runtime: ServerRuntime | undefined;
  try {
    await mkdir(join(directory, "dist", "assets"), { recursive: true });
    await writeFile(join(directory, "dist", "index.html"), "participant");
    await writeFile(join(directory, "dist", "pruefung.html"), "attestor");
    await writeFile(join(directory, "dist", "assets", "app-abcdefgh.js"), "safe");
    await writeFile(join(directory, "policy.json"), JSON.stringify(policyInput()));
    runtime = await startServer({ POLICY_PATH: join(directory, "policy.json"), DATABASE_PATH: ":memory:", DISPLAY_NAME: "Stadt", OPERATOR_NAME: "Stadtstack", ISSUER_SIGNING_KEY_SEED_HEX: "51".repeat(32),
      PORT: "0", WEB_DIST_DIR: join(directory, "dist") });
    const address = runtime.server.address(); assert.ok(address && typeof address !== "string");
    for (const path of ["/assets/../", "/assets/%2e%2e/", "/assets/%2E%2E/pruefung", "/assets/%2e%2e%2f", "/assets/..%5cindex.html", "/assets/%252e%252e/index.html", "/assets/%61pp-abcdefgh.js", "/assets/unknown.js", "/missing"]) {
      const response = await rawResponse(address.port, path);
      assert.equal(response.status, 404, path); assert.equal(response.headers["cross-origin-opener-policy"], "same-origin", path);
      assert.deepEqual(JSON.parse(response.body), { error: "route_not_found" });
    }
    assert.equal((await rawResponse(address.port, "/")).body, "participant");
    assert.equal((await rawResponse(address.port, "/pruefung")).body, "attestor");
    assert.equal((await rawResponse(address.port, "/assets/app-abcdefgh.js")).body, "safe");
    assert.equal((await rawResponse(address.port, "/healthz")).status, 200);
  } finally { await runtime?.close(); await rm(directory, { recursive: true, force: true }); }
});
