import { readFile, readdir } from "node:fs/promises";
import type { Dirent } from "node:fs";
import { join, extname } from "node:path";
import { InPersonAttestorsAdapter } from "./adapters/in-person-attestors.ts";
import { IssuerService } from "./issuer/service.ts";
import type { IssuerPolicy } from "./issuer/policy.ts";
import type { ClientConfig } from "./shared/seams.ts";
import { errorResponse, jsonResponse, parseJsonBody, readBody } from "./shared/http.ts";
import { fail } from "./shared/errors.ts";

export type HttpHandler = (request: Request) => Promise<Response>;

export function createClientConfig(policy: IssuerPolicy, environment: NodeJS.ProcessEnv): ClientConfig {
  const displayName = environment.DISPLAY_NAME?.trim();
  if (!displayName) fail("server_display_name_invalid", 500);
  const configured = [environment.CHAIN_ID, environment.REGISTRY_ADDRESS, environment.PUBLIC_RPC_URL];
  let chain: ClientConfig["chain"] = null;
  if (configured.some((value) => value !== undefined)) {
    const { CHAIN_ID: chainId, REGISTRY_ADDRESS: address, PUBLIC_RPC_URL: rpcUrl } = environment;
    if (!chainId || !/^[1-9][0-9]*$/u.test(chainId) || !Number.isSafeInteger(Number(chainId)) ||
      !address || !/^0x[0-9a-fA-F]{40}$/u.test(address) || !rpcUrl) fail("server_chain_configuration_invalid", 500);
    let url: URL;
    try { url = new URL(rpcUrl); } catch { fail("server_chain_configuration_invalid", 500); }
    const local = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
    if ((url.protocol !== "https:" && !(url.protocol === "http:" && local)) || url.username || url.password || url.hash) fail("server_chain_configuration_invalid", 500);
    chain = { chainId: Number(chainId), registryAddress: address.toLowerCase() as `0x${string}`, rpcUrl: url.href };
  }
  return { schemaVersion: "participation_client_config_v1", municipalityId: policy.municipalityId, ags: policy.ags,
    policyVersion: policy.policyVersion, displayName, publicBaseUrl: policy.publicBaseUrl, adapterKind: policy.adapter.kind,
    basis: policy.basis, attestors: policy.adapter.kind === "in_person_attestors_v1" ? policy.adapter.attestors.map(({ attestorId, publicKey }) => ({ attestorId, publicKey })) : null, chain };
}

export function setSecurityHeaders(response: Response, rpcUrl?: string): Response {
  const connect = rpcUrl ? ` 'self' ${new URL(rpcUrl).origin}` : " 'self'";
  response.headers.set("content-security-policy", `default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src${connect}; worker-src 'self' blob:; base-uri 'none'; frame-ancestors 'none'; form-action 'self'`);
  response.headers.set("cross-origin-opener-policy", "same-origin");
  response.headers.set("cross-origin-embedder-policy", "require-corp");
  response.headers.set("referrer-policy", "no-referrer");
  response.headers.set("x-content-type-options", "nosniff");
  response.headers.set("permissions-policy", "camera=(self), publickey-credentials-create=(self), publickey-credentials-get=(self), accelerometer=(), autoplay=(), bluetooth=(), browsing-topics=(), display-capture=(), encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), hid=(), idle-detection=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), screen-wake-lock=(), serial=(), usb=(), xr-spatial-tracking=()");
  return response;
}

export type OptionalHttpHandlers = Readonly<{ handle(request: Request): Promise<Response | null> }>;
const CONTENT_TYPES: Readonly<Record<string, string>> = {
  ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8",
  ".wasm": "application/wasm", ".json": "application/json", ".svg": "image/svg+xml", ".png": "image/png",
  ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".webp": "image/webp", ".ico": "image/x-icon", ".woff2": "font/woff2", ".woff": "font/woff",
  ".dat": "application/octet-stream",
};

/** Read paths from the trusted build directory once, never from a request. */
export async function createStaticHttpHandlers(directory: string, log: (message: string) => void = console.warn): Promise<OptionalHttpHandlers> {
  const files = new Map<string, Readonly<{ bytes: Uint8Array; contentType: string; cacheControl: string }>>();
  let entries: Dirent[];
  try { entries = await readdir(directory, { withFileTypes: true }); }
  catch (error) {
    if (!(error instanceof Error) || !("code" in error) || error.code !== "ENOENT") throw error;
    log("Web client dist directory is missing; API remains available.");
    entries = [];
  }
  for (const [name, route] of [["index.html", "/"], ["pruefung.html", "/pruefung"]] as const) {
    if (!entries.some((entry) => entry.name === name && entry.isFile())) continue;
    files.set(route, { bytes: await readFile(join(directory, name)), contentType: CONTENT_TYPES[".html"]!, cacheControl: "no-store" });
  }
  async function loadAssets(assetDirectory: string, routePrefix: string): Promise<void> {
    for (const entry of await readdir(assetDirectory, { withFileTypes: true })) {
      if (!/^[a-zA-Z0-9_.-]+$/u.test(entry.name)) continue;
      const path = join(assetDirectory, entry.name);
      const route = `${routePrefix}/${entry.name}`;
      if (entry.isDirectory()) { await loadAssets(path, route); continue; }
      if (!entry.isFile()) continue;
      const type = CONTENT_TYPES[extname(entry.name)];
      if (!type) continue;
      files.set(route, { bytes: await readFile(path), contentType: type,
        cacheControl: /[-.][a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9]+$/u.test(entry.name) ? "public, max-age=31536000, immutable" : "no-store" });
    }
  }
  if (entries.some((entry) => entry.name === "assets" && entry.isDirectory())) await loadAssets(join(directory, "assets"), "/assets");
  return { async handle(request) {
    if (request.method !== "GET" && request.method !== "HEAD") return null;
    const file = files.get(new URL(request.url).pathname);
    return file ? new Response(request.method === "HEAD" ? null : file.bytes as BodyInit, { headers: { "content-type": file.contentType, "cache-control": file.cacheControl } }) : null;
  } };
}

export function createHttpHandler(options: Readonly<{ issuer: IssuerService; clientConfig?: ClientConfig; voteHandlers?: OptionalHttpHandlers; eudiHandlers?: OptionalHttpHandlers; staticHandlers?: OptionalHttpHandlers }>): HttpHandler {
  const issuer = options.issuer;
  const route: HttpHandler = async (request) => {
    try {
      const url = new URL(request.url);
      if (url.search || url.hash) fail("request_url_invalid");
      const path = url.pathname;
      if (request.method === "GET" && path === "/v1/policy") return jsonResponse(200, issuer.policy);
      if ((request.method === "GET" || request.method === "HEAD") && path === "/healthz") return jsonResponse(200, { ok: true });
      if (request.method === "GET" && path === "/v1/client-config" && options.clientConfig) return jsonResponse(200, options.clientConfig);
      if (request.method === "GET" && path === "/v1/eligibility/me") {
        return jsonResponse(200, await issuer.eligibilityMe(issuer.authenticate(request, new Uint8Array(0)), request.signal));
      }
      const eudi = await options.eudiHandlers?.handle(request);
      if (eudi) return eudi;
      const status = /^\/v1\/eligibility\/status\/([^/]+)$/u.exec(path);
      if (request.method === "GET" && status) return jsonResponse(200, await issuer.status(status[1]!, request.headers.get("x-stadtstack-status-nonce"), request.signal));
      const adoption = /^\/v1\/adoptions\/([^/]+)$/u.exec(path);
      if (request.method === "GET" && adoption) return jsonResponse(200, issuer.adoption(adoption[1]!));
      if (request.method === "POST" && ["/v1/eligibility/receipts", "/v1/identity-commitments", "/v1/adoptions", "/v1/attestations", "/v1/attestation-revocations"].includes(path)) {
        if (request.headers.get("content-type")?.split(";")[0]?.trim() !== "application/json") fail("content_type_invalid", 415);
        const body = await readBody(request, 262144);
        if (path === "/v1/eligibility/receipts" || path === "/v1/identity-commitments") {
          const identity = issuer.authenticate(request, body);
          const parsed = parseJsonBody(body);
          return jsonResponse(201, path === "/v1/eligibility/receipts" ? await issuer.issueReceipt(parsed, identity, request.signal) : await issuer.enroll(parsed, identity, request.signal));
        }
        const parsed = parseJsonBody(body);
        if (path === "/v1/adoptions") return jsonResponse(201, issuer.acceptAdoption(parsed));
        if (!(issuer.adapter instanceof InPersonAttestorsAdapter)) fail("attestor_adapter_unavailable", 404);
        return jsonResponse(201, path === "/v1/attestations" ? issuer.adapter.recordAttestation(parsed, issuer.clock()) : issuer.adapter.recordRevocation(parsed, issuer.clock()));
      }
      const vote = await options.voteHandlers?.handle(request);
      if (vote) return vote;
      const staticResponse = await options.staticHandlers?.handle(request);
      if (staticResponse) return staticResponse;
      return jsonResponse(404, { error: "route_not_found" });
    } catch (error) { return errorResponse(error); }
  };
  return async (request) => setSecurityHeaders(await route(request), options.clientConfig?.chain?.rpcUrl);
}
