import { InPersonAttestorsAdapter } from "./adapters/in-person-attestors.ts";
import { IssuerService } from "./issuer/service.ts";
import { errorResponse, jsonResponse, parseJsonBody, readBody } from "./shared/http.ts";
import { fail } from "./shared/errors.ts";

export type HttpHandler = (request: Request) => Promise<Response>;

export function createHttpHandler(options: Readonly<{ issuer: IssuerService; voteHandlers?: Readonly<{ handle(request: Request): Promise<Response | null> }> }>): HttpHandler {
  const issuer = options.issuer;
  return async (request) => {
    try {
      const url = new URL(request.url);
      if (url.search || url.hash) fail("request_url_invalid");
      const path = url.pathname;
      if (request.method === "GET" && path === "/v1/policy") return jsonResponse(200, issuer.policy);
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
      return jsonResponse(404, { error: "route_not_found" });
    } catch (error) { return errorResponse(error); }
  };
}
