import { exact } from "../shared/canonical.ts";
import { fail } from "../shared/errors.ts";
import { errorResponse, jsonResponse, parseJsonBody, readBody } from "../shared/http.ts";
import type { IssuerService } from "../issuer/service.ts";
import type { EudiPidAdapter } from "./eudi-pid.ts";

/** Authentication consumes the issuer's shared NIP-98 replay ledger. */
export function createEudiHttpHandlers(options: Readonly<{ issuer: IssuerService; adapter: EudiPidAdapter }>): Readonly<{ handle(request: Request): Promise<Response | null> }> {
  return {
    async handle(request) {
      const url = new URL(request.url);
      const start = request.method === "POST" && url.pathname === "/v1/eudi/requests";
      const poll = request.method === "GET" ? /^\/v1\/eudi\/requests\/([A-Za-z0-9_-]{1,256})$/u.exec(url.pathname) : null;
      if (!start && !poll) return null;
      try {
        if (url.search || url.hash) fail("request_url_invalid");
        if (options.issuer.adapter !== options.adapter) fail("eudi_adapter_configuration_invalid", 500);
        if (start) {
          if (request.headers.get("content-type")?.split(";")[0]?.trim() !== "application/json") fail("content_type_invalid", 415);
          const body = await readBody(request, 1024);
          const identity = options.issuer.authenticate(request, body);
          exact(parseJsonBody(body), [], "eudi_request_invalid");
          return jsonResponse(201, await options.adapter.start(identity.pubkey, options.issuer.clock(), request.signal));
        }
        const body = await readBody(request, 0);
        const identity = options.issuer.authenticate(request, body);
        return jsonResponse(200, await options.adapter.poll(poll![1]!, identity.pubkey, options.issuer.clock(), request.signal));
      } catch (error) { return errorResponse(error); }
    },
  };
}
