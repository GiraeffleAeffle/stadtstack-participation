import { fail, isCodedError } from "../shared/errors.ts";
import { errorResponse, jsonResponse, parseJsonBody, readBody } from "../shared/http.ts";
import { isBytes32 } from "../shared/ids.ts";
import { BallotIntake, validateBallot, type IntakeOptions } from "./intake.ts";

export type VoteHttpOptions = IntakeOptions & Readonly<{ clientKey?: (request: Request) => string }>;

export function createVoteHttpHandlers(options: VoteHttpOptions): Readonly<{ handle(request: Request): Promise<Response | null> }> {
  const intake = new BallotIntake(options);
  return {
    async handle(request: Request): Promise<Response | null> {
      if (request.method === "GET" && new URL(request.url).pathname === "/v1/elections") {
        return jsonResponse(200, { elections: options.store.listElections() });
      }
      const match = /^\/v1\/elections\/([^/]+)(?:\/(anchor|ballots|tally))?$/u.exec(new URL(request.url).pathname);
      if (!match || (request.method !== "GET" && request.method !== "POST") || (match[2] === "ballots" ? request.method !== "POST" : request.method !== "GET")) return null;
      const ballots = match[2] === "ballots";
      try {
        const id = match[1];
        if (!isBytes32(id)) fail("election_id_invalid");
        if (ballots) {
          if (request.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase() !== "application/json") fail("content_type_invalid", 415);
          const body = validateBallot(parseJsonBody(await readBody(request, 32768), "ballot_invalid"));
          if (body.electionId !== id) fail("election_id_mismatch");
          await intake.accept(body, options.clientKey?.(request) ?? "anonymous");
          return jsonResponse(200, { ok: true });
        }
        const election = options.store.getElection(id);
        if (!election) fail("election_unknown", 404);
        if (!match[2]) return jsonResponse(200, election);
        if (match[2] === "anchor") return jsonResponse(200, options.store.getAnchor(id));
        if (options.clock() < election.closesAt) fail("tally_not_closed", 409);
        const tally = options.store.getTally(id);
        if (!tally) fail("tally_unavailable", 404);
        return jsonResponse(200, tally);
      } catch (error) {
        if (ballots) return jsonResponse(isCodedError(error) ? error.status : 500, { ok: false, code: isCodedError(error) ? error.code : "internal_error" });
        return errorResponse(error);
      }
    },
  };
}
