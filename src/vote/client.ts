import { fail } from "../shared/errors.ts";
import type { Ballot } from "./ballot.ts";

/** The transport never attaches ambient cookies, follows redirects or caches ballots. */
export async function submitBallot(baseUrl: string, ballot: Ballot, fetcher: typeof fetch = fetch): Promise<Readonly<{ ok: true }> | Readonly<{ ok: false; code: string }>> {
  const response = await fetcher(`${baseUrl.replace(/\/$/u, "")}/v1/elections/${ballot.electionId}/ballots`, { method: "POST", credentials: "omit", cache: "no-store", redirect: "error", headers: { "content-type": "application/json" }, body: JSON.stringify(ballot) });
  const value: unknown = await response.json();
  if (!value || typeof value !== "object") fail("ballot_response_invalid");
  const result = value as Record<string, unknown>;
  if (response.ok && result.ok === true && Object.keys(result).length === 1) return { ok: true };
  if (result.ok === false && typeof result.code === "string" && Object.keys(result).length === 2) return { ok: false, code: result.code };
  fail("ballot_response_invalid");
}
