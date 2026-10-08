import type { Hex } from "./hash.ts";

/** Anonymous advisory ballot, the body of `POST /v1/elections/<electionId>/ballots`. */
export type Ballot = Readonly<{ schemaVersion: "advisory_ballot_v1"; electionId: Hex; choiceIndex: number; nullifier: Hex; signalHash: Hex; proof: Hex }>;
