import { canonical, exact, snapshot } from "../shared/canonical.ts";
import { fail } from "../shared/errors.ts";
import { isBytes32 } from "../shared/ids.ts";
import type { Clock } from "../shared/seams.ts";
import { signalHash } from "./election.ts";
import { parseField, proofBytes, type Hex } from "./hash.ts";
import type { VoteStore } from "./store.ts";
import type { BallotVerifier } from "./verifier.ts";

export type Ballot = Readonly<{ schemaVersion: "advisory_ballot_v1"; electionId: Hex; choiceIndex: number; nullifier: Hex; signalHash: Hex; proof: Hex }>;
export type IntakeOptions = Readonly<{ store: VoteStore; verifier: BallotVerifier; clock: Clock; rateLimit?: Readonly<{ capacity: number; refillPerSecond: number }>; maxConcurrentVerifications?: number }>;

export function validateBallot(input: unknown): Ballot {
  const value = exact(snapshot(input, "ballot_invalid"), ["schemaVersion", "electionId", "choiceIndex", "nullifier", "signalHash", "proof"], "ballot_invalid");
  if (Buffer.byteLength(canonical(value), "utf8") > 32768) fail("body_too_large", 413);
  if (value.schemaVersion !== "advisory_ballot_v1" || !isBytes32(value.electionId) || !isBytes32(value.nullifier) || !isBytes32(value.signalHash) || !Number.isInteger(value.choiceIndex) || (value.choiceIndex as number) < 0 || (value.choiceIndex as number) > 255 || typeof value.proof !== "string" || !/^0x(?:[0-9a-f]{2})+$/u.test(value.proof)) fail("ballot_invalid");
  return value as Ballot;
}

export class BallotIntake {
  readonly options: IntakeOptions;
  readonly capacity: number;
  readonly refillPerSecond: number;
  readonly maxConcurrent: number;
  private readonly buckets = new Map<string, { tokens: number; at: number }>();
  private concurrent = 0;

  constructor(options: IntakeOptions) {
    this.options = options;
    this.capacity = options.rateLimit?.capacity ?? 5;
    this.refillPerSecond = options.rateLimit?.refillPerSecond ?? 0.1;
    this.maxConcurrent = options.maxConcurrentVerifications ?? 2;
    if (!Number.isInteger(this.capacity) || this.capacity < 1 || !Number.isFinite(this.refillPerSecond) || this.refillPerSecond <= 0 || !Number.isInteger(this.maxConcurrent) || this.maxConcurrent < 1) fail("intake_options_invalid");
  }

  async accept(input: unknown, clientKey: string): Promise<void> {
    const ballot = validateBallot(input);
    const { store, verifier, clock } = this.options;
    const election = store.getElection(ballot.electionId);
    if (!election) fail("election_unknown", 404);
    const now = clock();
    if (election.state !== "open" || now < election.opensAt || now >= election.closesAt) fail("election_not_open", 409);
    if (!election.metadata.choices.some((choice) => choice.index === ballot.choiceIndex)) fail("choice_invalid");
    if (ballot.signalHash !== signalHash(ballot.choiceIndex, election.scope)) fail("signal_mismatch");
    parseField(ballot.nullifier, true);
    // Cheap validation precedes both admission controls. Keys never enter SQLite.
    for (const [key, bucket] of this.buckets) if (now - bucket.at >= this.capacity / this.refillPerSecond) this.buckets.delete(key);
    const prior = this.buckets.get(clientKey);
    const tokens = prior ? Math.min(this.capacity, prior.tokens + Math.max(0, now - prior.at) * this.refillPerSecond) : this.capacity;
    if (tokens < 1) fail("rate_limited", 429);
    this.buckets.set(clientKey, { tokens: tokens - 1, at: now });
    if (this.concurrent >= this.maxConcurrent) fail("verification_busy", 503);
    if (store.hasNullifier(ballot.electionId, ballot.nullifier)) fail("duplicate_nullifier", 409);
    this.concurrent++;
    try {
      if (!await verifier.verify(proofBytes(ballot.proof), [election.anchorRoot, ballot.nullifier, election.scope, ballot.signalHash])) fail("proof_invalid");
      if (!store.insertBallot(ballot)) fail("duplicate_nullifier", 409);
    } finally {
      this.concurrent--;
    }
  }
}
