import assert from "node:assert/strict";
import test from "node:test";
import { BallotIntake, createVoteHttpHandlers, fieldHex, identityCommitment, signalHash, submitBallot, type Ballot, type BallotVerifier } from "../../src/vote/index.ts";
import { electionFixture } from "./helpers.ts";

function ballotFor(id: Ballot["electionId"], scope: Ballot["signalHash"], nullifier = 1n): Ballot {
  return { schemaVersion: "advisory_ballot_v1", electionId: id, choiceIndex: 0, nullifier: fieldHex(nullifier), signalHash: signalHash(0, scope), proof: "0x0102" };
}

test("token bucket runs after cheap validation, is per client, and refills in memory", async (t) => {
  const fixture = await electionFixture([identityCommitment(1n)]);
  t.after(() => fixture.db.close());
  let now = 100;
  let verifies = 0;
  const verifier: BallotVerifier = { async verify() { verifies++; return false; } };
  const intake = new BallotIntake({ store: fixture.store, verifier, clock: () => now, rateLimit: { capacity: 1, refillPerSecond: 1 } });
  const ballot = ballotFor(fixture.mirror.electionId, fixture.mirror.scope);
  await assert.rejects(intake.accept({ ...ballot, signalHash: fieldHex(1n) }, "alice"), /signal_mismatch/u);
  await assert.rejects(intake.accept({ ...ballot, choiceIndex: 8 }, "alice"), /choice_invalid/u);
  await assert.rejects(intake.accept({ ...ballot, nullifier: fieldHex(0n) }, "alice"), /field_invalid/u);
  assert.equal(verifies, 0);
  await assert.rejects(intake.accept(ballot, "alice"), /proof_invalid/u);
  await assert.rejects(intake.accept(ballot, "alice"), /rate_limited/u);
  await assert.rejects(intake.accept(ballot, "bob"), /proof_invalid/u);
  now++;
  await assert.rejects(intake.accept(ballot, "alice"), /proof_invalid/u);
  assert.equal(verifies, 3);
  const columns = fixture.db.prepare("PRAGMA table_info(vote_ballots)").all().map((row) => row.name);
  assert.deepEqual(columns, ["election_id", "nullifier", "choice_index", "signal_hash", "proof"]);
});

test("global verification cap rejects concurrent work before cryptography and releases on failure", async (t) => {
  const fixture = await electionFixture([identityCommitment(1n)]);
  t.after(() => fixture.db.close());
  let resolve!: (value: boolean) => void;
  let verifies = 0;
  const verifier: BallotVerifier = { verify() { verifies++; return new Promise<boolean>((done) => { resolve = done; }); } };
  const intake = new BallotIntake({ store: fixture.store, verifier, clock: () => 100, maxConcurrentVerifications: 1 });
  const ballot = ballotFor(fixture.mirror.electionId, fixture.mirror.scope);
  const first = assert.rejects(intake.accept(ballot, "alice"), /proof_invalid/u);
  await assert.rejects(intake.accept(ballot, "bob"), /verification_busy/u);
  assert.equal(verifies, 1);
  resolve(false);
  await first;
  const later = assert.rejects(intake.accept(ballot, "bob"), /proof_invalid/u);
  resolve(false);
  await later;
  assert.equal(verifies, 2);
});

test("SQLite UNIQUE decides two verified ballots racing for the same nullifier", async (t) => {
  const fixture = await electionFixture([identityCommitment(1n)]);
  t.after(() => fixture.db.close());
  const completions: ((value: boolean) => void)[] = [];
  const intake = new BallotIntake({ store: fixture.store, verifier: { verify() { return new Promise<boolean>((resolve) => completions.push(resolve)); } }, clock: () => 100, maxConcurrentVerifications: 2 });
  const ballot = ballotFor(fixture.mirror.electionId, fixture.mirror.scope);
  const first = intake.accept(ballot, "alice");
  const second = assert.rejects(intake.accept(ballot, "bob"), /duplicate_nullifier/u);
  assert.equal(completions.length, 2);
  completions[0]!(true);
  await first;
  completions[1]!(true);
  await second;
  assert.equal(fixture.store.listBallots(ballot.electionId).length, 1);
});

test("four framework-free election endpoints bound JSON and never cache or set cookies", async (t) => {
  const fixture = await electionFixture([identityCommitment(1n)]);
  t.after(() => fixture.db.close());
  const handlers = createVoteHttpHandlers({ store: fixture.store, verifier: { async verify() { return false; } }, clock: () => 100 });
  const base = `https://issuer.test/v1/elections/${fixture.mirror.electionId}`;
  for (const path of [base, `${base}/anchor`]) {
    const response = await handlers.handle(new Request(path));
    assert.equal(response?.status, 200);
    assert.equal(response?.headers.get("cache-control"), "no-store");
    assert.equal(response?.headers.has("set-cookie"), false);
  }
  assert.equal((await handlers.handle(new Request(`${base}/tally`)))?.status, 409);
  assert.equal(await handlers.handle(new Request("https://issuer.test/other")), null);
  const post = (body: string) => new Request(`${base}/ballots`, { method: "POST", headers: { "content-type": "application/json" }, body });
  assert.equal((await handlers.handle(post(" ".repeat(32769))))?.status, 413);
  assert.equal((await handlers.handle(post("{}")))?.status, 400);
  const ballot = ballotFor(fixture.mirror.electionId, fixture.mirror.scope);
  assert.deepEqual(await (await handlers.handle(post(JSON.stringify(ballot))))!.json(), { ok: false, code: "proof_invalid" });
  assert.equal((await handlers.handle(post(JSON.stringify({ ...ballot, timestamp: 100 }))))?.status, 400);
});

test("ballot fetch omits credentials, disables caching and rejects redirects", async () => {
  const ballot = ballotFor(`0x${"1".repeat(64)}`, fieldHex(2n));
  const fetcher: typeof fetch = async (url, options) => {
    assert.equal(String(url), `https://issuer.test/v1/elections/${ballot.electionId}/ballots`);
    assert.equal(options?.credentials, "omit");
    assert.equal(options?.cache, "no-store");
    assert.equal(options?.redirect, "error");
    return new Response(JSON.stringify({ ok: true }), { status: 200 });
  };
  assert.deepEqual(await submitBallot("https://issuer.test", ballot, fetcher), { ok: true });
});
