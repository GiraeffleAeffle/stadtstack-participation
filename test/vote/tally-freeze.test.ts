import assert from "node:assert/strict";
import test from "node:test";
import { buildTally, signalHash, tallyHash, type Ballot, type ElectionMirror, type Hex } from "../../src/vote/index.ts";
import { electionFixture } from "./helpers.ts";

const provenance = { circuitSha256: "ab".repeat(32), vkHash: `0x${"cd".repeat(32)}` as Hex };

function ballot(mirror: ElectionMirror, n: number, choiceIndex = 0): Ballot {
  return { schemaVersion: "advisory_ballot_v1", electionId: mirror.electionId, choiceIndex, nullifier: `0x${n.toString(16).padStart(64, "0")}`, signalHash: signalHash(choiceIndex, mirror.scope), proof: "0x00" };
}

test("every stored ballot is counted: a stale tally is refused and a stored tally closes intake", async () => {
  const { store, mirror, chain } = await electionFixture([`0x${"00".repeat(31)}01`]);
  assert.equal(store.insertBallot(ballot(mirror, 1)), "inserted");
  assert.equal(store.insertBallot(ballot(mirror, 1)), "duplicate");
  const early = buildTally({ election: mirror, chain, ballots: store.listBallots(mirror.electionId), verifier: provenance });
  // Accepted after the tally was built, before it was stored.
  assert.equal(store.insertBallot(ballot(mirror, 2, 1)), "inserted");
  assert.throws(() => store.putTally(mirror.electionId, early, tallyHash(early)), /tally_stale/u);
  const tally = buildTally({ election: mirror, chain, ballots: store.listBallots(mirror.electionId), verifier: provenance });
  store.putTally(mirror.electionId, tally, tallyHash(tally));
  assert.deepEqual(tally.choices.map((choice) => choice.count), [1, 1]);
  assert.equal(store.insertBallot(ballot(mirror, 3)), "closed");
  assert.deepEqual(store.listBallots(mirror.electionId).length, 2);
});
