import type { DatabaseSync } from "node:sqlite";
import { canonical, digest, isSafeNonNegativeInteger } from "../shared/canonical.ts";
import { fail } from "../shared/errors.ts";
import type { CommitmentLock } from "../shared/seams.ts";
import type { ElectionAnchor } from "./anchor.ts";
import { electionScope, metadataHash, validateMetadata, type ElectionMetadata } from "./election.ts";
import { parseField, type Hex } from "./hash.ts";
import { buildMerkleTree } from "./merkle.ts";
import { assertElectionMatchesChain, type ChainElection, type ElectionMirror } from "./registry-client.ts";
import type { Ballot } from "./intake.ts";
import type { Tally } from "./tally.ts";

export function migrate(db: DatabaseSync): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS vote_elections (
      election_id TEXT PRIMARY KEY, municipality_id TEXT NOT NULL,
      mirror_json TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('draft','open','closed')),
      opened INTEGER NOT NULL DEFAULT 0 CHECK(opened IN (0,1)),
      opens_at INTEGER NOT NULL, closes_at INTEGER NOT NULL
    ) STRICT;
    CREATE TABLE IF NOT EXISTS vote_anchors (
      election_id TEXT PRIMARY KEY REFERENCES vote_elections(election_id), anchor_json TEXT NOT NULL
    ) STRICT;
    CREATE TABLE IF NOT EXISTS vote_anchor_leaves (
      election_id TEXT NOT NULL REFERENCES vote_anchors(election_id), commitment TEXT NOT NULL,
      PRIMARY KEY(election_id,commitment)
    ) STRICT;
    CREATE TABLE IF NOT EXISTS vote_ballots (
      election_id TEXT NOT NULL REFERENCES vote_elections(election_id),
      nullifier TEXT NOT NULL, choice_index INTEGER NOT NULL, signal_hash TEXT NOT NULL, proof TEXT NOT NULL,
      UNIQUE(election_id,nullifier)
    ) STRICT;
    CREATE TABLE IF NOT EXISTS vote_tallies (
      election_id TEXT PRIMARY KEY REFERENCES vote_elections(election_id), tally_hash TEXT NOT NULL, tally_json TEXT NOT NULL
    ) STRICT;
    CREATE TRIGGER IF NOT EXISTS vote_anchor_immutable_update BEFORE UPDATE ON vote_anchors
      WHEN (SELECT opened FROM vote_elections WHERE election_id=OLD.election_id)=1
      BEGIN SELECT RAISE(ABORT,'anchor_immutable'); END;
    CREATE TRIGGER IF NOT EXISTS vote_anchor_immutable_delete BEFORE DELETE ON vote_anchors
      WHEN (SELECT opened FROM vote_elections WHERE election_id=OLD.election_id)=1
      BEGIN SELECT RAISE(ABORT,'anchor_immutable'); END;
    CREATE TRIGGER IF NOT EXISTS vote_leaf_immutable_insert BEFORE INSERT ON vote_anchor_leaves
      WHEN (SELECT opened FROM vote_elections WHERE election_id=NEW.election_id)=1
      BEGIN SELECT RAISE(ABORT,'anchor_immutable'); END;
    CREATE TRIGGER IF NOT EXISTS vote_leaf_immutable_update BEFORE UPDATE ON vote_anchor_leaves
      WHEN (SELECT opened FROM vote_elections WHERE election_id=OLD.election_id)=1
      BEGIN SELECT RAISE(ABORT,'anchor_immutable'); END;
    CREATE TRIGGER IF NOT EXISTS vote_leaf_immutable_delete BEFORE DELETE ON vote_anchor_leaves
      WHEN (SELECT opened FROM vote_elections WHERE election_id=OLD.election_id)=1
      BEGIN SELECT RAISE(ABORT,'anchor_immutable'); END;
    CREATE TRIGGER IF NOT EXISTS vote_election_no_reopen BEFORE UPDATE ON vote_elections
      WHEN OLD.opened=1 AND (NEW.opened!=1 OR (OLD.state='closed' AND NEW.state!='closed') OR NEW.election_id!=OLD.election_id OR NEW.municipality_id!=OLD.municipality_id OR NEW.opens_at!=OLD.opens_at OR NEW.closes_at!=OLD.closes_at)
      BEGIN SELECT RAISE(ABORT,'election_immutable'); END;
    CREATE TRIGGER IF NOT EXISTS vote_ballot_no_update BEFORE UPDATE ON vote_ballots BEGIN SELECT RAISE(ABORT,'ballot_immutable'); END;
    CREATE TRIGGER IF NOT EXISTS vote_ballot_no_delete BEFORE DELETE ON vote_ballots BEGIN SELECT RAISE(ABORT,'ballot_immutable'); END;
  `);
}

export class VoteStore implements CommitmentLock {
  readonly db: DatabaseSync;

  constructor(db: DatabaseSync) {
    this.db = db;
    migrate(db);
  }

  putElection(metadataInput: ElectionMetadata, anchor: ElectionAnchor): ElectionMirror {
    const metadata = validateMetadata(metadataInput);
    const existing = this.getElection(metadata.electionId);
    if (existing && existing.state !== "draft") fail("anchor_immutable", 409);
    const tree = buildMerkleTree(anchor.leaves);
    if (anchor.schemaVersion !== "advisory_election_anchor_v1" || anchor.electionId !== metadata.electionId || anchor.municipalityId !== metadata.municipalityId || anchor.policyVersion !== metadata.policyVersion || anchor.treeDepth !== 16 || anchor.root !== tree.root || anchor.leaves.some((leaf, index) => leaf !== tree.leaves[index]) || !isSafeNonNegativeInteger(anchor.anchoredAt)) fail("anchor_invalid");
    parseField(anchor.root, true);
    const mirror: ElectionMirror = { electionId: metadata.electionId, metadata, anchorRoot: anchor.root, metadataHash: metadataHash(metadata), scope: electionScope(metadata.electionId), opensAt: metadata.opensAt, closesAt: metadata.closesAt, state: "draft" };
    this.db.exec("BEGIN IMMEDIATE");
    try {
      this.db.prepare("INSERT INTO vote_elections(election_id,municipality_id,mirror_json,state,opens_at,closes_at) VALUES(?,?,?,'draft',?,?) ON CONFLICT(election_id) DO UPDATE SET mirror_json=excluded.mirror_json,opens_at=excluded.opens_at,closes_at=excluded.closes_at").run(metadata.electionId, metadata.municipalityId, canonical(mirror), metadata.opensAt, metadata.closesAt);
      this.db.prepare("INSERT INTO vote_anchors(election_id,anchor_json) VALUES(?,?) ON CONFLICT(election_id) DO UPDATE SET anchor_json=excluded.anchor_json").run(metadata.electionId, canonical(anchor));
      this.db.prepare("DELETE FROM vote_anchor_leaves WHERE election_id=?").run(metadata.electionId);
      const insert = this.db.prepare("INSERT INTO vote_anchor_leaves(election_id,commitment) VALUES(?,?)");
      for (const leaf of anchor.leaves) insert.run(metadata.electionId, leaf);
      this.db.exec("COMMIT");
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
    return mirror;
  }

  openElection(id: Hex, chain: ChainElection): ElectionMirror {
    const mirror = this.getElection(id);
    if (!mirror) fail("election_unknown", 404);
    if (mirror.state !== "draft") fail("election_already_opened", 409);
    const opened: ElectionMirror = { ...mirror, state: "open" };
    assertElectionMatchesChain(opened, chain, this.getAnchor(id)!);
    this.db.prepare("UPDATE vote_elections SET mirror_json=?,state='open',opened=1 WHERE election_id=?").run(canonical(opened), id);
    return opened;
  }

  closeElection(id: Hex, chain: ChainElection): ElectionMirror {
    const mirror = this.getElection(id);
    const tally = this.getTally(id);
    if (!mirror || mirror.state !== "open" || !tally) fail("election_close_invalid", 409);
    const closed: ElectionMirror = { ...mirror, state: "closed" };
    assertElectionMatchesChain(closed, chain);
    if (chain.tallyHash !== tally.tallyHash || chain.acceptedBallots !== BigInt(tally.tally.totalAccepted)) fail("chain_tally_mismatch");
    this.db.prepare("UPDATE vote_elections SET mirror_json=?,state='closed' WHERE election_id=?").run(canonical(closed), id);
    return closed;
  }

  getElection(id: Hex): ElectionMirror | null {
    const row = this.db.prepare("SELECT mirror_json FROM vote_elections WHERE election_id=?").get(id);
    return row ? JSON.parse(row.mirror_json as string) as ElectionMirror : null;
  }

  getAnchor(id: Hex): ElectionAnchor | null {
    const row = this.db.prepare("SELECT anchor_json FROM vote_anchors WHERE election_id=?").get(id);
    return row ? JSON.parse(row.anchor_json as string) as ElectionAnchor : null;
  }

  isCommitmentInOpenAnchor(input: Readonly<{ municipalityId: string; commitment: Hex; at: number }>): boolean {
    return !!this.db.prepare("SELECT 1 FROM vote_anchor_leaves l JOIN vote_elections e USING(election_id) WHERE e.municipality_id=? AND l.commitment=? AND e.state='open' AND e.closes_at>? LIMIT 1").get(input.municipalityId, input.commitment, input.at);
  }

  hasNullifier(id: Hex, nullifier: Hex): boolean {
    return !!this.db.prepare("SELECT 1 FROM vote_ballots WHERE election_id=? AND nullifier=?").get(id, nullifier);
  }

  insertBallot(ballot: Ballot): boolean {
    return this.db.prepare("INSERT INTO vote_ballots(election_id,nullifier,choice_index,signal_hash,proof) VALUES(?,?,?,?,?) ON CONFLICT(election_id,nullifier) DO NOTHING").run(ballot.electionId, ballot.nullifier, ballot.choiceIndex, ballot.signalHash, ballot.proof).changes === 1;
  }

  listBallots(id: Hex): Ballot[] {
    return this.db.prepare("SELECT nullifier,choice_index,signal_hash,proof FROM vote_ballots WHERE election_id=? ORDER BY nullifier ASC").all(id).map((row) => ({ schemaVersion: "advisory_ballot_v1", electionId: id, nullifier: row.nullifier as Hex, choiceIndex: row.choice_index as number, signalHash: row.signal_hash as Hex, proof: row.proof as Hex }));
  }

  putTally(id: Hex, tally: Tally, tallyHash: Hex): void {
    if (tally.electionId !== id) fail("tally_election_mismatch");
    if (tallyHash !== `0x${digest(tally)}`) fail("tally_hash_mismatch");
    const current = this.getTally(id);
    if (current && (current.tallyHash !== tallyHash || canonical(current.tally) !== canonical(tally))) fail("tally_immutable", 409);
    this.db.prepare("INSERT INTO vote_tallies(election_id,tally_hash,tally_json) VALUES(?,?,?) ON CONFLICT(election_id) DO NOTHING").run(id, tallyHash, canonical(tally));
  }

  getTally(id: Hex): Readonly<{ tally: Tally; tallyHash: Hex }> | null {
    const row = this.db.prepare("SELECT tally_hash,tally_json FROM vote_tallies WHERE election_id=?").get(id);
    return row ? { tally: JSON.parse(row.tally_json as string) as Tally, tallyHash: row.tally_hash as Hex } : null;
  }
}
