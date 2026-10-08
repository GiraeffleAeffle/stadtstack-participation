import type { DatabaseSync } from "node:sqlite";
import { fail } from "../shared/errors.ts";

export function migrate(db: DatabaseSync): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS issuer_auth_events (event_id TEXT PRIMARY KEY);
    CREATE TABLE IF NOT EXISTS issuer_receipts (
      payload_checksum TEXT PRIMARY KEY, receipt_id TEXT NOT NULL UNIQUE,
      receipt_json TEXT NOT NULL, suggestion_json TEXT NOT NULL, evidence_ref TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS issuer_adoptions (
      adoption_event_id TEXT PRIMARY KEY, municipality_id TEXT NOT NULL,
      participant_suggestion_id TEXT NOT NULL, adopter_pubkey TEXT NOT NULL,
      acceptance_json TEXT NOT NULL, event_json TEXT NOT NULL,
      UNIQUE(municipality_id, participant_suggestion_id, adopter_pubkey)
    );
    CREATE TABLE IF NOT EXISTS issuer_enrollments (
      id INTEGER PRIMARY KEY, municipality_id TEXT NOT NULL, policy_version TEXT NOT NULL,
      subject_pubkey TEXT NOT NULL, commitment TEXT NOT NULL, evidence_ref TEXT NOT NULL,
      enrolled_at INTEGER NOT NULL, active INTEGER NOT NULL CHECK(active IN (0,1))
    );
    CREATE UNIQUE INDEX IF NOT EXISTS issuer_active_subject
      ON issuer_enrollments(municipality_id, subject_pubkey) WHERE active = 1;
    CREATE UNIQUE INDEX IF NOT EXISTS issuer_active_commitment
      ON issuer_enrollments(municipality_id, commitment) WHERE active = 1;
    -- One piece of evidence (wallet, credential, attested subject) is one
    -- person: it may hold only one active enrollment and adopt a suggestion
    -- under only one subject key.
    CREATE UNIQUE INDEX IF NOT EXISTS issuer_active_evidence
      ON issuer_enrollments(municipality_id, evidence_ref) WHERE active = 1;
    CREATE TABLE IF NOT EXISTS issuer_suggestion_evidence (
      participant_suggestion_id TEXT NOT NULL, evidence_ref TEXT NOT NULL, subject_pubkey TEXT NOT NULL,
      PRIMARY KEY (participant_suggestion_id, evidence_ref)
    );
    CREATE TABLE IF NOT EXISTS issuer_attestations (
      record_id TEXT PRIMARY KEY, municipality_id TEXT NOT NULL, policy_version TEXT NOT NULL,
      subject_pubkey TEXT NOT NULL, attestor_id TEXT NOT NULL, recorded_at INTEGER NOT NULL,
      record_kind TEXT NOT NULL CHECK(record_kind IN ('attestation','revocation')), record_json TEXT NOT NULL
    );
  `);
}

export class IssuerStore {
  readonly db: DatabaseSync;
  constructor(db: DatabaseSync) { this.db = db; migrate(db); }

  consumeAuth(eventId: string): void {
    const inserted = this.db.prepare("INSERT OR IGNORE INTO issuer_auth_events(event_id) VALUES (?)").run(eventId);
    if (inserted.changes !== 1) fail("auth_replayed", 409);
  }
}
