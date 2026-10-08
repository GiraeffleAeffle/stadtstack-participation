/**
 * Independent K-of-N residency eligibility with non-stacking renewal.
 *
 * Reject self-attestations and signatures outside the attestor's half-open
 * [validFrom, validUntil) interval. At query time t, replay accepted records
 * with timestamps <= t in ascending timestamp order, processing all records
 * at an equal timestamp together. Track each attestor's latest attestation;
 * take the K most recent distinct attestors after each complete time group.
 * A cohort qualifies when newest - oldest <= attestationWindowSeconds.
 * Its effectiveAt is newest and validUntil is oldest + validitySeconds.
 *
 * Freeze an established cohort until all K candidates are strictly newer
 * than its effectiveAt. Thus a new signature cannot reuse a previous cohort's
 * member to extend expiry. The next qualifying cohort replaces, never adds
 * to, the old validity interval, even if the old interval has expired.
 *
 * Track each attestor's latest revocation independently. At least R distinct
 * revocations at or after the current cohort's effectiveAt revoke it (equality
 * revokes). Revocation does not erase attestations or the cohort boundary.
 * Re-attestation restores eligibility only through a fresh qualifying cohort
 * whose effectiveAt is later than enough revocations to fall below R.
 * Older, expired attestor authorization never invalidates a signature that
 * was valid when made; eligibility itself expires at validUntil.
 */
import type { DatabaseSync } from "node:sqlite";
import { canonical, digest, exact, isSafeNonNegativeInteger, snapshot } from "../shared/canonical.ts";
import { verifyCanonical } from "../shared/ed25519.ts";
import { fail } from "../shared/errors.ts";
import { isHex64, SLUG } from "../shared/ids.ts";
import type { EligibilityAdapter, EligibilityCheckInput, EligibilityDecision, EligibilityRecheckInput } from "../shared/seams.ts";
import { migrate } from "../issuer/store.ts";
import { ATTESTATION_SCHEMA, REVOCATION_SCHEMA, ATTESTATION_DOMAIN, REVOCATION_DOMAIN, DOCUMENT_KIND_PATTERN } from "./in-person-attestation.ts";

export type Attestor = Readonly<{ attestorId: string; publicKey: string; ownSubjectPubkeys: readonly string[]; validFrom: number; validUntil: number }>;
export type InPersonAttestorsConfig = Readonly<{ kind: "in_person_attestors_v1"; attestors: readonly Attestor[]; requiredAttestations: number; attestationWindowSeconds: number; validitySeconds: number; revocationThreshold: number }>;

export function validateInPersonAttestorsConfig(input: unknown): InPersonAttestorsConfig {
  const value = exact(snapshot(input), ["kind", "attestors", "requiredAttestations", "attestationWindowSeconds", "validitySeconds", "revocationThreshold"], "attestor_config_invalid");
  if (value.kind !== "in_person_attestors_v1" || !Array.isArray(value.attestors) || value.attestors.length < 2 ||
    !isSafeNonNegativeInteger(value.requiredAttestations) || value.requiredAttestations < 2 || value.requiredAttestations > value.attestors.length ||
    !isSafeNonNegativeInteger(value.revocationThreshold) || value.revocationThreshold < 1 || value.revocationThreshold > value.attestors.length ||
    !isSafeNonNegativeInteger(value.attestationWindowSeconds) || !isSafeNonNegativeInteger(value.validitySeconds) || value.validitySeconds < 1
  ) fail("attestor_config_invalid");
  const ids: Record<string, true> = Object.create(null);
  const keys: Record<string, true> = Object.create(null);
  for (const item of value.attestors) {
    const a = exact(item, ["attestorId", "publicKey", "ownSubjectPubkeys", "validFrom", "validUntil"], "attestor_config_invalid");
    if (typeof a.attestorId !== "string" || !SLUG.test(a.attestorId) || ids[a.attestorId] || !isHex64(a.publicKey) || keys[a.publicKey] ||
      !Array.isArray(a.ownSubjectPubkeys) || !a.ownSubjectPubkeys.length || a.ownSubjectPubkeys.some((key) => !isHex64(key)) ||
      new Set(a.ownSubjectPubkeys).size !== a.ownSubjectPubkeys.length || !isSafeNonNegativeInteger(a.validFrom) ||
      !isSafeNonNegativeInteger(a.validUntil) || a.validFrom >= a.validUntil) fail("attestor_config_invalid");
    ids[a.attestorId] = true; keys[a.publicKey] = true;
  }
  return value as InPersonAttestorsConfig;
}

type StoredRecord = { attestor_id: string; recorded_at: number; record_kind: string };

export class InPersonAttestorsAdapter implements EligibilityAdapter {
  readonly kind = "in_person_attestors_v1";
  readonly config: InPersonAttestorsConfig;
  readonly db: DatabaseSync;
  readonly municipalityId: string;
  readonly policyVersion: string;
  readonly basis: unknown;

  constructor(config: InPersonAttestorsConfig, options: Readonly<{ db: DatabaseSync; municipalityId: string; policyVersion: string; basis: unknown }>) {
    this.config = validateInPersonAttestorsConfig(config);
    this.db = options.db; this.municipalityId = options.municipalityId; this.policyVersion = options.policyVersion; this.basis = snapshot(options.basis);
    migrate(this.db);
  }

  recordAttestation(input: unknown, now: number): Readonly<{ recordId: string }> {
    return this.record(input, now, false);
  }

  recordRevocation(input: unknown, now: number): Readonly<{ recordId: string }> {
    return this.record(input, now, true);
  }

  private record(input: unknown, now: number, revocation: boolean): Readonly<{ recordId: string }> {
    const record = exact(snapshot(input), ["core", "signature"], "attestation_invalid");
    const core = exact(record.core, revocation ? ["schemaVersion", "municipalityId", "policyVersion", "subjectPubkey", "attestorId", "revokedAt"] :
      ["schemaVersion", "municipalityId", "policyVersion", "subjectPubkey", "attestorId", "attestedAt", "basis", "documentKinds"], "attestation_invalid");
    const at = revocation ? core.revokedAt : core.attestedAt;
    const attestor = this.config.attestors.find((a) => a.attestorId === core.attestorId);
    if (!attestor || core.schemaVersion !== (revocation ? REVOCATION_SCHEMA : ATTESTATION_SCHEMA) ||
      core.municipalityId !== this.municipalityId || core.policyVersion !== this.policyVersion || !isHex64(core.subjectPubkey) ||
      !isSafeNonNegativeInteger(at) || at > now || at < attestor.validFrom || at >= attestor.validUntil ||
      attestor.ownSubjectPubkeys.includes(core.subjectPubkey)) fail("attestation_invalid");
    if (!revocation && (canonical(core.basis) !== canonical(this.basis) || !Array.isArray(core.documentKinds) || !core.documentKinds.length ||
      core.documentKinds.length > 16 || core.documentKinds.some((kind) => typeof kind !== "string" || !DOCUMENT_KIND_PATTERN.test(kind)) ||
      new Set(core.documentKinds).size !== core.documentKinds.length)) fail("attestation_invalid");
    if (!verifyCanonical(attestor.publicKey, { domain: revocation ? REVOCATION_DOMAIN : ATTESTATION_DOMAIN, core }, record.signature)) fail("attestation_signature_invalid", 401);
    const recordId = digest(record);
    this.db.prepare(`INSERT OR IGNORE INTO issuer_attestations VALUES (?, ?, ?, ?, ?, ?, ?, ?)`).run(
      recordId, this.municipalityId, this.policyVersion, core.subjectPubkey, attestor.attestorId, at, revocation ? "revocation" : "attestation", canonical(record));
    return { recordId };
  }

  async check(input: EligibilityCheckInput): Promise<EligibilityDecision> {
    input.signal.throwIfAborted();
    return this.evaluate(input.municipalityId, input.policyVersion, input.subjectPubkey, input.now);
  }

  async preview(input: Readonly<{ municipalityId: string; policyVersion: string; subjectPubkey: string; now: number; signal: AbortSignal }>): Promise<EligibilityDecision> {
    input.signal.throwIfAborted();
    return this.evaluate(input.municipalityId, input.policyVersion, input.subjectPubkey, input.now);
  }

  async recheck(input: EligibilityRecheckInput): Promise<EligibilityDecision> {
    input.signal.throwIfAborted();
    if (input.evidenceRef !== input.subjectPubkey) return { state: "inactive", reason: "evidence_mismatch" };
    return this.evaluate(input.municipalityId, input.policyVersion, input.subjectPubkey, input.now);
  }

  private evaluate(municipalityId: string, policyVersion: string, subject: string, now: number): EligibilityDecision {
    if (municipalityId !== this.municipalityId || policyVersion !== this.policyVersion) return { state: "inactive", reason: "policy_mismatch" };
    const rows = this.db.prepare(`SELECT attestor_id, recorded_at, record_kind FROM issuer_attestations
      WHERE municipality_id=? AND policy_version=? AND subject_pubkey=? AND recorded_at<=?
      ORDER BY recorded_at ASC, record_id ASC`).all(municipalityId, policyVersion, subject, now) as StoredRecord[];
    const latest: Record<string, number> = Object.create(null);
    const revocations: Record<string, number> = Object.create(null);
    let grant: { effectiveAt: number; validUntil: number } | undefined;
    // Replay complete time groups: an added attestation cannot advance a grant
    // until every member of the next K-person cohort is newer than that grant.
    for (let index = 0; index < rows.length;) {
      const at = rows[index]!.recorded_at;
      while (index < rows.length && rows[index]!.recorded_at === at) {
        const row = rows[index++]!;
        if (row.record_kind === "revocation") revocations[row.attestor_id] = at;
        else latest[row.attestor_id] = at;
      }
      const selected = Object.values(latest).sort((a, b) => b - a).slice(0, this.config.requiredAttestations);
      if (selected.length === this.config.requiredAttestations) {
        const earliest = selected.at(-1)!;
        const effectiveAt = selected[0]!;
        if (effectiveAt - earliest <= this.config.attestationWindowSeconds && (!grant || earliest > grant.effectiveAt)) {
          grant = { effectiveAt, validUntil: earliest + this.config.validitySeconds };
        }
      }
    }
    if (!grant) return { state: "inactive", reason: "insufficient_attestations" };
    if (Object.values(revocations).filter((at) => at >= grant.effectiveAt).length >= this.config.revocationThreshold) return { state: "inactive", reason: "revoked" };
    if (now >= grant.validUntil) return { state: "inactive", reason: "expired" };
    return { state: "active", ...grant, evidenceRef: subject };
  }
}
