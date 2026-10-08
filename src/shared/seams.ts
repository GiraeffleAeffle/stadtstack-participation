/**
 * Interfaces between the issuer, the eligibility adapters and the advisory
 * participation lane. Each side may be replaced without touching the other.
 */

/** What a request is for; adapters bind wallet or attestor proofs to it. */
export type EligibilityPurpose =
  | Readonly<{ kind: "adoption_receipt"; participantSuggestionId: string; topicId: string }>
  | Readonly<{ kind: "commitment_enrollment"; commitment: `0x${string}` }>;

export type EligibilityCheckInput = Readonly<{
  municipalityId: string;
  policyVersion: string;
  /** Nostr key that signed the request (NIP-98). */
  subjectPubkey: string;
  purpose: EligibilityPurpose;
  /** Single-use id of the authenticated request; adapters bind proofs to it. */
  requestId: string;
  /** Adapter-specific evidence from the request body; untrusted. */
  evidence: unknown;
  now: number;
  signal: AbortSignal;
}>;

export type EligibilityRecheckInput = Readonly<{
  municipalityId: string;
  policyVersion: string;
  subjectPubkey: string;
  /** Issuer-private reference returned by an earlier `check`. Never published. */
  evidenceRef: string;
  now: number;
  signal: AbortSignal;
}>;

export type EligibilityDecision =
  | Readonly<{
    state: "active";
    /** Earliest time this eligibility holds; never later than `now`. */
    effectiveAt: number;
    /** End of validity, or null when the source has no fixed end. */
    validUntil: number | null;
    evidenceRef: string;
  }>
  | Readonly<{ state: "inactive"; reason: string }>;

export interface EligibilityAdapter {
  /** Stable adapter kind, e.g. `in_person_attestors_v1`. */
  readonly kind: string;
  check(input: EligibilityCheckInput): Promise<EligibilityDecision>;
  recheck(input: EligibilityRecheckInput): Promise<EligibilityDecision>;
}

/** Provided by the issuer: commitments whose eligibility re-check is active. */
export interface EligibleCommitmentSource {
  listEligibleCommitments(input: Readonly<{
    municipalityId: string;
    policyVersion: string;
    at: number;
    signal: AbortSignal;
  }>): Promise<readonly `0x${string}`[]>;
}

/** Provided by the participation lane: whether an open poll pins a commitment. */
export interface CommitmentLock {
  isCommitmentInOpenAnchor(input: Readonly<{ municipalityId: string; commitment: `0x${string}`; at: number }>): boolean;
}

export type Clock = () => number;
