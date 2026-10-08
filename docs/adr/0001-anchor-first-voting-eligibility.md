# 0001. Anchor-first voting eligibility

## Status

Accepted. [DESIGN.md](../DESIGN.md) is normative.

## Context

Eligibility, an authenticated subject key, and an anonymous ballot identity serve
different purposes. Treating a wallet or subject key as the ballot identity
would expose the connection between civic eligibility and a person's choice.
Eligibility can also change while a poll is running; a mutable voting roster
would make the electorate and proof rules ambiguous.

## Decision

Each advisory poll uses one frozen Merkle anchor. At `anchoredAt`, the issuer
re-checks enrollment eligibility through the configured adapter and selects the
currently active commitments of eligible enrollments. There is one active
commitment per `(municipalityId, subjectPubkey)`.

The default in-person model uses signed off-chain attestations, not an on-chain
citizen registry. The adapter seam can support other eligibility evidence;
neither attestor records nor adapter evidence enters the public anchor.

The `advisory_election_anchor_v1` artifact contains unique, non-zero commitments,
sorted ascending as numbers. It uses a depth-16 tree with zero-valued empty
leaves, for a maximum of 65,536 leaves. Numeric ordering avoids publishing
enrollment or attestation order. The root is pinned by `openElection` and cannot
change afterwards. A subject key, wallet address, or public identity hash is
never a substitute for knowledge of the secret behind an anchored commitment.

Enrollment after the snapshot can qualify a person for a later anchor, not
modify an existing one. Later eligibility changes do not retroactively change
the frozen electorate. Enrollment churn is not a reason to reject a valid
ballot from someone already included in the anchor. Replacement follows
[ADR-0005](0005-voting-identity-rebinding.md).

Clients obtain the complete anchor and construct membership witnesses locally.
Before proving, they compare the reconstructed root, metadata hash, derived
scope, and voting window with the chain record. A server mirror is not the
source of truth for those values.

## Consequences

- Eligibility administration is separate from anonymous ballot intake.
- Freezing the electorate gives proofs a stable meaning, but excludes late
  enrollments and retains snapshot members through the poll.
- Sorted leaves remove order leakage, not the issuer's private
  subject-to-commitment mapping or network timing information.
- The operator chooses anchor composition and can add commitments for secrets
  it controls. A valid membership proof is not independent proof that every
  anchor member is a unique eligible person. Public policy, adapter checks,
  and external oversight remain necessary.
- The Stadtstack receipt seam certifies `civic_eligibility_only`; neither
  eligibility evidence nor anchor membership confers binding decision power.
