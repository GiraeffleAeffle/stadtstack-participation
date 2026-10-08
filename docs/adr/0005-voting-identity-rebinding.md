# 0005. Voting identity rebinding outside affected open anchors

## Status

Accepted. [DESIGN.md](../DESIGN.md) is normative.

## Context

A different PRF credential can yield a different commitment. Losing the old
credential can make an anchored identity unavailable. Replacement must preserve
the single-active-commitment invariant without suggesting that an immutable
anchor now recognizes the new secret.

## Decision

Allow authenticated replacement of an active enrollment, but refuse replacement
while an open poll's anchor contains the current commitment. This is an
anchor-membership-specific lock, not a blanket ban whenever any poll is open.
An unrelated open poll whose anchor lacks that commitment does not itself
prevent replacement. Enforcement belongs on the issuer side through the
commitment-lock seam, not only in a client control.

The holder derives the replacement secret with the same PRF-only rules as
[ADR-0004](0004-voting-enrollment-auto-activation.md), signs the enrollment
request from the subject's Nostr key, and presents adapter evidence. The issuer
preserves one active commitment per `(municipalityId, subjectPubkey)`.
There is no fallback secret store, secret recovery, or concurrent second active
identity.

Clients must explain the consequences before replacement: it affects future
anchor snapshots, does not rewrite existing anchors, and does not make a new
credential capable of proving membership for the old commitment. A synced
credential that produces the same PRF result need not create a new identity;
device names alone do not decide whether rebinding is necessary.

## Consequences

- A holder included in an open anchor cannot rotate that commitment during the
  poll. Losing the old credential can therefore prevent participation in that
  poll; the server cannot recover the secret.
- The membership-specific lock avoids unnecessarily blocking holders who cannot
  participate in an unrelated open poll anyway.
- Replacement and anchor creation need consistent locking so concurrent actions
  cannot bypass the rule. Store uniqueness also remains required.
- Historical anchors and accepted ballots retain their original meaning;
  replacement does not erase a prior ballot or permit a second ballot for the
  same secret and scope.
- No multi-identity voting, escrow, new recovery endpoint, or change to snapshot
  eligibility is implied by this decision.
