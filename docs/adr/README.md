# Architecture decision records

[DESIGN.md](../DESIGN.md) is normative. These accepted records explain the
municipality-neutral advisory voting decisions and their consequences; they do
not expand the legal scope or promise deployment-level anonymity. See also the
[threat model](../THREAT_MODEL.md).

| Record | Decision |
| --- | --- |
| [0001](0001-anchor-first-voting-eligibility.md) | Freeze adapter-rechecked eligibility as a depth-16 anchor with numerically sorted commitments. |
| [0002](0002-ballot-path-privacy-invariants.md) | Separate authenticated enrollment from anonymous ballot intake; persist no ballot timing or client identifiers. |
| [0003](0003-semaphore-style-advisory-lane.md) | Use domain-separated membership proofs, scoped nullifiers, and a reproducible public tally; MACI is a comparison only. |
| [0004](0004-voting-enrollment-auto-activation.md) | Offer explicit activation after eligibility, using PRF-only citizen secrets and signed enrollment. |
| [0005](0005-voting-identity-rebinding.md) | Permit replacement only when the current commitment is absent from all affected open anchors. |
| [0006](0006-eudi-pid-adapter.md) | Keep EUDI test-verifier PID processing transient, using a keyed person-data reference across rotating holder keys; prefer German online eID for production investigation. |

## Adaptation notes

These records replace the earlier voting-lane decisions, in order: anchor-first
eligibility, ballot-path privacy, the Semaphore-style lane, enrollment
activation, and identity rebinding. Prior product-specific routes and UI details
are not contracts of this repository.

The deliberate changes are depth 16; explicit hash domain tags; PRF-only secret
derivation with no browser-storage fallback; numeric leaf ordering and
nullifier-ordered canonical tallies; signed off-chain attestors behind an
adapter seam rather than a required on-chain citizen registry; a
commitment-specific replacement lock rather than a blanket open-poll ban; and
Stadtstack eligibility and participation-result wire artifacts. Transient
in-memory per-client rate limiting is allowed, while persistent ballot linkage
is not. All results remain advisory and non-binding.
