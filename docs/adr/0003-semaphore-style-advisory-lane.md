# 0003. Semaphore-style advisory lane; MACI is a comparison only

## Status

Accepted. [DESIGN.md](../DESIGN.md) is normative.

## Context

Advisory participation needs a checkable electorate, anonymous membership
proofs, one accepted ballot per voting identity per poll, and a reproducible
result. These requirements do not imply encrypted ballots, a decryption
coordinator, or resistance to vote buying. A protocol with stronger
anti-collusion goals would introduce materially different trust and operational
requirements.

## Decision

Use a Noir-native Semaphore-style membership/nullifier lane, not a claim of
compatibility with the Semaphore reference circuit. Citizens prove locally;
the server accepts ballots off-chain; the election registry pins the anchor,
metadata, scope, window, and final tally hash. There is no decryption coordinator.

All circuit-relevant hashes operate in the BN254 scalar field with
`h(a, b, d) = poseidon2_permutation([a, b, d, 0])[0]`:

| Purpose | Derivation |
| --- | --- |
| Identity commitment | `h(secret, 0, 1)` |
| Merkle node | `h(left, right, 2)` |
| Election scope | `h(hi128(electionId), lo128(electionId), 4)` |
| Scoped nullifier | `h(secret, scope, 3)` |
| Signal hash | `h(choiceIndex, scope, 5)` |

The tree depth is 16. The secret and scope are non-zero; path indices are
boolean. Public input order is `root, nullifier, scope, signal_hash`.
`choiceIndex` is in `[0, 255]` and must name a choice in the pinned metadata.
The circuit binds the signal hash as a public input; intake separately checks
its derivation from the submitted choice and election scope. Proof verification
uses zero-knowledge UltraHonk with the Keccak oracle hash. Pinned Noir and
TypeScript parity fixtures and matching circuit/verifier artifacts are part of
the reproducibility contract.

Ballots are ordered by nullifier in `advisory_tally_v1`; counts are rebuilt from
the accepted ballots. The window comes from the chain, not a new wall-clock
reading. Canonical JSON and SHA-256 define the metadata and tally digests.
`tallyHash = 0x + digest(tally)` is pinned at close. Public auditors can check
every proof, duplicate nullifier, choice, count, artifact hash, and registry
record. Publication does not prove that the server included every submitted
ballot or that the operator selected an honest electorate.

Stadtstack consumes the projection `participation_result_v1` with
`authorityBinding: "none"`. Poll metadata has `legalEffect:
"advisory_non_binding"`. The separate eligibility issuer emits Stadtstack wire
receipts with `authorityBinding: "civic_eligibility_only"`; these are neither
ballot receipts nor a grant of legal decision authority.

MACI remains a comparison point, not a migration plan. A future replacement
requires a new decision naming the unmet civic requirement, expected benefit,
coordinator and key trust assumptions, operational and recovery costs, legal
scope, and audit plan. Binding elections require a separate design and legal
basis, not a relabeling of these artifacts.

## Consequences

- Nullifier uniqueness prevents duplicate acceptance for the same secret and
  scope. It does not establish one natural person per commitment.
- Choices are plaintext anonymous signals. Secrecy of the person-to-choice
  link depends on secret confidentiality and deployment hygiene.
- No receipt-freeness or MACI-style anti-collusion is claimed. There is no
  revoting mechanism that invalidates a coerced earlier ballot.
- The server can censor or omit ballots; the operator can withhold closing or
  publication. Hash pinning detects artifact substitution, not those omissions.
- Parameter, circuit, verifier, or derivation changes need explicit versioning
  and review; historical polls retain their original verification meaning.
