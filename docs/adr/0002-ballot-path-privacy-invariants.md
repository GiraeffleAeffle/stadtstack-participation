# 0002. Ballot-path privacy invariants

## Status

Accepted. [DESIGN.md](../DESIGN.md) is normative.

## Context

Authenticated enrollment intentionally links an eligible subject to a commitment.
Ballot intake must not carry that authentication into the voting lane. Even a
sound zero-knowledge proof cannot conceal identifying request metadata captured
by the client, server, proxy, or network.

## Decision

`POST /v1/elections/<electionId>/ballots` is authenticated by a membership proof
only, not a Nostr signature, wallet signature, session, or cookie. The exact
ballot shape is `{ schemaVersion, electionId, choiceIndex, nullifier, signalHash,
proof }`, with schema version `advisory_ballot_v1`. No subject or wallet field is
accepted. Clients submit with `credentials: "omit"`, `cache: "no-store"`, and
`redirect: "error"`. Responses are non-cacheable JSON and set no cookies.

Stored ballots carry no timestamps, sessions, or client identifiers. Intake
returns only `{ ok: true }` or `{ ok: false, code }`, without echoing proof bytes,
nullifiers, or a personalized receipt identifier. Client integrations must not
turn the plain confirmation into a persistent identity-linked ballot receipt.

Unlike a blanket ban on reading client metadata, this design explicitly allows
per-client rate-limit keys held in memory only. The keys must not enter ballot
records, audit records, public artifacts, or persistent request logs. A global
concurrent-verification cap complements that limit. These protections bound
resource use; they do not provide anonymity against the live server.

The tally publishes accepted proofs, choices, signal hashes, and nullifiers,
sorted ascending by nullifier. It contains no per-ballot wall-clock time or
submission-order field. This is public ballot auditability, not encrypted
ballot storage: the anonymous choices are visible to the intake server and to
readers of the published tally.

## Consequences

- Enrollment and eligibility receipts are authenticated; ballot submission is
  not. Stadtstack eligibility receipts must never be attached to ballots.
- Full-anchor download and local witness construction avoid an endpoint that
  reveals which leaf a client is asking to prove.
- Proxies, access logs, observability, browser extensions, and analytics can
  defeat application-level privacy. Their configuration requires separate
  review; `no-store` alone does not prevent logging.
- In-memory limiting still permits transient correlation and may exclude
  citizens sharing a network. Distributed clients can evade it.
- Sorted publication and omission of timestamps reduce stored timing linkage,
  but cannot erase live observation, transport timing, or database forensic
  traces. Small electorates and outside knowledge further reduce anonymity.
- Proofs and nullifiers are publicly auditable and voters can disclose their
  secret or cooperate with a coercer. This design does not claim receipt-freeness,
  coercion resistance, or anti-collusion.
