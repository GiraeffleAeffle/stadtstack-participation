# 0004. Voting enrollment as explicit activation after eligibility

## Status

Accepted. [DESIGN.md](../DESIGN.md) is normative.

## Context

Being eligible does not automatically put a citizen's voting identity into an
anchor. An easily missed enrollment ceremony can exclude motivated participants
who first arrive after a poll opens. Enrollment should be a clear next action,
without confusing eligibility approval with anonymous voting identity creation.

## Decision

Keep the principle of enrollment as a consentful activation action following
eligibility verification, rather than a separate conceptual destination.
“Auto-activation” means an integration can offer the next action immediately;
it never means an attestor or server silently generates a citizen's secret.
This repository supplies the protocol and client helpers, not a prescribed UI,
navigation flow, browser dismissal store, or authenticated enrollment-status
endpoint.

The citizen derives the identity secret only from WebAuthn PRF. Request the PRF
extension at credential creation and evaluate it with
`userVerification: "required"`. The PRF input is
`sha256("stadtstack-participation/person-secret/v1/" + municipalityId)`.
Derive `secret` using HKDF-SHA256 with PRF output as input key material, salt
`"stadtstack-participation"`, info `"person-secret/v1/" + municipalityId`, and
64 output bytes, reduced modulo the BN254 scalar-field modulus. Reject zero.
Unsupported PRF fails with `prf_unavailable`; there is no IndexedDB,
localStorage, escrow, or alternative-secret fallback.

Enrollment submits the commitment and adapter evidence in a NIP-98-signed
request from the subject's Nostr key to `POST /v1/identity-commitments`. Exact
URL, method, body digest, clock skew, and single-use event checks bind that
request. The issuer enforces one active commitment per municipality and subject.
Attestors establish eligibility through signed off-chain evidence; they neither
derive the secret nor act as the ballot identity.

An integration should explain that activation prepares a later anchor and does
not insert the citizen into an already frozen poll. It should keep PRF output,
secret, and local commitment comparisons out of telemetry and persistent browser
storage. Ballot submission remains separate and unauthenticated.

## Consequences

- Eligibility approval and voting enrollment remain distinct checks, even when
  an integration presents them as adjacent actions.
- PRF-only derivation makes unsupported authenticators an explicit availability
  constraint instead of silently changing secret protection.
- Municipality-specific derivation separates commitments across municipalities;
  commitments can still be recognized across polls within one municipality.
- The issuer knows the subject-to-commitment association. Enrollment is not
  anonymous, and the UX must not imply otherwise.
- Losing access to the PRF credential may lose access to an existing anchor.
  Replacement is governed by [ADR-0005](0005-voting-identity-rebinding.md), not
  automatic recovery or mid-poll insertion.
