# Threat model

## Scope and security claims

[DESIGN.md](DESIGN.md) is normative. This model covers the eligibility issuer,
its adapters, the anonymous advisory participation lane, and the election
registry. It describes required controls and their limits, not evidence of a
completed security audit or of safe infrastructure configuration.

The lane proves knowledge of a secret behind a commitment in a frozen anchor
and restricts acceptance to one ballot per secret and election scope. It does
not independently prove one natural person per enrollment, guarantee submission
inclusion, or create binding municipal decisions. Eligibility receipts carry
`authorityBinding: "civic_eligibility_only"`; participation results carry
`authorityBinding: "none"` and are advisory non-binding.

## Assets

- Citizen PRF output and derived secret: disclosure can expose the
  person-to-ballot link across the municipality's polls and enable impersonation.
- Nostr subject keys, attestor signing keys, issuer Ed25519 keys, wallet keys,
  and registry admin/operator authority.
- Integrity and freshness of policy, attestations, revocations, adapter evidence,
  eligibility receipts/status, and adoption acceptance records.
- Confidentiality of issuer-private subject-to-commitment mappings and, for the
  citizen-NFT bridge, subject-to-wallet mappings. Public keys and wallet
  addresses are pseudonymous, not necessarily anonymous.
- Integrity and availability of enrollments, frozen anchors, metadata, election
  windows/scopes, accepted ballots, and canonical tallies.
- Separation of public audit artifacts from authenticated enrollment and network
  metadata, including privacy of participation and the person-to-choice link.
- Circuit/verifier artifacts, their hashes, dependency pins, and reproducible
  verification semantics.

No names, addresses, birth dates, or document numbers belong in this module.
Document-kind labels are not document contents. Avoiding those fields does not
make pseudonymous associations harmless or remove data-protection obligations.

## Actors and capabilities

| Actor | Capabilities and potential abuse |
| --- | --- |
| Issuer operator | Configures policy and adapters, holds signing authority, and can access private issuer records. Can misstate eligibility, disclose mappings, or refuse service. |
| Attestors | Sign observed eligibility evidence and revocations. Can make mistakes, lose keys, collude, or attest multiple subject keys for one person. |
| Election operator | Chooses the electorate snapshot, metadata, and window, opens/closes polls, and publishes results. Can add controlled commitments, exclude eligible citizens, or withhold publication. |
| Server | Receives authenticated enrollment and plaintext anonymous ballots; sees live connections and transient limiter keys. A compromised server can correlate traffic, censor, omit accepted ballots, or leak records. |
| Network observer | Observes connections, sizes, timing, and service use. A TLS endpoint or compromised proxy can also inspect ballot payloads. |
| Other citizens | See public policy, anchors, and tallies; can submit malformed proofs, race duplicate ballots, exhaust verification resources, share secrets, or seek multiple enrollments. |
| Coerced voter | Can be forced to vote under observation, reveal a secret, surrender a credential, or cooperate in proving a choice. There is no protocol escape through revoting. |

A single deployment may combine several roles. Role separation in code does not
establish independence of the people controlling those roles.

## Trust assumptions and boundaries

### Eligibility and electorate composition

The issuer is trusted to apply the published policy honestly. The election
operator controls anchor composition and can add commitments for known secrets.
Chain pinning prevents subsequent root changes; it does not certify that the
chosen leaves correspond to unique eligible people. The server cannot fabricate
a valid proof for an honest citizen's secret under the cryptographic assumptions,
but an operator can create valid proofs for operator-controlled leaves.

The in-person adapter requires at least two distinct qualifying attestors,
rejects configured self-attestation, enforces key validity and policy basis,
and evaluates renewal and revocation rules. This assumes independent, honest
evidence collection and correct ownership declarations. Colluding attestors can
approve ineligible or duplicate subjects; configured ownership checks cannot
discover undeclared keys or prove human uniqueness. A subject-level uniqueness
constraint is not a population register.

The citizen-NFT bridge trusts the specified chain, RPC view, contract code hash,
active-status interface, and wallet-signature validation. It verifies a defined
status, not independent identity proofing. The issuer knows both the subject key
and wallet from the evidence and private evidence reference. That relationship
must not appear in public receipts, anchors, ballots, or tallies.

### Ballot privacy

The issuer knows subject-to-commitment from enrollment. Knowing that mapping
alone should not reveal the scoped nullifier without the secret, under the hash
and proof assumptions. Repeated public commitments nevertheless reveal roster
continuity within a municipality. Municipality-specific PRF/HKDF derivation
separates voting commitments, not reuse of a subject key or wallet elsewhere.

Vote secrecy means secrecy of the person-to-choice link, not encryption of the
choice. The server sees choices and the published tally contains anonymous
choices, proofs, and nullifiers. Security depends on a confidential, high-entropy
PRF secret, honest client code, authenticator protection, and correct
zero-knowledge verification. A compromised browser, extension, dependency, or
client distribution can extract the derived secret or submit a different choice.
`userVerification: "required"` does not protect against malicious client code
that runs after verification. Server-assisted proving would disclose the secret
and is outside this privacy boundary.

The protocol is not receipt-free, coercion-resistant, or anti-collusion. Unlike
MACI's revoting-based anti-collusion model, it supplies no later command that
invalidates a coerced accepted ballot. Plain confirmation responses do not stop
a voter from revealing a secret, generating evidence for a coercer, or voting
under observation. MACI is not implemented or implied by these documents.

### Timing, transport, and storage

TLS and correctly configured client/infrastructure behavior are deployment
assumptions. Cookie omission, no-store responses, complete-anchor downloads,
sorted artifacts, and absent ballot timestamps reduce explicit linkage. They do
not hide connection timing, traffic volume, authentication followed by voting,
or a small anonymity set. A global observer or a server watching both lanes can
correlate activity. No batching, mix network, or cover traffic is promised.

Per-client rate-limit keys exist transiently in server memory. The live server
can associate those keys with requests. Reverse proxies, access logs, tracing,
crash dumps, backups, SQLite row order, journals, and filesystem history can
preserve information outside the published schema. Sorted tally output does not
erase those traces. `cache-control: no-store` is not a log-retention policy.

### Chain, auditability, and liveness

Clients trust the intended chain and registry/verifier configuration and check
chain data rather than trusting a server mirror. A dishonest RPC endpoint or
compromised admin authority can undermine that check. Chain availability and
finality remain external assumptions.

An independently verified tally proves validity of the published ballot set,
its counts, and its pinned hash. It cannot prove that all attempted or
server-acknowledged ballots were included. The plain acknowledgement is not an
inclusion receipt. The server can censor or omit ballots; the operator can
withhold a close transaction or publish a tally omitting ballots. Independent
auditing can detect invalid proofs, repeated nullifiers, wrong counts, and hash
mismatch, but not unobserved omissions or dishonest eligibility admission.

## Code mitigations and residual risks

These controls are specified by DESIGN.md; external review must establish that
implementation and deployment actually preserve them.

| Threat | Mitigation in the design/code contract | Residual risk |
| --- | --- | --- |
| Secret theft or cross-municipality linkage | PRF-only derivation, required user verification, municipality-specific input/HKDF, non-zero field secret, no stored-secret fallback. | Malicious clients, credential compromise, loss of credential, and external subject-key reuse. Unsupported PRF fails closed and excludes that device. |
| Forged or replayed enrollment/receipt requests | NIP-98 exact URL/method/body binding, clock-skew checks, and single-use event IDs; one active commitment per municipality/subject. | Stolen subject keys, issuer compromise, or multiple subject keys approved for one person. |
| Dishonest/expired attestation | Distinct attestor threshold, key-validity checks, configured no-self-attestation, exact policy basis, bounded attestation window, K-fresh renewal, and distinct-attestor revocation threshold. Issuer/attestor key equality is rejected. | Collusion, falsely declared key ownership, operational mistakes, and malicious configuration. |
| Wallet-evidence substitution | Fixed EIP-191 text binds municipality, policy, subject, purpose, request ID and time; EOA/ERC-1271/ERC-6492 validation, expected contract code hash, configured block view, and active-status recheck. | Dishonest RPC, chain changes, contract/interface assumptions, wallet compromise, or multiple-wallet eligibility. |
| Stale or substituted civic evidence | Short receipt TTL, fresh adapter-backed signed status, echoed status nonce and fixed audience, canonical Ed25519 receipt proofs, exact Stadtstack wire shapes. | A trusted issuer can sign false evidence; live status depends on adapter and service availability. |
| Mutable electorate or replacement races | Depth-16 immutable chain root, adapter recheck at anchoring, unique numerically sorted leaves, subject enrollment uniqueness, and replacement lock for current commitments in open anchors. | Operator composition fraud, snapshot exclusions, later revocation not changing the electorate, and locking defects. |
| Ballot alteration or duplicate acceptance | Choice/signal checks; proof inputs pinned to root/nullifier/scope/signal; scoped nullifier derivation; proof verification before insertion; database `UNIQUE(election_id, nullifier)` resolves races. | Valid ballots for dishonest anchor leaves; malicious clients; cryptographic or verifier defects. Uniqueness is per secret, not per human. |
| Resource exhaustion | Bounded 32 KiB ballot body, exact JSON shape, cheap election/window/choice checks first, in-memory per-client limits and global concurrent-verification cap. | Distributed denial of service, shared-client unfairness, expensive valid proofs, and resource pressure outside the application. |
| Persistent ballot linkage | No subject/wallet/session/client identifier or timestamp in stored ballots; no cookies; credential-free/no-store/no-redirect client submission; plain replies; local membership witnesses; sorted public artifacts. | Live timing correlation, infrastructure logs, forensic traces, small electorates, and voluntary/coerced disclosure. |
| Tally substitution or unverifiable results | Canonical SHA-256 digests, nullifier-sorted ballots, chain-derived window, public proofs and counts, circuit/VK identifiers, and on-chain tally hash/count at close. | Selective omission, withholding, dishonest anchor admission, or auditors using the wrong verifier/chain. |
| Parser ambiguity or artifact drift | Bounded JSON snapshots, exact keys, safe canonical values, pinned toolchain, Noir/TypeScript hash parity fixtures, committed matching circuit/verifier artifacts and rebuild comparison. | Supply-chain compromise, build non-reproducibility, inadequate fixture coverage, or unreviewed parameter changes. |

## External review coverage

Before making real-world anonymity or eligibility claims, review at least:

1. **Cryptography:** Poseidon2 parameter/domain parity, BN254 bounds, secret
   reduction and zero handling, high/low election-ID split, bit ordering,
   depth-16 zero padding, boolean path constraints, root and nullifier checks,
   signal public-input binding, and matching UltraHonk Keccak zero-knowledge
   proof/public-input encodings in browser, server, and Solidity.
2. **Client boundary:** PRF creation/evaluation behavior across authenticators,
   required user verification, no fallback or persistent secret/proof telemetry,
   metadata/root/scope/window checks against the intended chain, whole-anchor
   witness construction, and omission of cookies and redirects on ballot intake.
3. **Issuer and adapters:** canonical signing domains and Stadtstack verifier
   interoperability, status nonce/audience/freshness, NIP-98 replay handling,
   policy isolation, threshold/renewal/revocation edge cases, private evidence
   storage, and all wallet-signature forms including counterfactual validation
   and adversarial RPC responses.
4. **Concurrency and lifecycle:** uniqueness under concurrent submissions,
   replacement versus anchor creation/opening, immutable snapshots, exact
   half-open voting windows, chain/mirror disagreement, closing restrictions,
   duplicate nullifiers, deterministic tallies, and independent proof/count/hash
   reconstruction including empty polls.
5. **Authority and supply chain:** actual registry admin/operator/verifier
   configuration, key custody and separation, artifact manifests, reproducible
   circuit/verifier generation, pinned dependencies, malicious-client delivery,
   and parameter-change procedures.
6. **Privacy operations:** request and access logs at every transport layer,
   tracing/analytics, limiter-key lifetimes, process dumps, database journals,
   backups and retention, unauthorized access to private mappings, and realistic
   timing/small-electorate correlation. Record deployment evidence separately;
   application schema tests cannot certify infrastructure behavior.
7. **Availability and abuse:** proof-verification cost, limiter fairness and
   bypass, body/parser bounds, censoring or omitted ballots, operator/attestor
   collusion, credential/key loss, revocation delays, and recovery drills that
   do not silently rewrite anchors or weaken secret handling.
8. **Public claims:** explicit advisory status, no guarantee of human uniqueness,
   no inclusion guarantee, no receipt-freeness or anti-collusion, and honest
   disclosure of issuer mappings, operator composition power, and plaintext
   anonymous choices. Any binding-election or stronger coercion-resistance
   requirement needs a new protocol decision and legal review.
