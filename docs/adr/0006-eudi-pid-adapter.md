# 0006. Test-verifier PID eligibility with transient person-data deduplication

## Status

Accepted for staging tests only. [DESIGN.md](../DESIGN.md) is normative.
The EU hosted test verifier is **not a production municipal identity service**.

## Context

OpenID4VP allows a wallet to selectively disclose PID attributes. The EU
reference verifier at `https://verifier-backend.eudiw.dev` exposes transaction
initialization and result polling [1]. Its reference implementation explicitly
warns against production use. The existing owner's MIT Ledger of Life client
provides a useful API integration reference, not a sufficient municipal policy
or SD-JWT parser: its optional city, unreferenced-disclosure extraction and
subject-level storage do not implement this module's requirements.

The EU test issuer currently advertises `urn:eudi:pid:1`; the German demo PID
provider advertises `urn:eudi:pid:de:1` [2, 3]. Both expose `family_name`,
`given_name`, `birthdate`, `address.postal_code` and `address.locality`. The
German provider also advertises `age_equal_or_over.{12,14,16,18,21,65}` [3].
These are selective disclosures, not zero-knowledge predicates. Address
attributes are optional: absence fails eligibility. Neither the inspected
German PID claim metadata nor its presentation flow provides an AGS claim or a
stable per-relying-party person pseudonym [3, 4]. The generic PID Rulebook
allows a residence/contact address; the address claim alone does not establish
registered main residence for every EU issuer [5].

Germany's architecture specifies five one-time credentials per format, with
**different holder keys**, and deletion after each presentation (step 031 and
"Batch Credential Refresh") [4]. A holder-key digest therefore fails person
uniqueness during ordinary usage, not just on reissuance. Names and birthdate
originate in the eID data and remain the same across batches and refreshes
when that source dataset is unchanged [6]. This is a deduplication heuristic,
not a unique legal identifier.

The German wallet is planned for early 2027, with pseudonym functionality
planned later [7]. Its documented flow is same-device, `direct_post.jwt`, with
access and registration certificates; the wallet checks that requested claims
are within the registered purpose [4, 8]. This adapter's EU test-wallet custom
scheme/QR flow is not evidence of German production interoperability or device
testing. Organizations need RP registration and a verifier component with
appropriate trust lists and certificates [8].

## Decision

### Policy and minimization

Implement exactly one `eudi_pid_v1` adapter per policy, with no `preview`:

```
{ kind: "eudi_pid_v1", verifierBaseUrl, acceptedVcts,
  acceptedAddresses: [{ postalCode, locality }],
  transactionTtlSeconds, validitySeconds }
```

`verifierBaseUrl` must be an HTTPS origin (no path, credentials, query,
fragment or trailing slash). `acceptedVcts` and the address list must be
nonempty and duplicate-free. Address comparison uses Unicode NFC, trimming
and case-insensitive comparison; postal code alone is never enough.
Transaction TTL is 30–900 seconds; decision validity is 1–31,536,000 seconds.
The policy must require `main_residence`, `nationality: "any"` and
`localityScope: null`. Secondary-residence eligibility, citizenship restrictions
and registry locality scopes cannot be implemented from these requested claims
and are rejected rather than silently weakened. The operator must establish
that an accepted PID profile represents the intended registered main address;
accepting a vct is not itself evidence of that semantic guarantee.

Request **exactly** `family_name`, `given_name`, `birthdate`,
`address.postal_code` and `address.locality` using DCQL and `dc+sd-jwt` [9].
The explicit purpose of processing names and birthdate is preventing double
participation. Birthdate is also used for whole-year age calculation in UTC,
matching `basis.minimumAgeYears` (or no age restriction when null). No separate
age-source option or age predicate is requested, because birthdate is already
needed for person deduplication. No street, birthplace, nationality, document
number, administrative identifier or portrait is requested.

Names, birthdate and address exist transiently in process memory only. They
are never stored, logged, returned to the client or included in public
artifacts. The hosted verifier independently receives and may retain them:
this module's storage minimization is **not** a claim about the remote
verifier's retention, process dumps, proxy logs or backups. RP registration
would need to authorize all five claims and this deduplication purpose.

### Lifecycle and trust boundary

- `POST /v1/eudi/requests`, NIP-98 JSON `{}`, creates a fresh 256-bit nonce and
  binds the verifier transaction to the authenticated subject. It returns
  `{ transactionId, walletUrl, expiresAt }` (integer Unix seconds).
- `GET /v1/eudi/requests/<transactionId>`, NIP-98 with no body, is visible only
  to that subject. It returns `{ state: "pending" }`, `{ state: "ready" }`,
  `{ state: "failed", reason }` or `{ state: "expired" }`; never claims.
- Both routes share the issuer's exact-URL/method/body authentication and
  single-use NIP-98 replay ledger. A different subject receives the same 404 as
  an unknown transaction.
- Enrollment evidence is exactly `{ transactionId }`. Only the bound subject
  may consume a ready transaction, once, before its half-open TTL ends.
  Atomic SQLite consumption decides duplicate checks. A rejected enrollment
  after consumption requires a fresh wallet presentation; transactions are
  not reusable capabilities.
- The local database stores transaction bindings (subject, transaction ID,
  nonce, verifier client ID and times) and final decisions only. Nonce and
  verifier client ID are cleared when terminal. Raw JWTs, holder keys,
  disclosures and claims are never persisted.

The configured HTTPS verifier is **trusted** for issuer signatures, issuer
trust chains, key-binding signatures and credential status. These are not
locally repeated, and a dishonest or incorrectly configured backend can
fabricate eligibility. The deployment must establish its validation and trust
configuration; a successful API response is not an independent audit.
Redirects are forbidden and all server requests stay under the configured
origin. The application obtains the response from the exact stored transaction
path, rejects a mismatching transaction ID if returned, and independently
checks key-binding nonce, audience/client ID, issuance time, `sd_hash`, allowed
vct, `cnf.jwk` holder-key presence/structure and credential `exp` if present.
It reconstructs only disclosures referenced by signed `_sd` digests, with
bounds and duplicate checks, then applies required-claim, address and age rules.
The backend API normally returns no transaction ID in the result; routing plus
the unique nonce provides that binding [1].

`validUntil` is the minimum of credential `exp` (if supplied) and presentation
processing time plus `validitySeconds`. `recheck` returns the stored subject's
consumed active decision until that boundary, then `evidence_expired`. It does
not contact the wallet or observe subsequent PID revocation or relocation.
An appropriately short validity is essential; new policy versions require new
evidence. Frozen voting anchors retain their documented snapshot semantics.

### Uniqueness and its limits

```
hex(HMAC-SHA256(uniquenessKey,
  "stadtstack-participation/eudi-person/v1/" + municipalityId + ":" +
  canonicalJson({ familyName, givenName, birthdate })))
```

For each name: Unicode NFC, trim, collapse internal whitespace to one space,
then `toLowerCase()`. Birthdate must be a real full ISO `YYYY-MM-DD` date, not
a partial or impossible date. Claims are discarded after this computation.
Holder binding remains mandatory, but the holder key is not the uniqueness
input. The same normalized person dataset gives the same reference despite
rotating holder keys; different municipalities have domain-separated values.
The issuer enforces its existing one-active-enrollment-per-evidence rule: a new
subject with the same reference supersedes the old one unless its commitment
is pinned in an open poll.

The operator supplies a separate, stable, raw secret of at least 32 random
bytes through `EUDI_UNIQUENESS_KEY_FILE`. It must not reuse the issuer signing
key. Back up this secret with equivalent protection to the private database;
rotation without a migration changes all references and breaks deduplication.
`EUDI_INTENDED_USE_ID` defaults to the test registration `TEST-01`.

This keyed hash is **pseudonymous personal data**, not anonymization. An
operator holding the key can test guessed name/birthdate tuples; a compromised
server sees the transient raw data. The reference has deliberate limits:

- A legal name change creates a new reference while the old enrollment stays
  eligible until its stored validity ends. It can permit overlapping identities.
- Two residents with identical normalized names and birthdate collide. The
  later presentation supersedes the earlier resident under the Storage rule
  (or is locked by an open anchor). Operator review must resolve such a case;
  the adapter cannot distinguish the people without additional authority.
- Source corrections, spelling/transliteration changes and different issuer
  datasets can create new references. Credential validity does not prove that
  every issuer uses an identical legal-name representation.
- Sharing a wallet, collusion, issuer/verifier compromise, fabricated test PID
  data and dishonest operators are not prevented.

Short validity, operator-reviewed recovery/name-change/collision procedures,
abuse monitoring without raw-claim logging, and proportionate rate limits are
possible mitigations, **not implemented guarantees of human uniqueness**.
Do not add an alternate adapter to the same policy to evade these limitations;
evidence from different adapters cannot be safely matched.

## Alternatives considered

1. **HMAC of the holder-key JWK thumbprint — rejected.** It minimizes data but
   cannot deduplicate people when a normal German presentation consumes a
   one-time credential with a different holder key [4]. An unkeyed person-data
   hash is also rejected because low-entropy names/birthdates permit offline
   guessing.
2. **German online eID (nPA/eAT/eID card) — recommended production investigation.**
   BSI TR-03127 §§4.4.2, 4.4.5 and 4.4.6 establish sector-specific Restricted
   Identification (pseudonym), yes/no age verification without reading
   birthdate, and Community ID Verification against the stored official AGS
   without reading an address [10]. TR-03110 explains RI and unlinkability
   across sectors [11]. The service needs an eID server (TR-03130) and a
   Berechtigungszertifikat granting these rights; TR-03127 §§4.7 and 5.2.1 and
   the Personalausweisportal explain the authorization path [10, 12]. A future
   `de_eid_v1` adapter could obtain municipality-exact residence, age and a
   sector-specific deduplication handle without names. This is the preferred
   production path for German municipalities, subject to service authorization,
   integration and legal review; it is not implemented here. RI is **card- and
   sector-specific**, not a permanent natural-person identifier. Card replacement
   and multiple eligible documents still need an operational uniqueness/recovery
   process; the portal explicitly warns about card changes [13].
3. **EUDI pseudonyms/per-RP identifiers — revisit when specified and available.**
   German official guidance lists pseudonyms among later features [7]. A stable,
   issuer-authenticated, RP-scoped person handle could avoid names, if its
   issuance, recovery and uniqueness semantics suit municipal participation.
   No such handle was verified in the inspected German PID metadata/flow [3, 4].
   ARF support for pseudonym use is not proof that a specific wallet exposes a
   reissuance-stable person identifier; its concrete API and lifecycle remain
   unverified for this integration.
4. **Direct local SD-JWT cryptographic verification now — rejected for staging.**
   Reimplementing issuer trust-list, certificate, status, HAIP encryption and
   registration handling inside the eligibility adapter would create a second
   verifier rather than port the existing tested API seam. A controlled verifier
   with RP registration is required before any production EUDI deployment.

## Consequences

The adapter checks a configured PID address/age policy and deduplicates the
normalized person dataset; it does not independently establish legal residence,
AGS boundaries or unique natural persons. The postal/locality mapping must be
reviewed by the municipality, because postal areas cross municipal boundaries.
The test verifier's test issuer trust is not real identity proofing. For the
first real municipal pilot, use the in-person policy; this EUDI policy is a
separate staging interoperability exercise, not a second enrollment channel.
Own-verifier operation, RP registration, German same-device/certificate
integration, device testing, data-protection review and identity-recovery
procedures are prerequisites for production, not promises made by these tests.

## Sources

Primary sources inspected on 2026-10-08 (mutable documentation/metadata):

1. [EU verifier README, API and trust disclaimer](https://github.com/eu-digital-identity-wallet/eudi-srv-verifier-endpoint), [OpenAPI](https://github.com/eu-digital-identity-wallet/eudi-srv-verifier-endpoint/blob/main/src/main/resources/public/openapi.json), [wallet-result response implementation](https://github.com/eu-digital-identity-wallet/eudi-srv-verifier-endpoint/blob/main/src/main/kotlin/eu/europa/ec/eudi/verifier/endpoint/port/input/GetWalletResponse.kt).
2. [EU test PID issuer metadata](https://issuer.eudiw.dev/.well-known/openid-credential-issuer): `eu.europa.ec.eudi.pid_vc_sd_jwt`.
3. [Bundesdruckerei German demo PID metadata](https://demo.pid-provider.bundesdruckerei.de/.well-known/openid-credential-issuer): `pid-sd-jwt`.
4. [German wallet architecture: PID presentation](https://bmi.usercontent.opencode.de/eudi-wallet/wallet-development-documentation-public/latest/architecture-concept/03-data-flows/22-pid-presentation.html), particularly steps 004–008, 013, 031 and Batch Credential Refresh.
5. [EUDI ARF 1.9.0 Annex 3.01 PID Rulebook](https://eudi.dev/1.9.0/annexes/annex-3/annex-3.01-pid-rulebook/), §§2.2–2.3 and 4.1.
6. [German wallet architecture: PID issuance](https://bmi.usercontent.opencode.de/eudi-wallet/wallet-development-documentation-public/latest/architecture-concept/03-data-flows/21-pid-issuance.html), especially steps 040, 048 and 063–068.
7. [German government's wallet FAQ](https://eudi-wallet.gov.de/en/faq) and [official project overview](https://eudi-wallet.gov.de/en/). Early-2027/later-pseudonym wording was confirmed by the FAQ's indexed primary-source text; the static reader exposes the FAQ questions but not expanded answers. The overview confirms availability from 2027.
8. [German RP technical integration and registration requirements](https://bmi.usercontent.opencode.de/eudi-wallet/developer-guide/rp/onboarding/rp_highlevel_onboarding/) and [PID presentation validation guide](https://bmi.usercontent.opencode.de/eudi-wallet/developer-guide/rp/guide/presentation/pid_presentation/).
9. [OpenID for Verifiable Presentations 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html), DCQL and response binding; [SD-JWT RFC 9901](https://www.rfc-editor.org/rfc/rfc9901.html), disclosure processing and key binding.
10. [BSI TR-03127 v1.40 PDF](https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Publikationen/TechnischeRichtlinien/TR03127/BSI-TR-03127_1-40.pdf?__blob=publicationFile&v=3), §§3.4.3, 4.4.2, 4.4.5–4.4.6, 4.7 and 5.2.1.
11. [BSI TR-03110 overview and protocol specifications](https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/Technische-Richtlinien/TR-nach-Thema-sortiert/tr03110/TR-03110_node.html).
12. [Personalausweisportal: Berechtigungszertifikate](https://www.personalausweisportal.de/Webs/PA/DE/verwaltung/technik/berechtigungszertifikate/berechtigungszertifikate-node.html).
13. [Personalausweisportal: Pseudonym](https://www.personalausweisportal.de/Webs/PA/DE/wirtschaft/technik/pseudonym/pseudonym-node.html). Portal statements confirmed from indexed primary-source excerpts; direct static retrieval was blocked by its cookie-check page. Full current portal content was not independently retrieved.
