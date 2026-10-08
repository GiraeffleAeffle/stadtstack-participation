# Operations

This runbook operates **advisory, non-binding** participation. [DESIGN.md](DESIGN.md)
is normative; review [THREAT_MODEL.md](THREAT_MODEL.md) before a pilot. Commands
below are operator instructions, not evidence that a deployment or check was run.
Run Node commands from the repository root with Node.js >= 22.18; use Foundry
>= 1.4 for contracts. The operator CLI prepares transactions and never holds a
chain signing key. Safe owners review and execute them separately.

## Registry deployment on Chiado

Use a Safe for `ADMIN_ADDRESS` and a Safe for `OPERATOR_ADDRESS` (they may be the
same Safe). Verify the Safe addresses, owners, threshold and network independently.
The deployment account pays gas; it must not be a role address unless deliberately
chosen as one. Import/fund its encrypted Foundry keystore separately; do not put a
private key in an environment variable or shell command.

From `contracts/`, set the two public role addresses, then simulate:

```sh
export ADMIN_ADDRESS="$ADMIN_SAFE_ADDRESS"
export OPERATOR_ADDRESS="$OPERATOR_SAFE_ADDRESS"
forge script script/DeployElectionRegistry.s.sol:DeployElectionRegistry \
  --rpc-url https://rpc.chiadochain.net --account keystore
```

After reviewing the simulation and explicitly approving deployment, the operator
can submit the same script:

```sh
forge script script/DeployElectionRegistry.s.sol:DeployElectionRegistry \
  --rpc-url https://rpc.chiadochain.net --account keystore --broadcast
```

The script deploys `MembershipVoteVerifier` then `ElectionRegistry`, prints both
addresses and the deployer/admin/operator, and asserts that the deployer has each
role **if and only if** it was explicitly configured for that role. It uses no
`forge-std` dependency. Without `--broadcast`, Forge only simulates deployment.
Do not mistake simulated addresses for deployed contracts.

Before configuring the service, check the confirmed receipts and runtime code on
Chiado (chain ID **10200**). Read `verifier()`, `DEFAULT_ADMIN_ROLE()`,
`ELECTION_OPERATOR_ROLE()` and `hasRole(bytes32,address)` on the deployed registry.
Check the named Safes have their intended roles, the deployment account has neither
unless explicitly configured, and the verifier matches the deployment record.
Keep the addresses, chain ID, deployment receipts and reviewed artifact hashes as
release evidence. This script does not configure a Safe or rotate its owners.

## Service configuration

Run the server as `node src/server.ts`, behind TLS on the policy's exact
`publicBaseUrl` host. Do not share that host with other applications or bind
passkeys to a parent domain. Build the reviewed web release with `npm run web:build`
before serving it; do not replace reviewed assets during a poll without review.

| Environment | Requirement |
| --- | --- |
| `DATABASE_PATH` | Issuer-private SQLite database path; restrict directory/file and backup access. CLI and server must use the same database. |
| `POLICY_PATH` | Path to the validated public issuer policy JSON. CLI and server must use the same policy version. |
| `ISSUER_SIGNING_KEY_FILE` | Private Ed25519 PKCS#8 PEM file matching the public policy key; restrict access, never publish it. |
| `DISPLAY_NAME` | Required municipality display name used by the web client. |
| `HOST` | Bind address, default `127.0.0.1`; container deployments can set `0.0.0.0` behind a restricted proxy. |
| `CLIENT_KEY_HEADER` | Optional trusted proxy client-key header for transient rate limiting; the proxy must overwrite it and block direct access. Never trust a client-supplied value. |
| `EUDI_UNIQUENESS_KEY_FILE` | Required for `eudi_pid_v1`: private raw file containing at least 32 random bytes, separate from the issuer signing key. |
| `EUDI_INTENDED_USE_ID` | EUDI verifier intended-use identifier; default `TEST-01` for the test backend. |
| `PORT` | Listening port, default `3000`. |
| `WEB_DIST_DIR` | Web distribution directory, default `web/dist` in this repository. |
| `CHAIN_ID` | Intended election registry chain ID; Chiado is `10200`. |
| `REGISTRY_ADDRESS` | Deployed election registry address, not the verifier address. |
| `PUBLIC_RPC_URL` | Public browser-accessible RPC URL; no credentials or private tokens. |
| `RPC_URL` | Operator CLI's RPC endpoint for authoritative registry reads; may differ from the public endpoint but must return the same chain/registry. |
| `ROEBEL_RPC_URL` | Required when using `roebel_citizen_nft_v1`; RPC endpoint for that policy's citizen-status chain. |

`CHAIN_ID`, `REGISTRY_ADDRESS` and `PUBLIC_RPC_URL` are **all-or-none** server public
configuration. With none configured, client config exposes `chain: null`; voting
must not be advertised as ready. Set all three after deployment. `RPC_URL` is a
separate operator setting and is not exposed to browsers. Never use a secret-bearing
RPC URL for `PUBLIC_RPC_URL`.

Before admitting participants, check `GET /healthz` on the running service and
`GET /v1/client-config` and `GET /v1/policy` through the public TLS origin. Confirm
the display name, municipality/AGS, policy version, adapter kind, issuer key and
chain settings. Confirm `/` and `/pruefung` serve the intended German clients and
that CSP, COOP/COEP, no-store and no-cookie behavior survive the proxy. Health
availability alone does not certify RPC correctness, adapter correctness or
anonymity. Check a PRF-capable passkey on the exact production host; unsupported
PRF must fail closed, not fall back to stored secrets.

Disable request bodies, subject identifiers, proofs, nullifiers, IP addresses and
authentication headers in persistent access logs, traces and analytics, including
at proxies. Protect SQLite journals, backups and crash dumps as private data.
No-store is not a log-retention policy. Record a retention/access policy and test
restoration without rewriting frozen anchors or weakening key protection.

The existing `ISSUER_SIGNING_KEY_SEED_HEX` signing source is an alternative to the
PEM file, not an additional key: configure exactly one source. Prefer the file to
avoid exposing key material through process environments. EUDI's verifier URL is
the policy's `verifierBaseUrl`, not an RPC URL. The hosted
`https://verifier-backend.eudiw.dev` backend and `TEST-01` intended use are staging
only. Production needs a controlled verifier, relying-party registration and
review of issuer-signature, holder-binding and status verification. Back up the
EUDI uniqueness key securely: changing it changes every person's evidence
reference and silently disables duplicate-enrollment detection against existing
enrollments. Never publish either key.

## Issuer key and policy preparation

All CLI commands support `--json`. Output files are local operator artifacts;
do not commit private keys, the database or adapter evidence.

```sh
npm run operator -- issuer-key --out /secure/issuer.pem --json
```

This creates a mode-0600 PKCS#8 PEM and prints the public key. Record that public
key in the policy; verify it differs from every attestor public key. Retain the
private file only in controlled secret storage, and set `ISSUER_SIGNING_KEY_FILE`
to its runtime-mounted location.

Prepare `basis.json` with the exact policy basis keys `residence`,
`minimumAgeYears`, `nationality` and `localityScope`, and `adapter.json` with the
selected adapter configuration described in DESIGN. Use only one adapter per
policy. For in-person eligibility, register at least two distinct attestors and
their validity windows and ownership declarations; never substitute the issuer
key for an attestor. For the citizen-NFT adapter, independently pin its chain,
contract code hash and block tag. For EUDI, review allowed postcode/locality pairs
and claims, expiry and verifier trust before admitting participants.

```sh
npm run operator -- policy \
  --registry /reviewed/stadtstack-registry.json \
  --municipality "$MUNICIPALITY_ID" --policy-version "$POLICY_VERSION" \
  --issuer "$ISSUER_NAME" --issuer-key-id "$ISSUER_KEY_ID" \
  --issuer-public-key "$ISSUER_PUBLIC_KEY" \
  --public-base-url "$PUBLIC_BASE_URL" \
  --receipt-ttl-seconds 600 --status-max-age-seconds 60 \
  --max-event-clock-skew-seconds 60 \
  --allowed-agent-pubkeys "$ALLOWED_AGENT_PUBKEYS" \
  --basis basis.json --adapter adapter.json --out policy.json --json
```

`--allowed-agent-pubkeys` is comma-separated hex. `--attestors FILE` optionally
replaces `adapter.attestors`. If `--registry` is omitted, the default is
the sibling `stadtstack-registry/snapshot/registry.json`, resolved relative to
the CLI module rather than the shell's working directory. Explicitly pin the
reviewed snapshot for a pilot. Verify its digest and municipality-to-AGS mapping,
public HTTPS origin, policy basis, policy version and issuer public key. The CLI
also prints the Stadtstack verifier policy; configure the consuming Stadtstack
deployment with that reviewed projection. Set `POLICY_PATH` to `policy.json`.
Changing eligibility basis or adapter requires deliberate policy/version review,
not an unnoticed edit during an election.

## Poll lifecycle: draft → open → confirm → vote → tally → close → confirm → result

Set `DATABASE_PATH`, `POLICY_PATH` and the adapter runtime configuration above.
Set `RPC_URL`, `CHAIN_ID` and `REGISTRY_ADDRESS` for the intended registry. The CLI
must read the same enrollment/ballot database as the server. Never run a poll
against an empty copy or a different municipality's database.

### 1. Prepare and inspect the frozen draft

Prepare `poll.json` with this shape, using actual reviewed text and contract:

```json
{
  "electionSlug": "mobilitaet-2026",
  "title": "Mobilität im Stadtzentrum",
  "question": "Welche Maßnahme soll zuerst geprüft werden?",
  "choices": [
    { "index": 0, "label": "Mehr sichere Radwege" },
    { "index": 1, "label": "Bessere Busverbindungen" }
  ],
  "participationContract": { "id": "mobilitaet-beratung", "version": 1 }
}
```

Choose reviewed integer Unix-second timestamps, with `OPENS_AT < CLOSES_AT` and
enough future time for Safe execution and confirmation:

```sh
npm run operator -- poll-draft --metadata poll.json \
  --opens-at "$OPENS_AT" --closes-at "$CLOSES_AT" \
  --out open.safe.json --json
```

The command derives the election ID and metadata hash, rechecks current enrollment
eligibility through the configured adapter, builds the depth-16 anchor and stores
the draft. Record its returned `electionId` as `ELECTION_ID`. Inspect the returned
metadata and anchor: municipality/policy, slug, advisory legal effect, contract,
choice indices/labels, timestamps, unique nonzero numerically sorted leaves and
root. Confirm the electorate snapshot and exclusions with the responsible
reviewers. Later enrollment or revocation does not rewrite this frozen anchor.
A full metadata object is also accepted only when its computed identity and
window match the command inputs.

Confirmation, tally and result commands also accept the election ID as a
positional argument instead of `--election-id`; do not supply both forms.
Generated cast references use `cast send --account '<keystore-name>' --rpc-url
"$RPC_URL"` followed by the registry call. Select an authorized signer explicitly;
the runbook's normal execution path remains the operator Safe Transaction Builder.

Inspect `open.safe.json` and `open.safe.json.cast.txt`. Check chain ID, registry
destination, zero transaction value, `openElection` selector/arguments, root,
depth 16, metadata hash, derived scope and window. The cast file is an equivalent
transaction reference, not authorization to use an unrelated EOA.

### 2. Safe owners sign and execute open

Import `open.safe.json` into the **operator Safe's** Transaction Builder on the
intended chain. Owners independently compare every argument against the reviewed
draft, approve at the configured threshold and execute. Opening requires the
operator role; using a deployment EOA does not grant it. Confirm successful
execution and sufficient chain finality under the deployment's agreed policy.
Record the Safe transaction and chain receipt. Do not open a second/different
anchor to repair an already opened poll.

### 3. Confirm the authoritative open in the server mirror

```sh
npm run operator -- poll-confirm-open --election-id "$ELECTION_ID" --json
```

This reads the registry and records its state; preparation alone never marks the
poll open. On any mismatch or RPC failure, stop and investigate, rather than edit
the database. Check `GET /v1/elections` now lists the poll and
`GET /v1/elections/<electionId>` and `/anchor` match the chain record and reviewed
artifacts. Drafts must not appear in the public list.

### 4. Voting

Voting is allowed only in `[opensAt, closesAt)`. Before announcing readiness,
check that the participant client reads the intended registry and compares the
root, metadata hash, derived scope and window before proving locally. Check the
citizen enrolled before the frozen snapshot; late enrollment only prepares a
future poll. Do not ask for a voting secret or attach an eligibility receipt,
subject key, wallet identity, cookie or NIP-98 signature to a ballot.

Monitor health and capacity without persistent ballot/client correlation logs.
A successful `{ "ok": true }` is not a cryptographic inclusion receipt. Do not
promise coercion resistance, revoting, human uniqueness or recovery of a lost
PRF credential. An anchored commitment cannot be replaced while its affected
poll is open.

### 5. Build and audit the tally after the window

```sh
npm run operator -- poll-tally --election-id "$ELECTION_ID" \
  --out close.safe.json --json
```

Run only after `closesAt`; confirm both the service clock and the chain's latest
block time have reached the deadline before executing close. The command builds
and stores the deterministic tally and writes `close.safe.json` plus
`close.safe.json.cast.txt`. Storing the tally closes ballot intake. If a ballot
was accepted while the tally was being built, the command fails with
`tally_stale` and stores nothing; run it again. Independently audit the returned tally: chain-derived
window/root/metadata/scope, circuit/VK identifiers, every proof, valid choice and
signal, unique numerically sorted nullifiers, recomputed counts and
`totalAccepted`. Recompute the canonical JSON SHA-256 tally hash and compare it
with the close transaction. No new per-ballot timestamps belong in the tally.
Retain the exact reviewed tally bytes; do not replace them with a JSON rendering
whose hash has not been checked.

### 6. Safe owners sign and execute close

Import `close.safe.json` into the operator Safe. Independently compare the chain
and registry destination, zero value, `closeElection` election ID, tally hash and
accepted count with the audited tally. Approve and execute only after `closesAt`.
Confirm success/finality and record the Safe transaction and chain receipt.
Do not imply the window extended merely because the close transaction was late.

### 7. Confirm authoritative closure

```sh
npm run operator -- poll-confirm-close --election-id "$ELECTION_ID" --json
```

The chain must be closed and its tally hash/count must match the stored audited
tally. Stop on disagreement. Check the public election is closed and
`GET /v1/elections/<electionId>/tally` returns the audited artifact. Verify that
new ballots are refused. Public auditors can call `verifyBallot` after closure;
closure does not disable proof auditability.

### 8. Review and export the Stadtstack result

Prepare `review.json` as a `ResultContext` (see `src/vote/result.ts`), containing
`id`, `methodKind`, `methodVersion`, `ruleId`, `ruleVersion`, `resultSummary`,
`unresolvedDissent`, `representationAudit`, `limitations`, `reviewedAt`,
`resultArtifactRef`, `minorityReportRef` and `checksumBinding`.
`representationAudit` requires `targetPopulationDescription`, `recruitmentMethod`,
`samplingMethod`, `totalInvited`, `totalStarted`, `totalCompleted`, `limitations`.
Use `null` where sampling method, invitation count or minority report is unknown,
not invented observations. Completion/start/invitation counts must be consistent
and completed count must cover accepted votes. `reviewedAt` is an ISO UTC
timestamp with milliseconds, no earlier than the voting deadline.
`checksumBinding` contains `sourceBrief: { id, briefChecksum, briefEventId }`,
`policyVersion` and `actorBinding: { actorId, actorClass: "participation_reviewer" }`.
Use the actual reviewed source brief and reviewer; keep individual identities,
raw eligibility/credential material and ballot data out of result prose.

```sh
npm run operator -- poll-result --election-id "$ELECTION_ID" \
  --review review.json --out result.json --json
```

Export only after confirmed closure. Review `participation_result_v1` choices and
counts against the tally, the participation contract, checksum binding, review
time, representation limitations, dissent and artifact references. Its
`authorityBinding` must be `"none"`; it is not a binding decision. Publish the
public metadata, anchor, tally and result through the reviewed civic workflow,
never the issuer database or subject-to-commitment/evidence mappings. Preserve
the original artifacts and chain receipts for reproducibility.

## Failure handling

If a Safe transaction is pending or fails, do not confirm it as applied. Read the
registry again on the intended chain and compare with the prepared artifacts
before retrying execution or confirmation. Keep the same reviewed election
identity and immutable anchor; do not manually patch mirror rows. An RPC view or
mirror disagreement is a stop condition. Protect and restore keys/database under
controlled procedures; never recover by generating a citizen secret or silently
changing enrollment evidence references. Publication and hash pinning demonstrate
validity of the published set, not inclusion of every attempted vote or honest
electorate composition. Record those limits in the public pilot review.
