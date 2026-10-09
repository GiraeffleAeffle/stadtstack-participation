# Deployment

Staging only: anonymous **advisory, non-binding** participation, not an official
municipal election. Nothing in this runbook authorises publication, DNS changes,
chain transactions or cluster writes by an assistant. The owner performs them.
See [OPERATIONS.md](OPERATIONS.md) for policy and registry commands and
[PILOT_STRAUSBERG.md](PILOT_STRAUSBERG.md) for the go/no-go decisions.

## Architecture and packaging

One exact HTTPS host, `mitmachen.stadtstack.eu`, serves `/` (participants),
`/pruefung` (attestors), `/assets/*` and `/v1/*` through HAProxy Ingress. Never
share this host with another application or set a parent-domain WebAuthn rpId:
passkeys and their PRF material are bound to this exact host. A host change
requires new credentials and re-enrollment, not a redirect-based migration.

The multi-stage Dockerfile uses the same digest-pinned Node 24 bookworm-slim
base as Ledger of Life (Node >=22.18 is required). It builds the Vite clients,
installs production-only dependencies separately, and copies `src/`,
`artifacts/`, `web/dist` and `package.json`. The server reads
`artifacts/membership_vote.json` relative to its source; clients use the bundled
artifact. No contract toolchains or keys enter the runtime image. The build
context is deny-by-default, excluding `.git`, dependencies, contract libraries,
circuit targets, tests, env files and local databases.

Runtime is uid/gid 1000, read-only root, drop ALL capabilities, RuntimeDefault
seccomp, no privilege escalation and no service-account token. It listens on
container/Service port **3000** (`HOST=0.0.0.0`); TLS terminates at the ingress.
`/healthz` is the startup/readiness/liveness path. Verification is in process:
initial requests are 500m CPU/1 GiB RAM and limits 2 CPU/4 GiB; measure verification
latency/RSS before increasing concurrency. One replica and **Recreate** are
intentional: SQLite has one application writer and an RWO data volume.

## Runtime configuration

| Setting | Chart value / purpose |
| --- | --- |
| `DISPLAY_NAME` | `config.DISPLAY_NAME`, `Strausberg`; German client label |
| `OPERATOR_NAME`, `OPERATOR_IS_MUNICIPALITY` | `config.*`, `Stadtstack` and `"false"`: the pages say it is an independent offer, not one of the city administration |
| `HOST`, `PORT` | Fixed `0.0.0.0`, `3000` |
| `DATABASE_PATH` | Fixed `/data/participation.sqlite` |
| `POLICY_PATH` | `/run/policy/policy.json`, complete public `policy` value mounted from ConfigMap |
| `WEB_DIST_DIR` | `/app/web/dist` |
| `CHAIN_ID`, `REGISTRY_ADDRESS`, `PUBLIC_RPC_URL` | `config.*`; empty chart values are omitted from runtime env until configured, then all three must be non-empty; Chiado chain ID `10200`; RPC URL is public browser configuration and must contain no credential |
| `CLIENT_KEY_HEADER` | `x-real-ip`, only safe behind the reviewed ingress |
| `ISSUER_SIGNING_KEY_FILE` | `/run/secrets/participation/issuer-signing-key.pem`; required Ed25519 PKCS#8 PEM |
| `EUDI_UNIQUENESS_KEY_FILE` | `/run/secrets/participation/eudi-uniqueness-key`; mounted only for `eudi_pid_v1`, >=32 **raw random bytes**, not hex/PEM |
| `EUDI_INTENDED_USE_ID` | `config.EUDI_INTENDED_USE_ID`, staging default `TEST-01` |
| `ROEBEL_RPC_URL` | Only for NFT adapter; not used by this in-person pilot. A separate deployment must explicitly allow its RPC IPs. |

Issuer and EUDI key files are Secret `participation-secrets`, mode 0440 with
fsGroup 1000. Keep the EUDI key stable: replacing it breaks duplicate-person
recognition for existing references. Back it up separately, encrypted, along
with the issuer key; neither belongs in policy, Git, the image or SQLite.
One policy selects **one** adapter. Do not mix in-person and EUDI admission for
one pilot. The EU verifier is a test verifier, not production identity assurance;
only test PIDs should be sent to it. See [ADR 0006](adr/0006-eudi-pid-adapter.md).

### Network and proxy identity

Namespace creation is outside Helm, in `deploy/namespace.yaml`, exactly like
Ledger: Pod Security restricted pinned to Kubernetes v1.36. Ingress class is
`haproxy`, issuer `letsencrypt-prod`, controller namespace `ingress-system`.
Host-network HAProxy appears as the reviewed node/Flannel gateway IPs; these
specific ingress sources mirror Ledger. The HTTP-01 solver receives only the
same ingress sources on 8089. All other traffic is denied by default. Backup
Pods have no network permissions.

Ledger's chart/docs do not specify a trusted client-address header.
[HAProxy Ingress documentation](https://haproxy-ingress.github.io/docs/configuration/keys/#forwardfor)
says `X-Real-IP` receives the source address, while X-Forwarded-For handling is
configurable. This chart additionally **overwrites** X-Real-IP with `%[src]` in
the backend; it does not trust a user-supplied or comma-appended XFF value.
Before admitting people, verify the controller accepts this annotation, strips
forged values, and receives the actual client source via the load balancer.
If it sees only the load balancer, limiting is shared until the infrastructure
owner fixes trusted PROXY protocol/source preservation. Never trust this header
on a directly reachable Node service. Disable/review ingress/LB request logs,
tracing and dumps; the app's no-store header does not prevent transport logs.

Egress is DNS to kube-dns (TCP/UDP 53), and TCP 443 to **only** explicitly
reviewed RPC IPs (`egress.rpcCidrs`) plus verifier IPs (`egress.eudiCidrs`) when
EUDI is selected. Standard Kubernetes NetworkPolicy cannot match FQDNs:
resolve each configured HTTPS hostname with `dig +short A HOST` and
`dig +short AAAA HOST`, record the date/provider, and pin individual public
addresses as /32 or /128. Never add private/metadata/cluster IPs or `0.0.0.0/0`.
Shared CDN IPs permit other names on that IP; TLS hostname validation still
applies but this is not hostname-level isolation. DNS changes fail closed;
re-review and release updated IPs. EUDI server host is
`verifier-backend.eudiw.dev`; wallet links are opened by the client, not fetched
by the server. Browser RPC access is outside pod NetworkPolicy and needs CORS.

## Owner-only first release, in order

1. **DNS:** add an A record `mitmachen.stadtstack.eu` to the same public ingress
   IP as `ledger.stadtstack.eu`. Read-only `dig +short ledger.stadtstack.eu`
   returned **77.42.11.9 on 8 October 2026**. Recheck before changing DNS; do
   not invent an AAAA record. Reserve this host for this app alone.
2. **Safe on Gnosis Chiado:** create a Safe on chain 10200, choose named
   independent signers and a threshold, and fund only the needed test gas.
   Record the Safe address and recovery process. Admin and election operator
   authority both belong to the Safe, not the deployment EOA or app server.
3. **Registry:** use the Forge deployment script in [OPERATIONS.md](OPERATIONS.md)
   with explicit Safe admin/operator and the pinned generated verifier. The
   owner signs/sends transactions, verifies chain ID, code and role addresses,
   and records registry/verifier addresses and deployment receipts. Configure
   all three public chain env values together and resolve the selected public
   HTTPS RPC host's egress addresses.
4. **Issuer key and policy:** create a private directory outside all repositories
   (0700), generate `issuer-signing-key.pem` (0600) with `npm run operator --
   issuer-key`, and build a policy with `operator policy` using the pinned
   Stadtstack registry snapshot, `strausberg`, its verified AGS, exact host,
   chosen basis and three attestor public keys. Follow the exact flags/examples
   in OPERATIONS. Confirm issuer public key differs from every attestor key;
   export the Stadtstack verifier policy. Write the validated policy, wrapped
   as `{ "policy": … }`, to `deploy/values/mitmachen.stadtstack.eu.policy.json`;
   helmfile reads it after the main values file. Never edit it by hand.
   For EUDI-only testing generate a separate 32-byte random
   `eudi-uniqueness-key` (0600) and use the EUDI policy/egress instead.
5. **Cluster Secret:** after successful Verify CI, the owner publishes an
   `image-*` tag, makes the GHCR package public once, copies the workflow's
   **digest**, not its tag, into the values file, and commits/pushes the public
   deploy tree. The wrapper refuses missing digests, policies and unpushed
   commits even for namespace/Secret setup. From an interactive terminal:
   ```bash
   cd ~/Code/strausberg-zk-residency
   export LIVE_STADTSTACK_PARTICIPATION_ACK=release-stadtstack-participation-through-deploy-apply-only-v1
   bash infra/hetzner-talos/scripts/apply-live-stadtstack-participation.sh --namespace
   bash infra/hetzner-talos/scripts/apply-live-stadtstack-participation.sh --secret "$HOME/.config/stadtstack-participation/keys"
   ```
   The key directory must contain only `issuer-signing-key.pem` and optionally
   `eudi-uniqueness-key`. The script snapshots private, owner-only regular files
   without following links, never prints their bytes, and replaces the entire
   Secret. On later rotation it restarts the app; preserve existing required keys.
6. **First release:** stop the Freelens daily WireGuard viewer first. Ensure the
   bootstrap recovery gate is valid and the pinned local tools are installed,
   including Helm diff. `PARTICIPATION_REPO` can override the default
   `~/Code/stadtstack-participation`. Then:
   ```bash
   bash infra/hetzner-talos/scripts/apply-live-stadtstack-participation.sh --diff-only
   bash infra/hetzner-talos/scripts/apply-live-stadtstack-participation.sh --release
   ```
   Read every diff and type the exact confirmations. The wrapper exports only
   committed `deploy/` by object ID, requires HEAD on its pushed upstream,
   serialises the daily identity, checks wireproxy digest, tool versions,
   bootstrap recovery and closed public management ports, and removes temporary
   plaintext credentials/tunnel on exit. `deploy/apply.sh` renders before access,
   refuses Helm connection overrides, pins one context, checks kube-system UID
   `7bc769bc-e860-4d54-a0d5-d426f3a52420`, previews namespace/backup claim and Helm
   changes, and applies only this namespace, Secret and release. Atomic Helm
   timeout is 600s; old pending releases can recover to a last good revision only
   after 15 minutes and a separate confirmation. No general kubectl shell is
   exposed. The infra wrapper is a new local owner file, not committed here.

## Persistent data, backup and restore

`participation-data`: 2 Gi RWO `hcloud-volumes`, Helm keep policy. SQLite includes
private eligibility/enrollment/evidence mappings, signatures, receipts,
revocations, replay records, elections/anchors and anonymous ballots/tallies.
Never copy only a live `.sqlite` file and omit its WAL.

Every six hours UTC, a bounded 300s CronJob uses Node's SQLite online backup API,
including committed WAL pages during concurrent writes. Same-node affinity
allows sharing the web RWO volume. It has no Secret/token/network access, no
retry, Forbid concurrency, and retains one successful/two failed Jobs.
Mode-0600 snapshots are integrity-checked before atomic rename and newest **28
successful snapshots** are retained (about seven days, longer if jobs fail).
Partials are not valid restore inputs. The separate 2 Gi `participation-backups`
claim is applied **outside Helm**, like Ledger, to avoid WaitForFirstConsumer
blocking an atomic release. Both volumes are sensitive. This is not an offsite
backup: the owner must encrypt/export a verified snapshot to independent storage
and drill restoration; agree expiry for exported copies too.

Restore needs a separately authorised owner admin session (the release wrapper
cannot exec helpers or scale). Record the web pod's node/digest; suspend backups
and wait for active Jobs, scale the app to zero, then use a restricted uid/gid
1000 maintenance Pod on that node, mounting data read/write and backups
read-only, without token/network/Secrets. Run `PRAGMA integrity_check` on the
selected successful snapshot, retain an encrypted forensic copy of the current
DB if warranted, remove obsolete live WAL/SHM **only after all writers stop**,
and copy the snapshot to `/data/participation.sqlite` as uid/gid 1000 mode 0600.
Remove helper, restore one web replica, check health/policy and re-enable backups.
Do not silently resume a restored open poll: compare every chain anchor/window,
accepted-ballot set and stored mirror. Restore can lose acknowledged ballots;
stop the affected poll, disclose the incident and never manufacture votes.

## Post-deploy verification / go-no-go

- Certificate Ready; HTTPS redirects; `/healthz` is 200, `/v1/policy` matches the
  public policy and issuer key, `/v1/client-config` has Strausberg basis/adapter
  and exact Chiado registry/RPC values.
- `/` and `/pruefung` and hashed assets load. Check CSP own origin + configured
  RPC only, wasm permission, worker self/blob, COOP same-origin, COEP require-corp,
  Referrer-Policy no-referrer, nosniff and camera/passkeys own-origin permissions.
  API JSON is no-store and sets no cookies. Check ingress/LB logging separately.
- On **this exact production hostname**, create/assert a PRF-capable passkey,
  inspect subject fingerprint, complete two distinct attestations and enrollment;
  reject unsupported PRF without a secret-storage fallback. Test actual pilot
  devices, not only a virtual authenticator.
- Operator checks Safe roles, policy keys, anchor/metadata/window chain parity;
  complete a clearly labelled rehearsal poll, tally and independently verify the
  public JSON/hash before inviting people. No binding-election claims.
- Confirm backup first success, volume capacity, private-header overwrite,
  forbidden private/network egress, and expected HTTPS destinations. No local
  Docker/chart validation proves live policy enforcement.

## Rollback / emergency stop

Stop invitation/enrollment immediately for privacy, eligibility, verifier or
client-integrity incidents. Owner can suspend backups and scale web to zero via
an independently authorised admin session; preserve evidence securely without
request bodies or secrets. Publish a plain incident notice via a separately
reviewed channel. A stopped server does not change immutable chain windows or
invalidate existing ballots; the contract cannot prematurely close a poll.

For a code-only rollback, pin the previous known-good image digest in values,
review DB/schema compatibility and current policy/key validity, commit/push, and
use the same wrapper diff/release. Alternatively an authorised owner session may
`helm --kube-context CONTEXT -n stadtstack-participation rollback
stadtstack-participation REVISION --wait --timeout 10m` after checking the same
cluster UID. Never uninstall/delete PVCs to roll back. Helm rollback does not
restore SQLite, external Secrets, Safe state, or chain roots. Never downgrade to
code that weakens uniqueness/privacy checks. A compromised issuer/attestor key
requires a reviewed new policy and custody response, not merely an old image.

## Local packaging evidence (8 October 2026)

The Colima `docker build -t stadtstack-participation:local .` succeeded (native
arm64). The image ran once as its non-root user with read-only root, tmpfs /tmp,
ALL capabilities dropped, no-new-privileges and a fresh random throwaway issuer
key/policy. `/healthz` and `/v1/policy` both returned HTTP 200, JSON/no-store and
the security headers; no publication or live release occurred. Colima does not
share macOS `/tmp`, so the first bind-mount attempt failed before container
creation; test fixtures were regenerated in a shared private temporary folder.
The container and all throwaway files were removed afterwards.

The configured chart passed strict Helm lint (one chart, zero failures) and
Helm/Helmfile offline rendering. The initial Helmfile render exposed a wrong
values filename; it was corrected. Both deployment scripts passed shellcheck.
The committed empty digest/policy are intentional first-release gates, not a
deployable sample identity or fabricated image. Validate with the owner's real
public policy and published digest before release. CI publication, amd64 image
runtime, public DNS/TLS, real-device PRF, live network enforcement and backup
restore remain owner verification gates, not claims from these local checks.
