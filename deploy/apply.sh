#!/usr/bin/env bash
# Bounded release of Stadtstack Participation to the reviewed Talos cluster. On the owner's machine it runs inside
# strausberg-zk-residency's infra/hetzner-talos/scripts/apply-live-stadtstack-participation.sh, which opens the session.
#
#   deploy/apply.sh --diff-only      read-only: what would change, and whether the Secret exists
#   deploy/apply.sh --namespace      first run only: create the namespace (so the Secret can be stored), nothing else
#   deploy/apply.sh --secret DIRECTORY    store Secret participation-secrets from an owner-only key directory outside any repository
#   deploy/apply.sh                  the release: diff, typed confirmation, helmfile apply, rollout and status;
#                                    first, after its own typed confirmation, it recovers a release that an
#                                    interrupted helm process left pending
#
# Every mode refuses a render without a real image digest and any cluster but the reviewed one. One kube context is
# resolved at the start and passed explicitly to every kubectl and helmfile call, so the cluster that was checked is
# the cluster that is changed. Nothing here reads back, decodes or prints a Secret value.
set -euo pipefail

# Connection overrides can redirect Helm away from the context kubectl verifies.
# Refuse even empty exported values before invoking any external command.
for override in HELM_KUBEAPISERVER HELM_KUBECAFILE HELM_KUBETOKEN \
  HELM_KUBEASUSER HELM_KUBEASGROUPS HELM_KUBEINSECURE_SKIP_TLS_VERIFY HELM_KUBETLS_SERVER_NAME; do
  if [[ "${!override+x}" == x ]]; then
    printf 'Refusing connection override %s; unset it before running.\n' "$override" >&2
    exit 1
  fi
done

usage() { printf 'Usage: deploy/apply.sh [--diff-only | --namespace | --secret DIRECTORY]\n' >&2; }
mode='release'
secret_file=''
case "${1:-}" in
  "") ;;
  --diff-only) mode='diff' ;;
  --namespace) mode='namespace' ;;
  --secret) mode='secret'; secret_file="${2:-}"; [[ -n "$secret_file" ]] || { usage; exit 2; } ;;
  *) usage; exit 2 ;;
esac
if [[ "$mode" == secret ]]; then (( $# == 2 )) || { usage; exit 2; }; elif (( $# > 1 )); then usage; exit 2; fi
# Resolve the Secret file's directory before the script changes directory. The file itself is opened exactly once,
# later, without following links.
if [[ -n "$secret_file" ]]; then
  secret_parent="$(cd -- "$(dirname -- "$secret_file")" 2>/dev/null && pwd -P)" || { printf 'Secret file directory not found: %s\n' "$secret_file" >&2; exit 1; }
  secret_file="${secret_parent}/$(basename -- "$secret_file")"
fi

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$script_dir"
KUBECTL="${KUBECTL:-kubectl}"
NAMESPACE=stadtstack-participation
for binary in git helmfile helm "$KUBECTL" curl python3; do
  command -v "$binary" >/dev/null || { printf 'Required binary missing: %s\n' "$binary" >&2; exit 1; }
done
if ! [[ "$(helm plugin list)" =~ (^|$'\n')diff[[:space:]] ]]; then
  printf 'Install the Helm diff plugin before proceeding.\n' >&2
  exit 1
fi

# 1. Render first: this is the missing-digest refusal, and it needs no cluster.
render="$(helmfile -f helmfile.yaml template)"

# 2. One context for everything. Helm and helmfile have their own context overrides; refuse any that disagree.
context="$("$KUBECTL" config current-context)"
[[ -n "$context" ]] || { printf 'No current kube context.\n' >&2; exit 1; }
for override in HELM_KUBECONTEXT HELMFILE_KUBE_CONTEXT; do
  if [[ -n "${!override:-}" && "${!override}" != "$context" ]]; then
    printf '%s is %s but kubectl uses %s; unset it or switch contexts.\n' "$override" "${!override}" "$context" >&2
    exit 1
  fi
done
kc() { "$KUBECTL" --context "$context" "$@"; }
hf() { helmfile --kube-context "$context" -f helmfile.yaml "$@"; }
server="$(kc config view --minify -o jsonpath='{.clusters[0].cluster.server}')"

# 3. The reviewed cluster only.
expected_uid=7bc769bc-e860-4d54-a0d5-d426f3a52420
actual_uid="$(kc get namespace kube-system -o jsonpath='{.metadata.uid}')"
if [[ "$actual_uid" != "$expected_uid" ]]; then
  printf 'Wrong cluster: kube-system UID does not match the reviewed Talos cluster (context %s).\n' "$context" >&2
  exit 1
fi
printf 'Cluster: context %s, API %s, kube-system UID verified.\n' "$context" "$server"

confirm() {
  printf 'Target: context %s, API %s, namespace %s.\n' "$context" "$server" "$NAMESPACE" >/dev/tty
  printf 'Type exactly "%s" to continue: ' "$1" >/dev/tty
  local answer
  IFS= read -r answer </dev/tty
  [[ "$answer" == "$1" ]] || { printf 'Confirmation did not match; nothing changed.\n' >&2; exit 1; }
}

# A preview must succeed: kubectl diff exits 0 (no change) or 1 (changes); anything else is an error, not a preview.
preview() {
  local status=0
  kc diff --server-side --field-manager=participation-apply -f "$1" || status=$?
  (( status <= 1 )) || { printf 'The preview of %s failed (kubectl diff exit %s); nothing changed.\n' "$1" "$status" >&2; exit 1; }
}

namespace_exists=false
kc get namespace "$NAMESPACE" >/dev/null 2>&1 && namespace_exists=true

if [[ "$mode" == namespace ]]; then
  preview namespace.yaml
  confirm "create namespace $NAMESPACE"
  kc apply --server-side --field-manager=participation-apply -f namespace.yaml
  printf 'Next: store the Secret with --secret DIRECTORY (see docs/DEPLOYMENT.md), then run --diff-only.\n'
  exit 0
fi

if [[ "$mode" == secret ]]; then
  "$namespace_exists" || { printf 'Namespace %s does not exist yet. First run: --namespace\n' "$NAMESPACE" >&2; exit 1; }
  if git -C "$secret_file" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    printf 'Secret directory is inside a git work tree; keep it outside every repository.\n' >&2; exit 1
  fi
  # Snapshot only the two allowed files; never print secret contents. Directory
  # and each opened regular file must be yours, private, not linked, and outside Git.
  snapshot_dir="$(mktemp -d "${TMPDIR:-/tmp}/participation-secret.XXXXXX")"
  chmod 700 "$snapshot_dir"
  trap 'rm -rf -- "$snapshot_dir"' EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  require_eudi=false; [[ "$render" != *EUDI_UNIQUENESS_KEY_FILE* ]] || require_eudi=true
  python3 - "$secret_file" "$snapshot_dir" "$require_eudi" <<'PY'
import os, stat, sys
source, target, require_eudi = sys.argv[1:]
fd = os.open(source, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    details = os.fstat(fd)
    if details.st_uid != os.getuid() or stat.S_IMODE(details.st_mode) & 0o077:
        raise SystemExit('Secret directory must be owned by you and mode 0700')
    names = os.listdir(fd)
    allowed = {'issuer-signing-key.pem', 'eudi-uniqueness-key'}
    if not set(names) <= allowed or 'issuer-signing-key.pem' not in names:
        raise SystemExit('Directory must hold issuer-signing-key.pem and optionally eudi-uniqueness-key only')
    if require_eudi == 'true' and 'eudi-uniqueness-key' not in names:
        raise SystemExit('EUDI policy requires eudi-uniqueness-key; refusing to replace Secret without it')
    for name in sorted(names):
        key = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
        try:
            s = os.fstat(key)
            if not stat.S_ISREG(s.st_mode) or s.st_uid != os.getuid() or s.st_nlink != 1 or stat.S_IMODE(s.st_mode) & 0o077:
                raise SystemExit('Secret files must be regular, owned by you, mode 0600, one link')
            data = os.read(key, 65537)
            if not data or len(data) > 65536:
                raise SystemExit('Secret file size invalid')
            if name == 'issuer-signing-key.pem' and not data.startswith(b'-----BEGIN PRIVATE KEY-----'):
                raise SystemExit('Issuer key must be PKCS#8 PEM generated by operator issuer-key')
            if name == 'eudi-uniqueness-key' and len(data) < 32:
                raise SystemExit('EUDI uniqueness key must contain at least 32 raw random bytes')
            out = os.open(os.path.join(target, name), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(out, 'wb') as handle:
                handle.write(data)
        finally:
            os.close(key)
finally:
    os.close(fd)
PY
  printf 'Replacing Secret participation-secrets; existing deployment restarts. Key bytes are never printed.\n'
  confirm "store secret participation-secrets"
  kc -n "$NAMESPACE" create secret generic participation-secrets --from-file="$snapshot_dir" --dry-run=client -o yaml |
    kc apply --server-side --field-manager=participation-apply -f -
  deployment="$(kc -n "$NAMESPACE" get deployment stadtstack-participation --ignore-not-found -o name)"
  if [[ -n "$deployment" ]]; then
    kc -n "$NAMESPACE" rollout restart deployment/stadtstack-participation
    kc -n "$NAMESPACE" rollout status deployment/stadtstack-participation --timeout=180s
  fi
  printf 'Next: --diff-only, then the release.\n'
  exit 0
fi

# 4. The Secret must exist before a release: without it the pod never starts and the atomic release rolls back.
secret_ready=false
if "$namespace_exists"; then
  # Key NAMES only. Go-template variables belong to kubectl, not the shell.
  # shellcheck disable=SC2016
  keys="$(kc -n "$NAMESPACE" get secret participation-secrets -o go-template='{{range $key, $value := .data}}{{printf "%s\n" $key}}{{end}}' 2>/dev/null)" || keys=""
  if [[ "$keys" == *issuer-signing-key.pem* ]]; then
    secret_ready=true
    adapter=other; [[ "$render" != *EUDI_UNIQUENESS_KEY_FILE* ]] || adapter=eudi_pid_v1
    if [[ "$adapter" == eudi_pid_v1 && "$keys" != *eudi-uniqueness-key* ]]; then secret_ready=false; fi
  fi
fi
secret_help() {
  if ! "$namespace_exists"; then
    printf 'Namespace %s does not exist yet. First run: deploy/apply.sh --namespace\n' "$NAMESPACE" >&2
  fi
  printf '%s\n' 'Secret participation-secrets must contain issuer-signing-key.pem and, for EUDI, eudi-uniqueness-key. Use an owner-only directory outside every repository (see docs/DEPLOYMENT.md), then run --secret DIRECTORY.' >&2
}

# Helm's own record. A pending-* status means a helm process stopped mid-operation (for example, its terminal closed).
# Helm then refuses every upgrade ("another operation is in progress") until the release is rolled back.
release_state=''
if "$namespace_exists"; then
  # Prints: latest revision, its status, the last deployed or superseded revision (0 if none), seconds since update.
  release_state="$(helm --kube-context "$context" -n "$NAMESPACE" history stadtstack-participation --max 20 -o json 2>/dev/null |
    python3 -c '
import json, re, sys
from datetime import datetime, timezone
rows = json.load(sys.stdin)
if rows:
    last = rows[-1]
    good = [row["revision"] for row in rows if row["status"] in ("deployed", "superseded")]
    updated = datetime.fromisoformat(re.sub(r"\.[0-9]+", "", last["updated"]).replace("Z", "+00:00"))
    print(last["revision"], last["status"], good[-1] if good else 0, int((datetime.now(timezone.utc) - updated).total_seconds()))
' 2>/dev/null)" || release_state=''
fi
if [[ -n "$release_state" ]]; then
  read -r revision status last_good age <<<"$release_state"
  printf 'Helm release stadtstack-participation: revision %s, %s.\n' "$revision" "$status"
  case "$status" in
    pending-install | pending-upgrade | pending-rollback)
      if [[ "$mode" != release ]]; then
        printf 'Revision %s is stuck in %s; the release recovers it first, after its own confirmation.\n' "$revision" "$status"
      elif (( last_good == 0 )); then
        printf 'Revision %s is stuck in %s and no earlier revision was ever deployed; nothing to roll back to.\n' "$revision" "$status" >&2
        exit 1
      elif (( age < 900 )); then
        printf 'Revision %s changed %s seconds ago; a helm process may still be running (its timeout is 600 seconds). Retry after 15 minutes.\n' "$revision" "$age" >&2
        exit 1
      else
        helm --kube-context "$context" -n "$NAMESPACE" history stadtstack-participation --max 5
        printf 'Revision %s is stuck in %s: a helm process was interrupted, and Helm refuses every upgrade until the release is rolled back.\n' "$revision" "$status"
        printf 'Recovery rolls back to revision %s, the last good one, and waits for it. The release then continues with its own diff and confirmation.\n' "$last_good"
        confirm "recover $NAMESPACE"
        helm --kube-context "$context" -n "$NAMESPACE" rollback stadtstack-participation "$last_good" --wait --timeout 10m
      fi
      ;;
  esac
fi

# 5. Show exactly what would change.
# The snapshot claim is applied outside the chart (see backups-pvc.yaml); it needs the namespace.
if "$namespace_exists"; then
  preview namespace.yaml
  preview backups-pvc.yaml
fi
hf diff --include-tests

if [[ "$mode" == diff ]]; then
  "$secret_ready" || secret_help
  exit 0
fi
"$secret_ready" || { secret_help; exit 1; }

# 6. The release, after a typed confirmation.
confirm "apply $NAMESPACE"
kc apply --server-side --field-manager=participation-apply -f namespace.yaml
kc apply --server-side --field-manager=participation-apply -f backups-pvc.yaml
hf apply --include-tests
kc -n "$NAMESPACE" rollout status deployment/stadtstack-participation --timeout=180s

# 7. The first certificate can take a minute or two. A release that is up but still waiting for it is not a failure.
host="$(kc -n "$NAMESPACE" get ingress stadtstack-participation -o jsonpath='{.spec.rules[0].host}')"
tls_secret="$(kc -n "$NAMESPACE" get ingress stadtstack-participation -o jsonpath='{.spec.tls[0].secretName}')"
ready=''
for _ in $(seq 1 24); do
  ready="$(kc -n "$NAMESPACE" get certificate "$tls_secret" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || true)"
  [[ "$ready" == True ]] && break
  sleep 5
done
if [[ "$ready" != True ]]; then
  printf 'Release is running; the certificate for %s is not ready yet. Check: kubectl -n %s describe certificate %s\n' "$host" "$NAMESPACE" "$tls_secret"
  exit 0
fi
curl --fail --silent --show-error "https://${host}/healthz" |
  python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin)))'
