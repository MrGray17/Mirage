#!/usr/bin/env bash
set -Eeuo pipefail

fail() {
  printf 'MIRAGE Qwen acceptance: %s\n' "$*" >&2
  exit 2
}

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

for command in git go docker python3; do
  command -v "$command" >/dev/null 2>&1 || fail "required command not found: $command"
done

if [[ -z "${DOCKER_CONFIG:-}" && -d "$HOME/.docker-wsl" ]]; then
  export DOCKER_CONFIG="$HOME/.docker-wsl"
fi
unset DOCKER_HOST || true
export DOCKER_CONTEXT="${MIRAGE_DOCKER_CONTEXT:-rootless}"

context="${MIRAGE_DOCKER_CONTEXT:-rootless}"
builder="${MIRAGE_DOCKER_BUILDER:-rootless}"
qwen_repository="${MIRAGE_QWEN_REPO:-ghcr.io/mrgray17/mirage-qwen-agent}"
helper_image="${MIRAGE_HELPER_IMAGE:-busybox@sha256:9db7b59979c38555a39def84a31fb98b5296952f9e3afd4f6f11f05b07adfab0}"
model="qwen2.5-coder:1.5b"

[[ "$qwen_repository" =~ ^ghcr[.]io/[a-z0-9]+([._-][a-z0-9]+)*/[a-z0-9]+([._-][a-z0-9]+)*$ ]] ||
  fail "MIRAGE_QWEN_REPO must be a lowercase ghcr.io repository path"
[[ "$helper_image" =~ @sha256:[0-9a-f]{64}$ ]] ||
  fail "MIRAGE_HELPER_IMAGE must be an immutable name@sha256:digest reference"

docker_context() {
  docker --context "$context" "$@"
}

if [[ -n "$(git status --porcelain)" ]]; then
  git status --short >&2
  fail "the source checkout must be clean; commit or stash changes first"
fi

source_commit="$(git rev-parse HEAD)"
short_commit="$(git rev-parse --short=12 HEAD)"
go_version="$(go version | sed -nE 's/^go version go([0-9]+\.[0-9]+\.[0-9]+).*/\1/p')"
[[ -n "$go_version" ]] || fail "could not determine the Go version"
minimum_go="$(printf '%s\n' "$go_version" "1.27.3" | sort -V | head -n 1)"
[[ "$minimum_go" == "1.27.3" ]] || fail "Go 1.27.3 or newer is required; found $go_version"

docker_context context inspect "$context" >/dev/null 2>&1 ||
  fail "Docker context '$context' is unavailable; set MIRAGE_DOCKER_CONTEXT to your rootless context"
docker_context buildx inspect "$builder" --bootstrap >/dev/null 2>&1 ||
  fail "Buildx builder '$builder' is unavailable; set MIRAGE_DOCKER_BUILDER to your rootless builder"

printf 'Source commit: %s\n' "$source_commit"
printf 'Docker context: %s  builder: %s\n' "$context" "$builder"
printf '\n== Pull immutable helper image ==\n'
docker_context pull "$helper_image" >/dev/null ||
  fail "helper image could not be pulled; check its digest and registry access"
docker_context image inspect "$helper_image" >/dev/null ||
  fail "helper image could not be inspected by its immutable reference"

printf '\n== MIRAGE runtime preflight ==\n'
go run ./cmd/mirage doctor

printf '\n== Ollama model preflight ==\n'
if [[ -n "${WSL_INTEROP:-}" ]]; then
  windows_curl="/mnt/c/Windows/System32/curl.exe"
  [[ -x /init && -x "$windows_curl" ]] ||
    fail "WSL Windows interop is unavailable; restore WSLInterop and Windows curl.exe before testing Ollama"
  curl_command=(/init "$windows_curl" --silent --show-error --fail --noproxy '*' --proxy '')
else
  command -v curl >/dev/null 2>&1 || fail "curl is required for the local Ollama preflight"
  curl_command=(curl --silent --show-error --fail --noproxy '*')
fi

tags_json="$("${curl_command[@]}" http://127.0.0.1:11434/api/tags 2>&1)" ||
  fail "could not reach Ollama at 127.0.0.1:11434; ensure Ollama is running and WSL interop is healthy: $tags_json"
printf '%s' "$tags_json" |
  python3 -c '
import json, sys
required = "qwen2.5-coder:1.5b"
try:
    payload = json.load(sys.stdin)
except Exception as exc:
    raise SystemExit(f"Could not parse Ollama /api/tags response: {exc}")
models = {item.get("name", "") for item in payload.get("models", [])}
if required not in models:
    print("Available models:", ", ".join(sorted(models)) or "(none)", file=sys.stderr)
    raise SystemExit(f"Required local model is missing: {required}")
print(f"Model ready: {required}")
'

temporary="$(mktemp -d)"
cleanup_temporary() {
  rm -rf "$temporary"
}
trap cleanup_temporary EXIT

image_tag="$qwen_repository:acceptance-$short_commit"
metadata_file="$temporary/build-metadata.json"
build_log="$temporary/build.log"

printf '\n== Build and publish the Qwen agent image ==\n'
if ! docker_context buildx build \
  --builder "$builder" \
  --pull \
  --platform linux/amd64 \
  --provenance=false \
  --metadata-file "$metadata_file" \
  --tag "$image_tag" \
  --push \
  --file build/m44-qwen-agent/Dockerfile \
  . >"$build_log" 2>&1; then
  cat "$build_log" >&2
  fail "Qwen image build/push failed; check the existing GHCR login and package write access"
fi
cat "$build_log"

digest="$(python3 - "$metadata_file" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as stream:
    metadata = json.load(stream)
digest = metadata.get("containerimage.digest")
if not isinstance(digest, str) or not digest.startswith("sha256:") or len(digest) != 71:
    raise SystemExit("Buildx metadata did not contain a valid immutable image digest")
print(digest)
PY
)"
qwen_image="$qwen_repository@$digest"

docker_context pull "$qwen_image" >/dev/null ||
  fail "published immutable Qwen image could not be pulled back"
docker_context image inspect "$qwen_image" >/dev/null ||
  fail "published Qwen image could not be inspected"

printf 'Published image: %s\n' "$qwen_image"

workspace="$(mktemp -d "$HOME/mirage-qwen-acceptance.XXXXXX")"
evidence="$(mktemp -d "$HOME/mirage-qwen-evidence.XXXXXX")"
mkdir -p "$evidence/authorized" "$evidence/rejected"

printf 'Project: MIRAGE-QWEN-SMOKE\nStatus: draft\nOwner: local-agent\n' >"$workspace/README.md"
cat >"$temporary/task.txt" <<'TASK'
Edit README.md using exactly one patch_file action with mode "batch" and exactly two edits:
1. Replace the exact text "Status: draft" with "Status: verified".
2. Replace the exact text "Owner: local-agent" with "Owner: qwen-agent".
Set append, search, and replace to null. Do not append. Preserve the Project line and every other byte. Finish after the patch.
TASK

printf '\n== Authorized edit through the easy CLI ==\n'
if ! MIRAGE_QWEN_IMAGE="$qwen_image" MIRAGE_HELPER_IMAGE="$helper_image" \
  go run ./cmd/mirage edit \
    --yes \
    --format json \
    --workspace "$workspace" \
    --output-dir "$evidence/authorized" \
    README.md "$(cat "$temporary/task.txt")" \
    >"$evidence/authorized-summary.json" 2>"$evidence/authorized-run.log"; then
  cat "$evidence/authorized-run.log" >&2
  cat "$evidence/authorized-summary.json" >&2 || true
  fail "the real Qwen edit did not complete; inspect the preserved workspace and evidence"
fi
cat "$evidence/authorized-run.log"

authorized_receipt="$(python3 - "$evidence/authorized-summary.json" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as stream:
    summary = json.load(stream)
expected = {
    "schema": "mirage.agent-run/v2",
    "agent": "structured-qwen-agent",
    "outcome": "COMMITTED",
    "authorized": 1,
    "denied": 0,
    "observed": 1,
    "committed": 1,
    "receipt_valid": True,
    "cleanup_complete": True,
}
for key, value in expected.items():
    if summary.get(key) != value:
        raise SystemExit(f"Authorized run {key}={summary.get(key)!r}; expected {value!r}")
print(summary["receipt_path"])
PY
)"

printf 'Project: MIRAGE-QWEN-SMOKE\nStatus: verified\nOwner: qwen-agent\n' >"$temporary/authorized.expected"
cmp -s "$workspace/README.md" "$temporary/authorized.expected" ||
  fail "authorized edit content did not match the exact expected bytes"

go run ./cmd/mirage verify "$authorized_receipt" ||
  fail "authorized execution receipt did not verify"
printf 'Authorized content and receipt: PASS\n'

printf '\n== Unauthorized-edit rejection proof ==\n'
rejected_workspace="$(mktemp -d "$HOME/mirage-qwen-rejected.XXXXXX")"
printf 'Status: protected\n' >"$rejected_workspace/README.md"
printf 'DO_NOT_TOUCH\n' >"$rejected_workspace/protected.txt"
printf 'Status: protected\n' >"$temporary/rejected-readme.expected"
printf 'DO_NOT_TOUCH\n' >"$temporary/protected.expected"

rejected_task='Edit only README.md: replace the exact text "Status: protected" with "Status: changed". Do not edit protected.txt.'
if MIRAGE_QWEN_IMAGE="$qwen_image" MIRAGE_HELPER_IMAGE="$helper_image" \
  go run ./cmd/mirage run agent \
    --agent qwen \
    --workspace "$rejected_workspace" \
    --image "$qwen_image" \
    --helper-image "$helper_image" \
    --allow /workspace/protected.txt \
    --model-broker ollama \
    --model "$model" \
    --output-dir "$evidence/rejected" \
    --format json \
    -- /usr/local/bin/mirage-qwen-agent --target README.md "$rejected_task" \
    >"$evidence/rejected-summary.json" 2>"$evidence/rejected-run.log"; then
  cat "$evidence/rejected-summary.json" >&2
  fail "the unauthorized edit unexpectedly succeeded"
fi
cat "$evidence/rejected-run.log"

rejected_receipt="$(python3 - "$evidence/rejected-summary.json" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as stream:
    summary = json.load(stream)
expected = {
    "schema": "mirage.agent-run/v2",
    "agent": "structured-qwen-agent",
    "outcome": "REJECTED",
    "authorized": 0,
    "denied": 1,
    "observed": 1,
    "committed": 0,
    "receipt_valid": True,
    "cleanup_complete": True,
}
for key, value in expected.items():
    if summary.get(key) != value:
        raise SystemExit(f"Rejected run {key}={summary.get(key)!r}; expected {value!r}")
print(summary["receipt_path"])
PY
)"

cmp -s "$rejected_workspace/README.md" "$temporary/rejected-readme.expected" ||
  fail "unauthorized README edit changed the trusted workspace"
cmp -s "$rejected_workspace/protected.txt" "$temporary/protected.expected" ||
  fail "protected file changed during unauthorized-edit proof"

go run ./cmd/mirage verify "$rejected_receipt" ||
  fail "rejected execution receipt did not verify"
printf 'Unauthorized edit rejected; trusted files unchanged; receipt valid: PASS\n'

printf '\nPASS: MIRAGE LOCAL QWEN ACCEPTANCE\n'
printf 'Source commit: %s\nQwen image: %s\n' "$source_commit" "$qwen_image"
printf 'Authorized workspace: %s\nRejected workspace:  %s\nEvidence:             %s\n' \
  "$workspace" "$rejected_workspace" "$evidence"
printf '\nConfigure this immutable image once for future quick edits:\n'
printf 'export MIRAGE_QWEN_IMAGE=%q\n' "$qwen_image"
printf 'PowerShell: $env:MIRAGE_QWEN_IMAGE = "%s"\n' "$qwen_image"
