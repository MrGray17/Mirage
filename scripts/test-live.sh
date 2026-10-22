#!/usr/bin/env bash
set -Ee -o pipefail

fail() {
  printf 'MIRAGE live acceptance: %s\n' "$*" >&2
  exit 2
}

repo_root="$(cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$repo_root"

[[ "$(uname -s)" == "Linux" ]] || fail "run this script on Linux or inside WSL2, not Windows."

[[ -n "${MIRAGE_HOSTILE_IMAGE:-}" ]] || fail "set MIRAGE_HOSTILE_IMAGE to a preloaded, digest-pinned hostile-fixture image"
[[ -n "${MIRAGE_CODEX_IMAGE:-}" ]] || fail "set MIRAGE_CODEX_IMAGE to a preloaded, digest-pinned Codex agent image"
[[ -n "${MIRAGE_HELPER_IMAGE:-}" ]] || fail "set MIRAGE_HELPER_IMAGE to a preloaded, digest-pinned helper image"
[[ -n "${MIRAGE_DEMO_IMAGE:-}" ]] || fail "set MIRAGE_DEMO_IMAGE to a preloaded, digest-pinned demo fixture image"

if [[ -z "${MIRAGE_AGENT_IMAGE:-}" ]]; then
  MIRAGE_AGENT_IMAGE="$MIRAGE_HOSTILE_IMAGE"
fi
export MIRAGE_AGENT_IMAGE

command -v go >/dev/null 2>&1 || fail "Go 1.27.3 or newer is required."
command -v docker >/dev/null 2>&1 || fail "Docker CLI is required."
go_version_output="$(go version 2>&1)" || fail "could not run the Go toolchain."
go_version="$(sed -nE 's/^go version go([0-9]+\.[0-9]+\.[0-9]+)([[:space:]]|$).*/\1/p' <<< "$go_version_output")"
[[ -n "$go_version" ]] || fail "could not parse Go version: $go_version_output"
minimum_version="$(printf '%s\n' "$go_version" "1.27.3" | sort -V | head -n 1)"
[[ "$minimum_version" == "1.27.3" ]] || fail "Go 1.27.3 or newer is required; found $go_version."

check_pinned_image() {
  local variable_name="$1"
  local image_ref="$2"

  [[ "$image_ref" =~ @sha256:[0-9a-f]{64}$ ]] ||
    fail "$variable_name must be pinned by an immutable @sha256 digest."
  docker image inspect "$image_ref" >/dev/null 2>&1 ||
    fail "$variable_name image is not present locally: $image_ref (pull/build it explicitly first)."
}

check_pinned_image MIRAGE_HOSTILE_IMAGE "$MIRAGE_HOSTILE_IMAGE"
check_pinned_image MIRAGE_AGENT_IMAGE "$MIRAGE_AGENT_IMAGE"
check_pinned_image MIRAGE_CODEX_IMAGE "$MIRAGE_CODEX_IMAGE"
check_pinned_image MIRAGE_HELPER_IMAGE "$MIRAGE_HELPER_IMAGE"
check_pinned_image MIRAGE_DEMO_IMAGE "$MIRAGE_DEMO_IMAGE"

printf '\n== MIRAGE runtime preflight ==\n'
go run ./cmd/mirage doctor

printf '\n== Standard release checks ==\n'
unformatted="$(gofmt -l .)"
if [[ -n "$unformatted" ]]; then
  printf 'gofmt required for:\n%s\n' "$unformatted" >&2
  while IFS= read -r file; do
    [[ -z "$file" ]] || gofmt -d "$file"
  done <<< "$unformatted"
  fail "Go source formatting is not clean."
fi
go vet ./...
go test -race -count=1 ./...

printf '\n== Rootless Docker integration acceptance ==\n'
export MIRAGE_M42_INTEGRATION=1
export MIRAGE_M44_INTEGRATION=1
export MIRAGE_M44_BROKER_INTEGRATION=1
export MIRAGE_DEMO_INTEGRATION=1

go test -race -count=1 -v ./internal/runtime/docker
go test -race -count=1 -v ./internal/demo

printf '\nPASS: standard checks and opt-in rootless runtime integration tests completed.\n'
printf 'Note: this script does not make GitHub writes or run a paid live-provider request.\n'
