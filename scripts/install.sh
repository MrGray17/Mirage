#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
install_root="${HOME}/.local/bin"
temporary_root="$(mktemp -d)"
staged_install=""
cleanup() {
  if [[ -n "$staged_install" ]]; then
    rm -f -- "$staged_install" || true
  fi
  rm -rf -- "$temporary_root" || true
}
trap cleanup EXIT

if ! command -v go >/dev/null 2>&1; then
  echo "MIRAGE requires Go 1.27.3 or newer to install from source." >&2
  exit 1
fi
if ! go_version_output="$(go version 2>&1)"; then
  echo "MIRAGE could not execute the Go toolchain; nothing was installed." >&2
  exit 1
fi
go_version="$(sed -nE 's/^go version go([0-9]+\.[0-9]+\.[0-9]+)([[:space:]]|$).*/\1/p' <<< "$go_version_output")"
if [[ -z "$go_version" ]]; then
  echo "MIRAGE could not parse the Go toolchain version: $go_version_output" >&2
  exit 1
fi
minimum_version="$(printf '%s\n' "$go_version" "1.27.3" | sort -V | head -n 1)"
if [[ "$minimum_version" != "1.27.3" ]]; then
  echo "MIRAGE requires Go 1.27.3 or newer; found $go_version. Nothing was installed." >&2
  exit 1
fi
if ! command -v git >/dev/null 2>&1; then
  echo "MIRAGE requires Git to establish its source commit identity; nothing was installed." >&2
  exit 1
fi
if ! commit="$(git -C "$repo_root" rev-parse --verify HEAD 2>/dev/null)"; then
  echo "MIRAGE could not establish its source commit identity; nothing was installed." >&2
  exit 1
fi
if [[ ! "$commit" =~ ^[0-9a-f]{40}$ ]]; then
  echo "MIRAGE source commit identity is not a canonical SHA-1; nothing was installed." >&2
  exit 1
fi

version="${MIRAGE_VERSION:-1.0.0}"
mkdir -p -- "$install_root"
target="$install_root/mirage"
if [[ -L "$target" || ( -e "$target" && ! -f "$target" ) ]]; then
  echo "MIRAGE install target exists but is not a regular file; refusing to overwrite it." >&2
  exit 1
fi

host_arch="$(go env GOHOSTARCH)"
if ! GOOS=linux GOARCH="$host_arch" go -C "$repo_root" build \
  -ldflags "-X github.com/MrGray17/Mirage/internal/buildinfo.Version=$version -X github.com/MrGray17/Mirage/internal/buildinfo.Commit=$commit" \
  -o "$temporary_root/mirage" ./cmd/mirage; then
  echo "MIRAGE Linux build failed; the existing installation was not changed." >&2
  exit 1
fi

# Stage in the destination directory so the final rename stays on one
# filesystem and an interrupted install cannot truncate the active executable.
staged_install="$(mktemp "$install_root/.mirage-stage.XXXXXX")"
if ! install -m 0755 "$temporary_root/mirage" "$staged_install"; then
  echo "MIRAGE could not stage the new executable; the existing installation was not changed." >&2
  exit 1
fi

if ! metadata="$("$staged_install" version --json 2>/dev/null)"; then
  echo "MIRAGE staged executable failed its version smoke test; existing installation was not changed." >&2
  exit 1
fi
if ! grep -Fq "\"version\":\"$version\"" <<< "$metadata" ||
   ! grep -Fq "\"commit\":\"$commit\"" <<< "$metadata" ||
   ! grep -Fq '"bridge_protocol":1' <<< "$metadata" ||
   ! grep -Fq '"platform":"linux"' <<< "$metadata"; then
  echo "MIRAGE staged executable has unexpected build identity; existing installation was not changed." >&2
  exit 1
fi

if ! mv -f -- "$staged_install" "$target"; then
  echo "MIRAGE could not activate the validated executable; existing installation was not changed." >&2
  exit 1
fi
staged_install=""

echo "Installed MIRAGE at $target"
case ":${PATH}:" in
  *":${install_root}:"*) ;;
  *) echo "Add $install_root to PATH, then run: mirage setup" ;;
esac
