#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
install_root="${HOME}/.local/bin"
temporary_root="$(mktemp -d)"
trap 'rm -rf -- "$temporary_root"' EXIT

if ! command -v go >/dev/null 2>&1; then
  echo "MIRAGE requires Go 1.24 or newer to install from source." >&2
  exit 1
fi

version="${MIRAGE_VERSION:-0.1.0}"
commit="$(git -C "$repo_root" rev-parse --verify HEAD 2>/dev/null || printf unknown)"
mkdir -p -- "$install_root"
go -C "$repo_root" build \
  -ldflags "-X github.com/MrGray17/Mirage/internal/buildinfo.Version=$version -X github.com/MrGray17/Mirage/internal/buildinfo.Commit=$commit" \
  -o "$temporary_root/mirage" ./cmd/mirage
install -m 0755 "$temporary_root/mirage" "$install_root/mirage"

echo "Installed MIRAGE at $install_root/mirage"
case ":${PATH}:" in
  *":${install_root}:"*) ;;
  *) echo "Add $install_root to PATH, then run: mirage setup" ;;
esac
