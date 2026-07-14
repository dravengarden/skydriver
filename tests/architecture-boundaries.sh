#!/usr/bin/env bash
set -euo pipefail

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repository_root"

dependency_manifests=(Cargo.toml Cargo.lock go.mod go.sum package.json pnpm-lock.yaml)
if rg --line-number --ignore-case \
  'github\.com/(OpenListTeam/)?OpenList|api\.oplist\.org|name = "openlist"' \
  "${dependency_manifests[@]}"; then
  echo "OpenList must not be a Carrack build or runtime dependency" >&2
  exit 1
fi

if rg --line-number --ignore-case \
  'OpenListTeam|api\.oplist\.org|openlist' \
  crates/carrack-client/src crates/carrack-cli/src; then
  echo "native Rust clients must not link to or call OpenList" >&2
  exit 1
fi

if test -e cmd/carrack/main.go || test -e cmd/carrackctl/main.go; then
  echo "public Carrack CLIs must be the native Rust binaries" >&2
  exit 1
fi
