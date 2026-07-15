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

legacy_go_paths=(archive cryptostream manifest provider sdk internal/cli driver/aliyundrive)
for legacy_path in "${legacy_go_paths[@]}"; do
  if test -d "$legacy_path" && find "$legacy_path" -type f -name '*.go' -print -quit | grep -q .; then
    echo "legacy Go archive code is forbidden under $legacy_path" >&2
    exit 1
  fi
done

if find transfer -maxdepth 1 -type f -name '*.go' -print -quit | grep -q .; then
  echo "only the V2 transfer/journal Go oracle may remain under transfer" >&2
  exit 1
fi

if rg --line-number \
  'github\.com/dravengarden/carrack/(archive|cryptostream|manifest|provider|sdk)(/|"|$)' \
  --glob '*.go' .; then
  echo "retained Go conformance packages must not import the removed archive stack" >&2
  exit 1
fi

if test -e schemas/bundle.v1.schema.json || test -e schemas/bundle-plan.v1.schema.json; then
  echo "bundle schemas are forbidden by the complete-object V2 model" >&2
  exit 1
fi
