set shell := ["bash", "-euo", "pipefail", "-c"]

default: verify

fmt:
    golangci-lint fmt
    cargo fmt --all
    pnpm --filter @carrack/web format

check-format:
    test -z "$(gofmt -l -- $(rg --files -g '*.go'))"
    golangci-lint fmt --diff
    cargo fmt --all --check
    pnpm --filter @carrack/web format:check

lint:
    go vet ./...
    golangci-lint run
    cargo clippy --workspace --all-targets --all-features -- -D warnings
    pnpm --filter @carrack/web check
    pnpm --filter @carrack/web lint

test:
    go test -race ./...
    cargo test --workspace --all-features
    pnpm --filter @carrack/web test
    control-plane/tests/core-protocol.sh
    control-plane/tests/vfs-v2-protocol.sh
    control-plane/tests/vfs-v2-put-protocol.sh
    control-plane/tests/vfs-v2-worker-protocol.sh
    control-plane/tests/vfs-v2-bootstrap-worker-protocol.sh
    control-plane/tests/vfs-v2-management-worker-protocol.sh
    control-plane/tests/worker-protocol.sh

build:
    go build ./...
    pnpm --filter @carrack/web build
    pnpm exec wrangler deploy --dry-run --config control-plane/wrangler.jsonc

verify: check-format lint test build
