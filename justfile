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
    bash tests/architecture-boundaries.sh
    bash -n tests/aliyun-live.sh
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
    control-plane/tests/cloudflare-environments.sh

build:
    go build ./...
    cargo check -p carrack-sdk-core --target wasm32-unknown-unknown
    pnpm --filter @carrack/web build
    pnpm exec wrangler deploy --dry-run --env dev --config control-plane/wrangler.jsonc
    pnpm exec wrangler deploy --dry-run --env prod --config control-plane/wrangler.jsonc

migrate-dev:
    node control-plane/scripts/apply-migrations.mjs dev

migrate-prod:
    test "${CARRACK_MIGRATE_PROD:-}" = "1"
    node control-plane/scripts/apply-migrations.mjs prod

deploy-dev: verify
    node control-plane/scripts/deploy-worker.mjs dev

deploy-prod: verify
    node control-plane/scripts/deploy-worker.mjs prod

audit-cloudflare:
    node control-plane/scripts/audit-environments.mjs

verify: check-format lint test build
