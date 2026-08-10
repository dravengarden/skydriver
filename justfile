set shell := ["bash", "-euo", "pipefail", "-c"]

default: verify

toolchain-check:
    required="$(cargo metadata --no-deps --format-version 1 | jq -r '.packages[0].rust_version')"; actual="$(rustc --version --verbose | awk '/^release:/ { print $2 }')"; test "$required" = "$actual" || { echo "rust-version $required does not match pinned rustc $actual" >&2; exit 1; }

fmt:
    golangci-lint fmt
    cargo fmt --all
    nixfmt flake.nix
    pnpm --filter @skydriver/web format

check-format:
    test -z "$(gofmt -l -- $(rg --files -g '*.go'))"
    golangci-lint fmt --diff
    cargo fmt --all --check
    nixfmt --check flake.nix
    pnpm --filter @skydriver/web format:check

lint:
    go vet ./...
    golangci-lint run
    cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
    pnpm --filter @skydriver/web check
    pnpm --filter @skydriver/web lint

dependencies:
    cargo deny check
    cargo machete --with-metadata

secrets-check:
    gitleaks dir . --config gitleaks.toml --redact --no-banner

test:
    bash tests/architecture-boundaries.sh
    control-plane/tests/schema-retirement.sh
    control-plane/tests/query-plans.sh
    bash -n tests/aliyun-live.sh
    bash -n tests/r2-live.sh
    bash -n tests/r2-small-sync-live.sh
    bash -n tests/lib/live-metrics.sh
    bash tests/live-metrics-test.sh
    node --check control-plane/scripts/audit-environments.mjs
    node --check control-plane/scripts/deployment-config.mjs
    node --check control-plane/scripts/deploy-worker.mjs
    node --check control-plane/scripts/provision-default-r2.mjs
    node --check control-plane/scripts/rotate-operator-credential.mjs
    node --test control-plane/scripts/deployment-acceptance.test.mjs
    node --test control-plane/scripts/deployment-config.test.mjs
    node --test control-plane/scripts/default-r2-provisioning.test.mjs
    node --test control-plane/scripts/provision-default-r2.test.mjs
    go test -race ./...
    cargo test --workspace --all-features --locked
    pnpm --filter @skydriver/web test
    control-plane/tests/vfs-v2-protocol.sh
    control-plane/tests/vfs-v2-put-protocol.sh
    control-plane/tests/vfs-v2-worker-protocol.sh
    control-plane/tests/vfs-v2-bootstrap-worker-protocol.sh
    control-plane/tests/vfs-v2-management-worker-protocol.sh
    control-plane/tests/environment-defaults-worker-protocol.sh
    control-plane/tests/cloudflare-environments.sh

# Runs deterministic, machine-local scaling acceptances without treating wall
# clock time as a correctness threshold. Use --nocapture to retain the measured
# SQLite, spool, and mandatory local hashing costs in CI or operator logs.
performance-acceptance:
    cargo test -p skydriver-client sync::tests::indexed_state_accepts_one_hundred_thousand_records_without_linear_lookup --release --locked -- --ignored --exact --nocapture
    cargo test -p skydriver-client sync::tests::warm_sync_rehashes_ten_thousand_files_without_provider_payload --release --locked -- --ignored --exact --nocapture
    cargo test -p skydriver-client sync::tests::wide_directory_hydration_streams_one_hundred_thousand_entries --release --locked -- --ignored --exact --nocapture
    cargo test -p skydriver-client sync::tests::changed_paths_measure_download_plan_client_framing --release --locked -- --ignored --exact --nocapture
    cargo test -p skydriver-sdk-core integrity::tests::streaming_directory_accepts_one_million_entries_with_logarithmic_state --release --locked -- --ignored --exact --nocapture

test-fast:
    cargo nextest run --workspace --all-features --locked

# Fast deterministic inner loop; excludes Worker protocol scripts and dry-run deploy builds.
verify-fast: toolchain-check check-format
    cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
    cargo nextest run --workspace --all-features --locked
    pnpm --filter @skydriver/web check
    pnpm --filter @skydriver/web test
    bash tests/architecture-boundaries.sh

build-cached:
    RUSTC_WRAPPER=sccache CARGO_INCREMENTAL=0 cargo build --workspace --all-features --locked

cache-stats:
    sccache --show-stats

# Preview or remove stale Cargo artifacts while retaining the most recently
# used builds up to the requested aggregate size. Pruning is intentionally
# operator-triggered because it trades disk space for the next rebuild time.
cache-prune-dry max_size="60GB":
    cargo sweep --dry-run --maxsize "{{ max_size }}" .

cache-prune max_size="60GB":
    cargo sweep --maxsize "{{ max_size }}" .

build:
    go build ./...
    cargo build --workspace --all-features --locked
    cargo check -p skydriver-sdk-core --target wasm32-unknown-unknown --locked
    pnpm --filter @skydriver/web build
    config="${SKYDRIVER_WRANGLER_CONFIG:-control-plane/wrangler.jsonc}"; pnpm exec wrangler deploy --dry-run --env dev --config "$config"
    config="${SKYDRIVER_WRANGLER_CONFIG:-control-plane/wrangler.jsonc}"; pnpm exec wrangler deploy --dry-run --env prod --config "$config"

migrate-dev:
    node control-plane/scripts/apply-migrations.mjs dev

migrate-prod:
    test "${SKYDRIVER_MIGRATE_PROD:-}" = "1"
    node control-plane/scripts/apply-migrations.mjs prod

rotate-operator-dev:
    node control-plane/scripts/rotate-operator-credential.mjs dev

rotate-operator-prod:
    test "${SKYDRIVER_ROTATE_OPERATOR_PROD:-}" = "1"
    node control-plane/scripts/rotate-operator-credential.mjs prod

deploy-dev: verify
    node control-plane/scripts/deploy-worker.mjs dev

deploy-prod: verify
    node control-plane/scripts/deploy-worker.mjs prod

# Durable Object migrations cannot be uploaded as an inactive Worker version.
# These explicit recipes atomically apply the configured migration while
# deploying the verified build to 100% of the selected environment.
deploy-do-migrations-dev: verify
    SKYDRIVER_APPLY_DO_MIGRATIONS=1 node control-plane/scripts/deploy-worker.mjs dev

deploy-do-migrations-prod: verify
    test "${SKYDRIVER_APPLY_DO_MIGRATIONS_PROD:-}" = "1"
    SKYDRIVER_APPLY_DO_MIGRATIONS=1 node control-plane/scripts/deploy-worker.mjs prod

audit-cloudflare:
    node control-plane/scripts/audit-environments.mjs

provision-r2-dev:
    env -u CLOUDFLARE_API_TOKEN -u CLOUDFLARE_TOKEN_FACTORY_API_TOKEN -u SKYDRIVER_OPERATOR_CREDENTIAL -u SKYDRIVER_VFS_TOKEN cargo build -p skydriver-cli --bin skydriverctl --locked
    node control-plane/scripts/provision-default-r2.mjs dev

provision-r2-prod:
    test "${SKYDRIVER_PROVISION_PROD:-}" = "1"
    env -u CLOUDFLARE_API_TOKEN -u CLOUDFLARE_TOKEN_FACTORY_API_TOKEN -u SKYDRIVER_OPERATOR_CREDENTIAL -u SKYDRIVER_VFS_TOKEN cargo build -p skydriver-cli --bin skydriverctl --locked
    node control-plane/scripts/provision-default-r2.mjs prod

check-r2-dev:
    env -u CLOUDFLARE_API_TOKEN -u CLOUDFLARE_TOKEN_FACTORY_API_TOKEN -u SKYDRIVER_OPERATOR_CREDENTIAL -u SKYDRIVER_VFS_TOKEN cargo build -p skydriver-cli --bin skydriverctl --locked
    node control-plane/scripts/provision-default-r2.mjs dev --check

check-r2-prod:
    env -u CLOUDFLARE_API_TOKEN -u CLOUDFLARE_TOKEN_FACTORY_API_TOKEN -u SKYDRIVER_OPERATOR_CREDENTIAL -u SKYDRIVER_VFS_TOKEN cargo build -p skydriver-cli --bin skydriverctl --locked
    node control-plane/scripts/provision-default-r2.mjs prod --check

verify: toolchain-check check-format lint dependencies secrets-check build test
