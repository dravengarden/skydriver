# Skydriver

Skydriver is an encrypted, content-addressed virtual filesystem for complete
objects. Files remain whole at every storage provider: Skydriver does not
split, pack, merge, stripe, or expose provider-internal parts as user files.

The project provides a Rust client and CLI, a Rust Cloudflare control plane, a
strict operator CLI, and a browser console. Payload bytes move directly
between the client and the selected storage driver; the control plane stores
metadata and coordinates authorization, publication, leases, and cleanup.

> Status: active development. The wire formats and requirements are versioned,
> but interfaces may still change between releases. Read the protocol
> documentation before using a deployment for important data.

## Highlights

- end-to-end integrity using SHA-256 Merkle roots and fixed verification blocks;
- authenticated encryption by default with directory key epochs and immutable
  file identities;
- atomic, no-replace publication with complete provider readback;
- resumable and bounded-concurrency transfer pipelines;
- optimistic metadata revisions and durable idempotency receipts;
- attenuated, revocable VFS tokens with directory and driver scope;
- local filesystem, Aliyun Drive Open, Cloudflare R2, and AWS S3 drivers; and
- a provider-free Rust correctness core shared by native clients and Worker
  WASM.

## Architecture

```text
skydriver client / CLI ────────► storage driver
          │                         (complete objects)
          │ metadata, grants,
          │ receipts, leases
          ▼
   Cloudflare control plane ───► D1 + R2 metadata
          │
          └────────────────────► browser console / skydriverctl
```

The main components are:

- `crates/skydriver-sdk-core`: portable canonical, integrity, crypto, catalog,
  and acceptance primitives;
- `crates/skydriver-client`: native I/O, transfer, recovery, and publication;
- `crates/skydriver-cli`: the `skydriver` filesystem CLI and `skydriverctl`
  management CLI;
- `control-plane`: the Rust Worker and D1/R2 protocol implementation;
- `web`: the React and MUI browser console; and
- `driver`, `transfer/journal`, and `vfs`: small Go conformance oracles.

The control plane never relays payload bodies. Provider credentials and VFS
keys remain server-side or in the deployment secret store; clients receive
only short-lived, scoped grants.

## Quick start

### Requirements

- Nix with flakes enabled;
- Git;
- a Unix-like environment for the shell and protocol tests; and
- Node, pnpm, Rust, and Go supplied by the repository's development shell.

### Build and verify

```bash
git clone https://github.com/dravengarden/skydriver.git
cd skydriver
nix develop -c just verify
```

For a faster local loop:

```bash
nix develop -c just verify-fast
```

The checked-in Wrangler configuration is local-safe and uses reserved example
values for remote profiles. For local Worker development, copy the ignored
vars file and replace every placeholder with a locally generated value:

```bash
cp control-plane/.dev.vars.example control-plane/.dev.vars
chmod 600 control-plane/.dev.vars
```

Never commit either `.dev.vars` or `.env`. Both are ignored by Git.

## CLI usage

The native CLI reads the control-plane URL and bearer token from the environment
so secrets do not enter process arguments:

```bash
export SKYDRIVER_CONTROL_URL='https://your-control-plane.example'
export SKYDRIVER_VFS_TOKEN='<short-lived scoped token>'

skydriver list /
skydriver mkdir /releases --idempotency-key release-dir-v1
skydriver put ./release.tar.zst /releases/release.tar.zst \
  --idempotency-key release-v1
skydriver get /releases/release.tar.zst ./release.tar.zst
skydriver rename /releases/release.tar.zst /releases/latest.tar.zst \
  --idempotency-key release-latest-v1
```

The management CLI exposes the same validated mutations as the browser UI:

```bash
export SKYDRIVER_OPERATOR_ACCOUNT='operator@example'
export SKYDRIVER_OPERATOR_CREDENTIAL='<short-lived operator credential>'

skydriverctl snapshot
skydriverctl metrics global all
skydriverctl watch --after 0 --limit 100
skydriverctl vfs acl show /releases
```

Provider credentials must come from an owner-private file or an equivalent
non-argv channel. They are never returned by the control plane.

## Configuration and deployment

Cloudflare deployment is intentionally separate from the public source tree's
defaults. Copy the checked-in Wrangler profile into a deployment-owned file,
replace the `.example` domains and placeholder resource IDs, then select it
with `SKYDRIVER_WRANGLER_CONFIG`. Keep D1, R2, Worker, and secret identities
separate between environments.

See [Cloudflare deployment](docs/cloudflare.md) for resource configuration,
secret handling, migration, release, audit, and opt-in live acceptance. The
control plane's [requirements](docs/requirements.md) are normative.

## Documentation

- [Requirements](docs/requirements.md)
- [VFS V2 protocol](docs/vfs-v2.md)
- [Management plane](docs/management-plane-v1.md)
- [VFS authorization](docs/vfs-authorization-v1.md)
- [Driver SPI](docs/driver-spi.md)
- [SDK core](docs/sdk-core.md)
- [Rust client boundary](docs/rust-client-migration.md)
- [Cloudflare deployment](docs/cloudflare.md)
- [Transfer performance methodology](docs/transfer-performance-observations.md)

## Security

Skydriver handles encryption keys, provider credentials, bearer tokens, and
filesystem metadata. Please read [SECURITY.md](SECURITY.md) before reporting a
security issue.

The project policy is simple: secrets and credentials must never enter Git,
logs, command arguments, browser storage, test artifacts, or API responses.
Use placeholders in examples and short-lived credentials for acceptance tests.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md), then run the repository gate from the
pinned shell:

```bash
nix develop -c just verify
```

Changes to wire formats, migrations, cryptographic domains, or authorization
rules must update the relevant normative documentation and regression tests.

## License

Skydriver is licensed under the [Apache License 2.0](LICENSE).
