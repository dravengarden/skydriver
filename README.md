# Carrack

Carrack is a complete-object virtual filesystem. A file remains one complete
object in exactly the same byte order at its storage driver; Carrack never
splits, packs, merges, or stripes user files. Different files in one virtual
directory may live on different drivers while the directory remains one
authenticated Merkle tree.

The canonical implementation has three surfaces:

- the Rust Cloudflare control plane owns metadata, permissions, key envelopes,
  driver configuration, optimistic publication, read leases, retention, and
  physical garbage collection;
- the Rust `carrack` binary and `carrack-client` crate expose filesystem-like
  list, stat, mkdir, put, get, remove, and rename operations; and
- the Rust `carrackctl` binary exposes every supported UI/operator mutation as
  strict JSON-first commands for humans and AI agents.

Payload bytes move directly between the Rust client and the selected driver.
They never transit the Worker. OpenList is not linked, launched, or called; it
may be inspected only as provider-behavior reference material.

## Correctness model

- Plaintext files have a SHA-256 Merkle root and fixed verification blocks.
- Directories have canonical ordered Merkle roots.
- Encryption is on by default. A directory key epoch and immutable file ID
  derive the file key; provider names are opaque random storage keys.
- Upload publishes only after complete provider readback and encoded checksum
  verification.
- Download verifies exact ranges, encoded SHA-256, authenticated encryption
  frames, plaintext size, and plaintext Merkle root before success.
- Namespace mutations use optimistic revisions and durable idempotency
  receipts. Rename/move changes metadata only and never copies payload bytes.
- Direct reads hold durable leases. Server GC cannot delete a location with an
  active lease and must repeat reachability, identity, driver-revision, grace,
  and fencing checks immediately around provider deletion.
- Native clients and the Cloudflare Worker share the filesystem-independent
  `carrack-sdk-core`. The verification gate compiles it for
  `wasm32-unknown-unknown` and executes its Merkle and authenticated-encryption
  round trip inside the Worker runtime.

## Native filesystem CLI

Both endpoint and bearer come from environment variables so secrets do not
enter argv:

```bash
export CARRACK_CONTROL_URL=https://dev.carrack.stormbird.xyz
export CARRACK_VFS_TOKEN='...'

carrack list /
carrack mkdir /releases --idempotency-key release-dir-v1
carrack put ./app.tar.zst /releases/app.tar.zst \
  --idempotency-key app-2026-07-14
carrack get /releases/app.tar.zst ./app.tar.zst
carrack sync /releases ./local-releases \
  --maximum-concurrency 4 --maximum-file-concurrency 4
carrack rename /releases/app.tar.zst /releases/latest.tar.zst \
  --idempotency-key latest-2026-07-14
carrack remove /releases/latest.tar.zst \
  --idempotency-key remove-latest-2026-07-14
```

`sync` first requests a bounded server-materialized catalog checkpoint. A
full-root token streams the immutable checkpoint directly; a safely authorized
narrow token receives only its projected Merkle subtree. ACL-boundary and
snapshot cases transparently traverse revision-pinned pages. The client verifies
the complete authorized catalog before payload work, while an unchanged verified
view uses a conditional request and transfers no checkpoint body. When a
full-root view changed from the immediately preceding published head, SDK 0.3.2
can receive only the hash-linked content-addressed directory nodes missing from
its authenticated base; it still reconstructs and verifies the exact complete
target checkpoint before reuse. A missing, oversized, or incompatible delta
transparently falls back to the complete checkpoint. The client also
verifies unchanged local files from prior authenticated version/block metadata
and downloads only changed or corrupted files. Changed files run concurrently
and each retains its own resumable range pipeline. Untracked local files are
preserved.

Multipart journals, resume, range scheduling, encryption, checksums, and GC
are internal. Transfer bounds tune the pipeline; they do not alter identity.

## Management CLI for agents

`CARRACK_OPERATOR_CREDENTIAL` authorizes redacted UI-equivalent environment
management. `CARRACK_VFS_TOKEN` separately authorizes scoped ACL, placement,
and child-token operations.

```bash
carrackctl snapshot
carrackctl watch --after 0 --limit 100
carrackctl directory <directory-id>
carrackctl driver register aliyun-main \
  --kind aliyundrive-open/v2 --config-file ./aliyun-config.json --check
carrackctl vfs acl show /releases
carrackctl vfs placement show /releases
carrackctl vfs token issue /releases \
  --action directory.list,content.read \
  --expires-at <unix-seconds> --idempotency-key release-reader-v1
```

Configuration commands validate locally and on the server. Mutations require
an exact expected revision and stable idempotency key, return a durable receipt,
and fail closed on ambiguous or incompatible responses. Provider credentials
are accepted only from owner-private JSON files and are never returned by the
control plane. The environment-owned `r2-default` credential is a stricter
exception: the UI never accepts it, and the environment provisioner alone
moves its exact-bucket Cloudflare authority through that write-only CLI path.

See [.agents/skills/carrack-admin/SKILL.md](.agents/skills/carrack-admin/SKILL.md)
for the AI operating procedure and
[.agents/skills/carrack-admin/references/commands.md](.agents/skills/carrack-admin/references/commands.md)
for the complete command contract.

## Drivers

The current native V2 adapters are:

| Driver | Complete upload | Exact range download | Resume/concurrency | Server delete | Notes |
|---|---:|---:|---:|---:|---|
| `local-filesystem/v2` | yes | yes | yes | retained/blocked | Cloudflare cannot safely reach an agent-local path; use a hosted driver for automatic physical cleanup |
| `aliyundrive-open/v2` | yes | yes | journaled, upload concurrency 1 | yes | native Open API; server-owned OAuth renewal; optional OpenList token issuer only |
| `r2/v1` | yes | yes | resumable multipart and concurrent ranges | yes | `r2-default` is environment-owned; direct short-lived SigV4 URLs; binding-owned cleanup; third-party buckets remain supported |

Unsupported capabilities fail closed or return an explicit warning with the
safe replacement. Additional S3/R2, Google Drive, and WebDAV adapters must use
the same complete-object contract; WebDAV implementations without reliable
range/multipart semantics may degrade with a warning but may not weaken hash
verification.

## Environments

| Environment | UI/API | D1 | R2 |
|---|---|---|---|
| development | `https://dev.carrack.stormbird.xyz` | `carrack-index-dev` | `carrack-manifests-dev` + `carrack-payload-dev` |
| production | `https://carrack.stormbird.xyz` | `carrack-index-prod` | `carrack-manifests-prod` + `carrack-payload-prod` |

Both custom domains disable `workers.dev`. Environment resource identifiers,
deployment checks, and operator bootstrap are documented in
[docs/cloudflare.md](docs/cloudflare.md).

## Development

```bash
nix develop
just verify
```

The full gate runs formatting, strict Rust/Go/web lint, race tests, Rust tests,
real local Worker+D1 protocol tests, UI tests, and dev/prod dry-run builds.
The small retained Go packages are conformance oracles for the complete-object
driver contract, durable journal, and shared Merkle/crypto vectors only. There
is no public Go SDK or CLI and no legacy archive implementation.

Key specifications:

- [requirements](docs/requirements.md)
- [VFS V2 protocol](docs/vfs-v2.md)
- [management plane](docs/management-plane-v1.md)
- [Cloudflare environments](docs/cloudflare.md)
- [Rust client boundary](docs/rust-client-migration.md)
