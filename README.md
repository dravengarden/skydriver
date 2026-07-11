# Carrack

Carrack is a business-neutral data transport and encrypted archive system. It
moves immutable data across consumer and cloud storage while keeping logical
objects independent from any provider.

Carrack has two components. The Go client SDK performs every payload transfer,
including import, copy, move, compaction, encryption, and restore. A Rust
Cloudflare control plane indexes immutable manifests and locations, authorizes
clients, manages encrypted key material, coordinates leases, and plans garbage
collection. It also exposes live client, operation, stage, progress, throughput,
retry, and historical-rate telemetry. It never relays payload bytes.

Application-specific ingestion and interpretation belong in separate consumer
projects. R2, Aliyun Drive, Google Drive, public HTTP/S3, local filesystems, and
future drivers use the same object and operation model.

## Initial layout

- `archive`: configurable physical block and crypto frame layout.
- `cryptostream`: provider-free HKDF and framed AES-GCM implementation.
- `manifest`: versioned, content-addressed archive manifests.
- `provider`: storage provider boundaries.
- `transfer`: crypto-free opaque ciphertext extent fetching and verification.
- `sdk`: embeddable transfer planning API used by Lightsail and local agents.
- `cmd/carrack`: operator CLI.
- `control-plane`: Cloudflare Worker and D1 migrations.
- `web`: Carrack control console.
- `schemas`: shared protocol schemas.
- `docs/requirements.md`: normative product, concurrency, recovery, and safety
  requirements.
- `docs/architecture.md`: correctness, concurrency, key, and GC protocol.

## Provider status

The Go SDK includes an Aliyun Drive provider for the official Open API. It
supports OpenList-compatible OAuth renewal without running an OpenList server,
automatic folder creation, bounded-memory multipart uploads, metadata lookup,
and exact range downloads. The provider deliberately keeps uploads sequential
and applies the same conservative per-operation request limits as OpenList.

Providers are selected through an immutable runtime registry of versioned,
compiled factories. A control-plane `DriverSpec` carries a kind, strict
non-secret JSON configuration, and an encrypted credential reference. The
initial kind is `aliyundrive-open/v1`; unsupported kinds and unknown config
fields are rejected before any network request.

OpenList cannot be consumed as a normal Go SDK because its public driver
packages expose contracts from Go `internal` packages. Carrack therefore owns
a narrow adapter aligned to a recorded OpenList commit; see
`provider/aliyundrive/UPSTREAM.md`.

Credentials are runtime dependencies. Callers may use a fixed access token or
the OpenList-compatible refresh-token source. A rotated refresh token must be
persisted through the supplied callback before the new access token is used.
Neither tokens nor download URLs belong in manifests, D1, logs, or Git.

The V1 default layout uses 64 MiB physical blocks, 8 MiB crypto frames, and
8 GiB target logical packs. A physical block is Carrack's independently
verified leaf, not a provider multipart-upload part. Drivers choose their own
part size and concurrency. All layout values are policy defaults rather than
protocol constants.

The initial crypto suite is `carrack-aes128gcm-hkdfsha256-v1`. Root-to-epoch
derivation matches across Go and Rust through a shared golden vector; pack keys
and authenticated frames are implemented only in the provider-free Go crypto
layer. The transfer layer sees opaque SHA-256-addressed ciphertext extents,
supports replica fallback and bounded concurrent batches, and has no crypto
dependency. Integration tests compose the layers without merging them.

The import path persists every random pack ID before transfer, then encrypts
whole frame spans into bounded 64 MiB staging extents. Each content-addressed
extent is uploaded and independently read back before it enters the portable
manifest. The SDK writes a destination sidecar and submits the identical
metadata to the Worker, which validates it again and stores it in a
recovery-SHA-addressed R2 archive. Replaying the same persisted plan produces
byte-identical ciphertext and safely converges with an earlier interrupted
upload.

Carrack prefers native drivers where Go already has a mature protocol or SDK:
S3-compatible storage, R2, public HTTP, and local filesystems do not pass
through OpenList. OpenList-derived adapters are reserved for long-tail consumer
cloud drives where its provider compatibility and OAuth work provide real
value. They still implement the same Carrack registry contract and do not
require an OpenList server.

## Development

```bash
cp .env.example .env
chmod 600 .env
nix develop
just verify
```

Cloudflare operator authentication, D1 migrations, runtime secrets, and deploy
commands are documented in `docs/cloudflare.md`.

This repository is private. Credentials belong in runtime secret stores, never
in tracked files.
