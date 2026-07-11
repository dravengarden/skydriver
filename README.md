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

- `archive`: configurable physical layout and the canonical gapless small-file
  bundle format. Configured sizes are targets and never add zero padding.
- `cryptostream`: provider-free HKDF and framed AES-GCM implementation.
- `manifest`: versioned, content-addressed archive manifests.
- `provider`: storage provider boundaries.
- `transfer`: crypto-free opaque ciphertext extent fetching and verification.
- `sdk`: embeddable transfer planning API used by Lightsail and local agents.
- `cmd/carrack`: operator CLI.
- `control-plane`: Cloudflare Worker and D1 migrations.
- `web`: Carrack control console.
- `schemas`: shared manifest, recovery, bundle, and bundle-plan schemas.
- `docs/requirements.md`: normative product, concurrency, recovery, and safety
  requirements.
- `docs/bundle-format.md`: exact zero-padding bundle wire contract.
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

The read-only native `public-http/v1` driver supports public HTTPS archives and
loopback test servers. It requires canonical relative keys, same-origin
redirects, identity encoding, and an exact `206 Content-Range`; whole-object or
ambiguous range responses are rejected. Restore may open both Aliyun and public
HTTP drivers and follows each extent's ordered replica locations for fallback.

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

Batch downloads coalesce only adjacent primary ranges from the same provider
object, up to an independent memory bound. One exact provider read still
produces separately owned and separately hashed extent buffers. A failed or
corrupt coalesced read falls back to the normal ordered multi-replica path, so
the optimization cannot weaken correctness or change ciphertext identity.

The restore SDK pins one portable recovery manifest, verifies each downloaded
ciphertext extent, authenticates every encrypted frame, and verifies the final
plaintext identity before atomically publishing a local file. Interrupted
restores retain a key-free journal and staging file; resume rehashes every
claimed local plaintext span before skipping its network transfer.
The control-plane restore protocol pins the immutable version before transfer,
renews an operation-scoped read lease, and releases it only after the SDK's
verified manifest and plaintext identities are committed as succeeded.
Portable recovery metadata is fetched from R2 only under that lease and is
validated again before the client receives it; archive payload remains direct.
The controlled restore SDK composes manifest pinning, read-lease renewal,
metadata fetch, local restore, and fenced completion. A renewal failure cancels
in-flight provider reads and prevents local publication.
Terminal authenticated-decryption or plaintext-identity failures close the
operation and release its lease immediately; transient provider failures keep
the key-free local resume state and are not reported as permanent corruption.
Each verified extent emits cumulative wire-read, useful-verified, active-time,
and replica-retry counters through the same fenced, reorder-safe telemetry
protocol used by imports. Telemetry failure does not invalidate restored data;
the CLI surfaces an explicit warning after retrying the latest sample.

The import path persists every random pack ID before transfer, then encrypts
whole frame spans into bounded 64 MiB staging extents. Consecutive extents are
coalesced into exact-length, content-addressed provider objects under the
driver's preferred and maximum sizes; locations retain each internal range.
Every provider object is independently read back before it enters the portable
manifest. The SDK writes a destination sidecar and submits the identical
metadata to the Worker, which validates it again and stores it in a
recovery-SHA-addressed R2 archive. Replaying the same persisted plan produces
byte-identical ciphertext and safely converges with an earlier interrupted
upload. The control client exposes idempotent operation creation, renewable
fenced claims, monotonic progress reporting, recovery staging, and atomic
import publication; provider payload bytes still never enter the Worker.

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

The initial restore CLI opens the compiled `aliyundrive-open/v1` driver and
accepts secrets only through process environment variables:

```bash
export CARRACK_CONTROL_TOKEN="$(read-control-token)"
export CARRACK_ALIYUN_ACCESS_TOKEN="$(read-aliyun-access-token)"

carrack restore ./restored.bin \
  --control-url https://carrack.example.com \
  --namespace 202122232425262728292a2b2c2d2e2f \
  --manifest <manifest-sha256> \
  --driver-id aliyun-main
```

An optional public replica can participate in the same restore:

```bash
carrack restore ./restored.bin \
  --control-url https://carrack.example.com \
  --namespace 202122232425262728292a2b2c2d2e2f \
  --manifest <manifest-sha256> \
  --driver-id aliyun-main \
  --public-http-driver-id public-mirror \
  --public-http-base-url https://archives.example.com/carrack
```

The control token is an unpadded base64url encoding of exactly 32 bytes. Under
the active read fence, the Worker derives the manifest's epoch key from its
versioned root secret, audits the grant without key material, and returns it to
the SDK over HTTPS. `CARRACK_EPOCH_KEY` remains an optional 32-byte base64url
override for offline recovery and controlled testing. The access-token form
above is caller-managed and never persisted.

For renewable credentials, initialize an encrypted compare-and-swap store once:

```bash
unset CARRACK_ALIYUN_ACCESS_TOKEN
export CARRACK_CREDENTIAL_KEY="$(read-credential-key)"
export CARRACK_ALIYUN_REFRESH_TOKEN="$(read-aliyun-refresh-token)"

carrack restore ./restored.bin \
  --control-url https://carrack.example.com \
  --namespace 202122232425262728292a2b2c2d2e2f \
  --manifest <manifest-sha256> \
  --driver-id aliyun-main \
  --credential-store ~/.local/state/carrack/aliyun-main.json
```

The credential key is a non-zero, unpadded base64url encoding of exactly 32
bytes and must come from a separate secret store. Carrack writes the encrypted
credential file with mode `0600`, binds its identity and revision into AES-GCM
authenticated data, and atomically persists every rotated refresh token. After
initialization, unset `CARRACK_ALIYUN_REFRESH_TOKEN`; subsequent restores load
and update the encrypted file using only `CARRACK_CREDENTIAL_KEY`.

This repository is private. Credentials belong in runtime secret stores, never
in tracked files.
