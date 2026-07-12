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
non-secret JSON configuration, and an optional encrypted credential reference.
The compiled kinds are `aliyundrive-open/v1`, `public-http/v1`, and
`local-filesystem/v1`; unsupported kinds and unknown config fields are rejected
before provider access.

The read-only native `public-http/v1` driver supports public HTTPS archives and
loopback test servers. It requires canonical relative keys, same-origin
redirects, identity encoding, and an exact `206 Content-Range`; whole-object or
ambiguous range responses are rejected. Restore may open both Aliyun and public
HTTP drivers and follows each extent's ordered replica locations for fallback.

The native `local-filesystem/v1` driver confines canonical keys beneath one
existing root with Go's traversal-resistant rooted filesystem API. It provides
content-derived object identity and exact range reads. Writes stream into a
private temporary file, verify the declared length and SHA-256, sync it, and
atomically publish without replacing an existing object. A retry succeeds only
when the existing object has identical bytes.

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

The provider-neutral replication SDK supplies the data path for copy and
repair. It reads each immutable ciphertext extent through ordered replica
fallback, verifies its SHA-256, groups only complete extents into bounded
content-addressed destination objects, and independently reads every object
back before returning a new location. Only after all payload groups verify does
it write an immutable recovery sidecar addressed by both the logical manifest
and complete recovery-document SHA-256. Replaying the same copy converges on
the same objects and does not duplicate locations. The controlled copy SDK pins
the current recovery revision, renews a write lease during provider I/O, and
cancels in-flight reads if renewal fails. The Worker accepts only an updated
recovery document that preserves the exact content manifest, retains every
source location, and covers every extent on the requested destination. It then
publishes the new locations and recovery head in one fenced revision CAS.
Concurrent losers remain unreachable staging, and an exact request can be
replayed after lease release. Copy never deletes a source; the later move saga
remains a separate operation. Controlled Repair is the narrower,
location-preserving path for objects proven missing: the Worker pins the exact
location revisions and complete provider-object identities, while the SDK
reconstructs every object from separately available, SHA-256-verified ranges.
After independent destination readback, one fenced D1 batch moves only those
locations through `verified` to `available`, resolves matching findings, and
closes the operation without changing the recovery revision. A changed
provider version or any corrupt range in the target object requires relocation
through Copy instead of an unsafe overwrite. The controlled move SDK pins every
available location on one source driver, publishes and verifies a complete
destination replica first, then publishes a second recovery revision that
removes exactly those pinned sources. The same live write fence protects both
revisions. D1 changes the removed locations to `tombstoned` and records a
policy-derived grace deadline, while the operation remains
`source_delete_pending` for an explicit janitor. Provider deletion is
intentionally not performed by the move client. An authorized `MoveJanitor`
later claims object-grouped delete
tasks, repeats active-read, reachability, replica-policy, incarnation, and
fence checks immediately before I/O, calls an idempotent driver deleter, and
only then advances D1 through `deleting` to `succeeded`. Lost completion
responses converge from the retained task record. The local filesystem driver
implements this delete capability; other drivers remain unavailable to the
janitor until they advertise and implement the same contract.

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

The local filesystem Import path encrypts one plaintext source into a distinct
archive root and publishes it under an `importer` or `administrator` token:

```bash
export CARRACK_CONTROL_TOKEN="$(read-importer-token)"

carrack import run \
  --control-url https://carrack.example.com \
  --namespace 202122232425262728292a2b2c2d2e2f \
  --object-id object-1 \
  --source-local-driver-id local-source \
  --source-local-root /srv/carrack/plaintext \
  --source-key dataset.bin \
  --destination-local-driver-id local-archive \
  --destination-local-root /srv/carrack/archive \
  --destination-prefix imported \
  --staging-directory /var/tmp/carrack \
  --plan-file /var/lib/carrack/plans/object-1.json
```

Source and destination driver IDs and canonical roots must differ. Operation
creation pins the namespace's active root version and key epoch, and the
fenced key grant supplies only that context. The command hashes the current
source identity into its idempotency key, atomically persists every random pack
ID before payload I/O, renews the write lease throughout encryption and
readback, and publishes only after the payload, destination sidecar, and R2
recovery copy verify. The plan contains no key material and must be reused for
a retry. `--expected-object-revision` defaults to `1` for a new object and must
be set to the current revision for a later generation.
If publication committed but its response was lost, an exact retry returns the
committed manifest with `already_published: true` without another key grant,
encryption pass, or destination write.

The restore CLI opens any configured compiled driver and accepts secrets only
through process environment variables:

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

A local archive replica can be used alone or alongside either remote driver:

```bash
carrack restore ./restored.bin \
  --control-url https://carrack.example.com \
  --namespace 202122232425262728292a2b2c2d2e2f \
  --manifest <manifest-sha256> \
  --local-driver-id local-mirror \
  --local-root /srv/carrack/archive
```

Driver IDs must match the manifest locations. The local root must already
exist; Carrack creates only object-key subdirectories beneath it.

An operator can independently scrub every complete ciphertext extent on one
local driver from a portable recovery sidecar, without a control-plane token or
decryption key:

```bash
carrack verify ./recovery.json \
  --local-driver-id local-mirror \
  --local-root /srv/carrack/archive \
  --format json
```

Verification streams each selected location through SHA-256 with constant
memory and does not stop after another replica succeeds. Its stable evidence
distinguishes verified bytes, proven missing objects, corrupt length or digest,
and unavailable drivers or inconclusive provider failures. A single pass does
not declare permanent data loss; reconciliation and repair remain separate
control-plane operations.

An administrator can run the same local scrub as a fenced control-plane
operation. The command renews its lease during provider reads and commits the
complete evidence set, location state changes, and integrity findings in one
idempotent D1 transaction:

```bash
export CARRACK_CONTROL_TOKEN="$(read-administrator-token)"

carrack verify run \
  --control-url https://carrack.example.com \
  --namespace 202122232425262728292a2b2c2d2e2f \
  --manifest <manifest-sha256> \
  --local-driver-id local-mirror \
  --local-root /srv/carrack/archive \
  --idempotency-key local-mirror-scrub-2026-07-12
```

The idempotency key names one audit attempt. Retrying that attempt reuses its
pinned recovery revision; a later scheduled scrub must use a new key.

Metadata reconciliation is a separate administrator operation. It compares a
validated R2 recovery document with the complete D1 location snapshot under one
renewable fence and records `unindexed`, `orphan`, and `degraded` findings
without contacting providers or editing the manifest:

```bash
carrack reconcile run \
  --control-url https://carrack.example.com \
  --namespace 202122232425262728292a2b2c2d2e2f \
  --manifest <manifest-sha256> \
  --idempotency-key metadata-reconcile-2026-07-12
```

The Worker recomputes the submitted report before committing it. Exact retries
are idempotent, changed reports are rejected, and resolved discrepancies close
only findings with the same condition and subject identity.

A relay can repair provider objects that verification has proven missing while
another exact replica remains available. This local-filesystem path preserves
the original storage keys and recovery revision:

```bash
export CARRACK_CONTROL_TOKEN="$(read-relay-token)"

carrack repair run \
  --control-url https://carrack.example.com \
  --namespace 202122232425262728292a2b2c2d2e2f \
  --manifest <manifest-sha256> \
  --source-local-driver-id local-source \
  --source-local-root /srv/carrack/source \
  --destination-local-driver-id local-mirror \
  --destination-local-root /srv/carrack/mirror \
  --idempotency-key local-mirror-repair-2026-07-12 \
  --staging-directory /var/tmp/carrack
```

The operation repairs only the target locations pinned when that idempotency
key was created. Newly missing locations require a new operation. Every range
in a target object must have a different, currently available source; corrupt
target objects and providers that cannot reproduce the pinned version identity
are rejected for relocation through Copy.

The local filesystem Copy path creates and publishes a verified destination
replica while retaining every source location:

```bash
export CARRACK_CONTROL_TOKEN="$(read-relay-token)"

carrack copy run \
  --control-url https://carrack.example.com \
  --namespace 202122232425262728292a2b2c2d2e2f \
  --manifest <manifest-sha256> \
  --source-local-driver-id local-source \
  --source-local-root /srv/carrack/source \
  --destination-local-driver-id local-destination \
  --destination-local-root /srv/carrack/destination \
  --destination-prefix copied \
  --staging-directory /var/tmp/carrack
```

Source and destination driver IDs and canonical roots must differ. The command
derives a stable idempotency key from the complete Copy identity, renews its
write fence during direct provider I/O, and exits only after the destination
objects, recovery sidecar, and recovery head have been verified and published.
It never tombstones or physically deletes the source, so no janitor sweep is
required.

The local filesystem Move path uses the same verified replication protocol.
A `relay` or `administrator` token continues through source tombstoning after
destination publication, but does not physically delete the source:

```bash
export CARRACK_CONTROL_TOKEN="$(read-relay-token)"

carrack move run \
  --control-url https://carrack.example.com \
  --namespace 202122232425262728292a2b2c2d2e2f \
  --manifest <manifest-sha256> \
  --source-local-driver-id local-source \
  --source-local-root /srv/carrack/source \
  --destination-local-driver-id local-destination \
  --destination-local-root /srv/carrack/destination \
  --destination-prefix moved \
  --staging-directory /var/tmp/carrack
```

The command derives a separate stable idempotency key from the complete Move
identity and prints the operation ID and grace deadline required by the later
janitor handoff.

After a Move reaches `source_delete_pending` and its grace deadline passes, an
explicit janitor token can sweep a local filesystem source:

```bash
export CARRACK_CONTROL_TOKEN="$(read-janitor-token)"

carrack move sweep <move-operation-id> \
  --control-url https://carrack.example.com \
  --local-driver-id local-source \
  --local-root /srv/carrack/archive
```

The token must have the namespace `janitor` or `administrator` role. The
command cannot choose arbitrary keys: it deletes only object tasks returned
and revalidated by the control plane. Driver IDs and the root must match the
source configuration used by the operation.

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
