# Carrack VFS V2

## Status

This document records the accepted V2 product direction. New V2 code follows
this document while the archive-oriented V1 implementation remains in the
repository for migration. V2 deliberately removes V1 packs, bundles, extents,
leaf merging, and compaction instead of adapting them into the filesystem.

The transition is complete only after `requirements.md` and `architecture.md`
have been replaced with the V2 baseline and the legacy packages have been
removed. Until then, V1 correctness fixes and V2 implementation changes must
remain isolated from one another.

The current implemented V2 slice includes:

- the complete-object driver contract, capability warnings, local filesystem
  driver, durable transfer journal, and Go/Rust Merkle formats;
- D1 identities, entries, versions, locations, roots, ACLs, attenuated tokens,
  optimistic Put intents and receipts, and catalog mutation/outbox records;
- one-shot encrypted or plaintext bootstrap, sealed directory-key epochs, and
  reauthorized short-lived key and driver grants;
- framed AES-256-GCM complete-file transforms with per-version HKDF keys; and
- SDK `Put`, `PutFile`, and `PutBytes` plus `carrack vfs put`, exercised against
  the real local Worker and `local-filesystem/v2` driver; and
- revision-consistent directory reads, Merkle-linked child creation,
  attenuated token lifecycle, direct ACL replacement, and placement replace-all
  through the Worker, Go SDK, and CLI; and
- a private local namespace catalog keyed by directory ID and Merkle root, with
  bounded concurrent prefetch, durable verified nodes, subtree reuse, and final
  live-root revalidation.

The next slices add immutable file-version and location records to the local
catalog, safe R2 checkpoint/delta materialization, and local transfer planning;
then Get, Push, and Pull; remote V2 drivers; V2 reachability/GC; and final legacy
removal. The archive-oriented CLI and packages below the V2 boundary remain
available only for migration and existing V1 workflows.

## Product boundary

Carrack maintains a virtual filesystem with three implementation surfaces:

1. A Rust control plane on Cloudflare with a React 19 operator UI.
2. A Go CLI and SDK used by people, automation, and AI skills.
3. Compiled Go storage drivers for S3, R2, Google Drive, Aliyun Drive,
   WebDAV, and local filesystems.

The CLI and SDK operate only between bytes or a local filesystem and the
Carrack VFS. External sources such as an unrelated S3 bucket, database, HTTP
service, or generated stream remain caller-owned. A caller may expose such a
source as bytes, a replayable reader, or a range source without adding source
semantics to Carrack.

Payload bytes flow directly between the Go client and a storage driver. The
control plane never relays VFS file payloads and never implements provider data
operations.

## Core invariants

1. One immutable Carrack file version is stored as one complete provider
   object at every location.
2. Carrack never stripes one file across drivers and never exposes a partial
   object at its final provider locator.
3. Provider multipart parts, encryption frames, verification blocks, and HTTP
   ranges are transport units, not independently addressable VFS data.
4. A file version becomes readable only after its complete identity and every
   required integrity proof have been verified.
5. A directory root cryptographically commits to its canonical entries and
   descendant content roots.
6. Provider object names reveal no virtual path, original filename, user,
   directory, media type, or business meaning.
7. Network transfer never holds a database transaction or a distributed
   pessimistic lock.
8. Metadata publication uses immutable identifiers, idempotency, expected
   versions, and short optimistic transactions.
9. Correctness never degrades. A missing acceleration capability may reduce
   performance or restart scope only after an explicit warning.
10. Deletion is delayed, fenced, auditable, and performed by an authorized Go
    janitor rather than by the control plane.

## Logical model

### Directory

A directory is a collection, authorization boundary, encryption boundary, and
placement-policy boundary. It has a stable identifier independent from its
name and parent. The tree exists for naming, navigation, policy inheritance,
and permission management; it does not mirror any provider directory tree.

Each directory records at least:

- a stable `directory_id`;
- its parent and canonical virtual name;
- an active content-encryption epoch;
- an inherited access-control policy;
- allowed and preferred storage driver instances;
- its current data root and monotonic metadata revision.

### File and file version

A file has a stable opaque 128-bit `file_id` and a mutable current-version
pointer. Every content change creates a new immutable 128-bit `version_id`.
The control plane should allocate UUIDv7 identifiers for D1 index locality;
they are never derived from paths or content. The version identifier, not the
stable file identifier, participates in key derivation so an overwrite cannot
reuse an encryption key and nonce domain. Provider storage names remain a
separate random 192-bit-or-stronger namespace.

A file version records at least:

- exact plaintext length;
- plaintext verification-block hashes and file Merkle root;
- encryption suite, directory key epoch, and frame size;
- exact encoded length and complete ciphertext hash;
- one or more complete provider locations;
- immutable creation and publication identities.

### Location

A location is one complete encoded file version on one driver instance. It
contains a driver-owned locator, exact length, provider version identity, and
verification state. It never contains an offset into a shared object.

The control plane allocates a distinct random 192-bit or stronger object name
for each location. Drivers with stable native identifiers, such as cloud-drive
file IDs, retain those identifiers in their typed locator and use them for
subsequent operations.

One directory may contain files on different drivers. One file version may
also have several complete locations on independent drivers.

### Snapshot and channel

A snapshot pins one immutable recursive directory root. A channel is a mutable
name, such as `latest`, that conditionally points to a snapshot. Publishing a
software release stages and verifies every file and snapshot first, then moves
the channel with one expected-version compare-and-swap.

## Provider representation

Virtual paths never become provider paths. A provider may use one reserved
Carrack root and randomly sharded opaque object names, for example:

```text
objects/v2/7f/7FW3VJQX8G1M9Z...
```

The object metadata must not contain the original filename, virtual path,
media type, or user-supplied description. Unencrypted file content remains
visible to the provider by definition, but its name and VFS placement remain
opaque.

A completed multipart upload is one provider object. A storage system whose
large-object format permanently exposes independently deletable segment
objects does not satisfy the V2 complete-object contract unless the driver can
prove that those segments are provider-internal and cannot independently
invalidate the final object.

## Integrity model

### File Merkle tree

Carrack divides a file into fixed-size verification blocks solely for hashing,
parallel transfer, and recovery. The final block uses its exact length. A
domain-separated SHA-256 Merkle construction commits to the block ordinal,
exact length, and bytes. `vfs-merkle-v1.md` defines the canonical binary format,
left-complete tree shape, NFC directory ordering, and shared Go/Rust golden
vectors.

Encrypted files align independently authenticated AEAD frames with verification
blocks when provider constraints permit. Unencrypted files retain the block
hashes in protected metadata so parallel range downloads and resumed writes
can verify every completed range before trusting it.

Publication requires both the plaintext file root and the complete encoded
object identity. A provider with a trusted strong upload checksum may satisfy
encoded-object verification without readback. A provider without one requires
a complete independent readback. This fallback may cost bandwidth but cannot
reduce correctness.

### Directory Merkle tree

Directory entries use canonical UTF-8 names, one normalization rule, bytewise
ordering, and a domain-separated hash. A file entry commits to its stable file
identity, immutable version identity, exact length, file root, and portable
metadata. A directory entry commits to the child identity and child data root.

Content roots remain separate from ACL and placement-policy roots. Permission
changes therefore do not create false file-content changes, while an optional
combined state root can authenticate both domains.

An upload or download succeeds only after the resulting file root matches. A
directory synchronization succeeds only after its resulting directory root
matches the pinned snapshot. Hash disagreement, incomplete bytes, unsupported
crypto, and unavailable keys are explicit failures and never successful
degradations.

## Metadata distribution

D1 is the online transaction authority but not the bulk read path for large
directory synchronization. Every committed mutation receives a monotonic
catalog revision. The control plane materializes immutable metadata in R2 as:

- periodic zstd-compressed canonical checkpoints;
- content-addressed, hash-chained delta segments after each checkpoint;
- a signed head containing revision, checkpoint, delta tail, and directory
  roots.

The CLI authenticates once, obtains a head and scoped metadata grant, downloads
the checkpoint or missing deltas directly, verifies the chain and final root,
and updates a local SQLite catalog. It then computes the complete transfer plan
locally. No per-file control-plane request is required on the payload hot path.

The implemented first slice uses the directory Merkle graph directly: private
local nodes are addressed by `(directory_id, data_root)`, missing directories
are assembled from revision-pinned pages with bounded cross-directory
concurrency, and the live root is revalidated after the recursive closure.
Unchanged subtrees require no control-plane read. Immutable version/location
records, a query index, and R2 checkpoint/delta publication remain pending;
`vfs-catalog-v1.md` fixes the current protocol and its exact boundary.

Checkpoints optimize full sequential catalog transfer. Delta segments optimize
incremental synchronization. A content-addressed Merkle B-tree may be added
for extremely large partial catalogs without changing directory roots or the
CLI planning model.

Catalog publication uses a D1 outbox and idempotent materialization. A head
never advertises an R2 revision until its immutable objects exist and verify.
Queue redelivery may duplicate work but cannot publish a different object at
the same content address.

## Client API

The stable user-facing operations are:

```text
Put(bytes or local file, VFS path)
Get(VFS path or version, writer or local file)
Push(local directory, VFS directory)
Pull(VFS directory or snapshot, local directory)
```

`Put` accepts in-memory bytes, a replayable stream, a range source, or a local
file. A one-shot or unknown-size stream is spooled to a protected temporary
file by default so hashing, retry, and recovery remain possible. `Get` to an
ordinary writer similarly stages and verifies before emitting bytes unless the
caller explicitly requests a non-resumable stream.

The Go SDK exposes both high-level methods and prepare, transfer, and commit
primitives. Callers may schedule many prepared transfers and supply their own
source pipeline, but they cannot bypass Carrack hashing, encryption, provider
verification, or conditional publication.

`vfs-bootstrap-v1.md` defines the one-shot authority bootstrap.
`vfs-put-v1.md` defines the implemented prepare, key and driver grants,
block-manifest staging, and optimistic commit wire protocol, including
idempotent replay, token refresh, Merkle-root recomputation, and D1 publication
invariants.
`vfs-management-v1.md` defines the implemented directory, token, ACL, and
placement-management routes, CLI commands, action requirements, and race
handling.
`vfs-catalog-v1.md` defines the implemented private local namespace DAG,
incremental synchronization, cache durability, and root-race handling.

CLI payloads use stdin and stdout rather than command-line byte arguments.
Machine-readable results have stable JSON schemas. Payload stdout is never
mixed with diagnostics; warnings and errors go to stderr. Mutations support
idempotency keys, expected versions, dry-run planning, and explicit deletion.

## Incremental, resumable, concurrent, and pipelined transfer

### Incremental synchronization

V2 guarantees file-level directory incrementality: unchanged file roots
transfer no payload bytes. A fast scan may use size, mtime, and local identity,
but final equality is established by the authenticated catalog and file root.

Cross-version binary delta upload is not a V2 portability guarantee. Updating
one byte still creates one new complete provider object. Drivers with safe
server-side range copy may accelerate unchanged ranges, but the optimization
cannot change the final object model or the correctness protocol.

### Resumable transfer

An upload journal retains the source identity, plan, immutable version and
object names, provider upload session, completed parts, checksums, and commit
preconditions. Resume rechecks the source, reacquires short-lived secrets,
compares the provider session with the journal, and transfers only missing or
invalid parts.

A download journal pins the snapshot, file version, provider identity,
staging file, and verified-block bitmap. Resume range-reads only missing blocks
and reacquires keys without persisting them. Final publication requires the
complete file root and an atomic no-replace local publication.

### Reference transfer journal

The Go `transfer/journal` package is the V2 reference recovery protocol. Its
private local store contains no payload bytes, credentials, directory keys, or
encryption secrets. It persists:

- one immutable SHA-256-enveloped plan with the exact probed driver descriptor,
  pinned source or provider object, complete checksum, and canonical ranges;
- an append-only, hash-chained state history guarded by optimistic revision
  CAS and an expiring executor fence;
- immutable per-part or per-block receipts published only after the provider
  or staging bytes are durable and verified.

Before a resumable upload calls provider completion, the journal commits the
ordered provider completion manifest, including provider ETags. A restart in
the `verifying` state therefore replays completion directly and does not depend
on listing a multipart session that the provider may already have destroyed.
A complete-write fallback relies on the driver contract's idempotent fresh-key
retry and records the returned immutable object before its terminal revision.

Range downloads rehash every receipted staging block before trusting it. A
missing or changed block is fetched again. Drivers without exact range support
restart only the current file as one verified sequential read and retain the
same journal API. Final publication first makes the verified sibling staging
inode visible at a non-replacing destination name, persists that link, and only
then removes and persists the staging name. Recovery recognizes an already
published exact destination and completes the journal without provider I/O.
Receipts are immutable while an attempt remains viable. If the final complete
SHA-256 rejects the assembled staging file, the entire untrusted receipt set is
durably invalidated before retry so an observed-but-wrong range cannot trap the
journal in a permanent verification loop.

The executor lease limits duplicate work but is not a pessimistic transfer
lock. After expiry another process may retry idempotent provider I/O; only the
current hash-chain revision can record progress or completion. Corrupt,
non-canonical, oversized, symlinked, cross-plan, or discontinuous records are
hard errors rather than restart hints.

### Concurrency and pipeline

The local planner has bounded queues for source reads, hashing, encryption,
provider I/O, verification, local publication, and batched metadata commits.
Memory is limited by total in-flight bytes rather than file count. Each driver
has independent concurrency, rate, and retry budgets.

Small files use file-level concurrency. Large files use parallel multipart
uploads or parallel range downloads when the driver advertises them. A driver
that permits only sequential resumable chunks still participates in the same
pipeline with per-file concurrency one while other files continue in parallel.

Adaptive concurrency reacts to measured throughput, latency, throttling,
quota, and provider errors. It never exceeds the driver's advertised safe
limits. Control-plane progress and completion reports are buffered and batched;
temporary metadata latency does not stall payload work while a prepared plan
window remains.

## Driver contract and degradation

The high-level Carrack API is identical for every driver. The driver SPI uses
small required interfaces plus optional range, resumable, multipart, checksum,
inventory, copy, and delete interfaces. Capabilities state whether a behavior
is native, safely emulated, or unavailable and document exact concurrency,
size, ordering, and session limits.

Every driver API comment must state:

- the complete-object correctness guarantee;
- native, emulated, server-dependent, and unavailable features;
- fallback behavior and its retry or performance impact;
- hard limits and required provider identities;
- recommended replacement driver kinds for missing acceleration features.

The planner evaluates capabilities before payload I/O. Missing acceleration
produces a structured warning describing correctness impact, fallback, and
configured or compiled alternatives. Warnings are emitted once per operation,
not once per block.

Permitted degradations include sequential full-object download, restarting the
current file, sequential resumable upload, and complete readback verification.
The following are hard errors rather than degradations:

- partial data can become visible at the final locator;
- an immutable object identity cannot be pinned;
- exact length and cryptographic integrity cannot be verified;
- the file exceeds the provider's complete-object limit;
- an object name can be silently overwritten without a unique key or version;
- a claimed range cannot be proven to match the requested immutable bytes.

Callers may require capabilities or reject every degradation. Directory
placement policy may likewise require range reads or resumable writes and ask
the control plane to choose another allowed driver before failing.

Driver capability declarations are the single source for Go documentation,
CLI inspection, UI tables, generated Markdown, warnings, and replacement
advice. A native declaration requires a contract test. Server-dependent
protocols such as WebDAV and nominally S3-compatible services require
registration-time probes and operation-time validation rather than optimistic
assumptions.

## Encryption and keys

File content is encrypted by default. A directory may explicitly select a
versioned plaintext suite. Provider object names remain opaque in either mode.

Each directory has a random 256-bit secret and independent epochs. D1 stores
only an authenticated envelope under a versioned control-plane master key. A
file content key is derived with HKDF-SHA-256 from the directory epoch secret
and immutable file version identifier using a fixed domain-separated label.

The control plane grants a directory epoch key once per authorized operation
or plan window. The client derives individual file keys locally, avoiding a
per-file control-plane dependency. Directory-level permissions are therefore
the V2 cryptographic boundary; file-level ACLs are not part of V2.

Renaming within one directory is metadata-only. Moving content across directory
key boundaries creates and verifies a new encoded file version. V2 does not add
a file-key wrapping layer merely to optimize cross-directory moves.

Possession of a granted directory epoch key cannot be revoked from client
memory. Token revocation prevents new metadata, credential, key grants, and
commits. Revoking historical content access requires a new directory epoch and
explicit re-encryption.

## Authorization

V2 uses fixed actions, groups, inherited directory ACLs, and attenuated tokens
instead of a general policy language. Roles are UI presets over fixed actions,
not independently programmable policy engines.

Actions include directory listing, content read, content write, entry delete,
snapshot publish, ACL management, token issue, driver use, driver management,
GC execution, audit read, and system management. Administrative permissions do
not implicitly grant content-read permission.

A token binds one user or service principal and can only narrow that
principal's current permissions by directory subtree, action set, driver set,
snapshot, and expiry. AI skills use short-lived service tokens with the
smallest directory and action scope. Every key grant, credential grant,
publication, ACL mutation, and destructive action is audited without logging
secret material.

## Concurrency

V2 uses optimistic concurrency because provider transfer can last minutes or
hours. A pessimistic directory lock would require expiry, renewal, fencing,
crash takeover, and user-visible blocking while providing no stronger final
publication guarantee.

Prepare allocates immutable version and object identities and records
idempotent staging intent without locking a directory. Payload transfer occurs
outside D1. Commit reauthorizes the current token and ACL, verifies expected
entry versions, inserts verified locations, updates entries and affected
directory roots, and advances the catalog revision in one short transaction.

Disjoint entry changes may merge even when the global root changed. Changes to
the same entry produce an explicit conflict. A losing upload remains an
adoptable staging object or a future GC candidate; it never overwrites the
winner. Replaying an identical idempotency key returns the durable receipt.

Only short database transactions and destructive janitor claims use exclusive
coordination. An optional advisory sync reservation may improve operator UX but
must not participate in correctness.

## Garbage collection

GC remains necessary for abandoned uploads, losing conflicts, replaced
versions, deleted entries, expired snapshots, and lost provider responses. It
is substantially simpler because a provider object belongs to one complete
file location and is never shared by byte ranges.

Current roots, retained snapshots, active snapshot read sessions, and
unexpired upload intents protect their reachable locations. Mark changes an
unreachable location irreversibly to a tombstoned state with a policy-derived
deadline. A tombstoned location cannot be referenced again; recovery creates a
new location with a new object name.

After grace, a janitor claims a short fenced task. Immediately before I/O, the
control plane rechecks the task, incarnation, deadline, immutable locator, and
provider identity. The Go janitor performs `Stat` and idempotent `Delete`.
After a lost response it re-observes the exact object; absence is success.

The control plane plans GC but never calls a VFS storage driver. Its R2 binding
is used only for control metadata such as catalogs and audit recovery, not for
ordinary VFS file payloads.

## Initial implementation order

1. Introduce the V2 driver contract, capability assessment, warnings, and
   generated support documentation beside the legacy provider package.
2. Implement a V2 local-filesystem driver and complete-object transfer journal
   as the reference contract implementation.
3. Add file and directory Merkle formats with Go/Rust golden vectors.
4. Add VFS identifiers, entries, immutable versions, locations, snapshots,
   ACLs, tokens, optimistic prepare/commit, and catalog revisions.
5. Implement metadata checkpoints, deltas, local SQLite synchronization, and
   local planning.
6. Implement high-level `put`, `get`, `push`, and `pull` APIs and AI-stable CLI
   JSON contracts.
7. Add S3 and R2 drivers, then Google Drive, Aliyun Drive, and WebDAV behind
   the same contract tests.
8. Add conservative reachability, grace, and fenced janitor GC.
9. Remove legacy packs, extents, bundles, compaction, and operation protocols
   after V2 parity and migration tests pass.
