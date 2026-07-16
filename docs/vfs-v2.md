# Carrack VFS V2

## Status

This document records the implemented V2 product boundary. The public client,
SDK, and management binaries are Rust and use complete provider objects. The
former Go archive SDK, CLI adapters, providers, packs, bundles, extents, leaf
merging, and compaction have been removed. The small retained Go packages are
strict conformance oracles for the complete-object driver contract, recovery
journal, and shared binary vectors; they are not an installation surface.

The current implemented V2 slice includes:

- the complete-object driver contract, capability warnings, native Rust local
  filesystem, Aliyun Drive Open, and Cloudflare R2 drivers, durable private
  transfer journals, and shared Go/Rust Merkle conformance vectors;
- D1 identities, entries, versions, locations, roots, ACLs, attenuated tokens,
  optimistic Put intents and receipts, and catalog mutation/outbox records;
- one-shot encrypted or plaintext bootstrap, sealed directory-key epochs, and
  reauthorized short-lived key and driver grants;
- framed AES-256-GCM complete-file transforms with per-version HKDF keys; and
- Rust file and byte Put, resumable ranged Get, incremental directory Sync,
  Remove, and metadata-only Rename/Move, exercised against the real local
  Worker and `local-filesystem/v2` driver; and
- revision-consistent directory reads, Merkle-linked child creation,
  attenuated token lifecycle, direct ACL replacement, and placement replace-all
  through the Worker, canonical Rust client, and CLIs; and
- a private local namespace and transfer catalog keyed by authenticated roots,
  bounded concurrent prefetch, durable verified nodes and range journals,
  subtree reuse, and final live-root revalidation; and
- server-materialized complete catalog checkpoints, directly streamed to safe
  full-root tokens or projected to a safe narrow token's exact Merkle subtree,
  plus optional single-transition hash-linked full-root deltas, shared
  native/WASM verification, and transparent ACL-boundary/full-checkpoint
  fallback; and
- durable read leases, reachability marking, tombstone grace, server-owned
  fenced GC, idempotent Aliyun and R2 deletion, and conservative retention for
  drivers the Worker cannot reach; and
- environment-owned default R2 identities, direct SigV4 client grants,
  resumable multipart upload, concurrent exact-range download, and
  binding-owned server cleanup independent of client signing-key rotation.

Remaining expansion work is explicit: multi-hop or narrow-view catalog-page
acceleration, additional hosted drivers, and production fault-injection for
every lifecycle class. Durable Aliyun credential rotation and removal of the
compatibility Go archive surface are complete and do not change the public
complete-object filesystem contract.

## Product boundary

Carrack maintains a virtual filesystem with two product components:

1. A Rust control plane on Cloudflare with a React 19 operator UI and typed
   hosted-driver lifecycle adapters.
2. A canonical Rust client core used by the filesystem and management CLIs.

The CLI and SDK operate only between bytes or a local filesystem and the
Carrack VFS. External sources such as an unrelated S3 bucket, database, HTTP
service, or generated stream remain caller-owned. A caller may expose such a
source as bytes, a replayable reader, or a range source without adding source
semantics to Carrack.

Payload bytes flow directly between the Rust client and a provider endpoint
described by a bounded server plan. The control plane never relays VFS file
payloads, but it owns provider control operations such as exact Stat, multipart
abort, credential refresh, and Delete.

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
10. Deletion is delayed, fenced, auditable, and performed only by the control
    plane's typed hosted-driver lifecycle executor.

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

D1 is the online transaction authority but not the intended bulk read path for
large directory synchronization. Every committed mutation receives a monotonic
catalog revision. The current Cron materializer collapses pending historical
outbox work into a newly verified latest checkpoint: it reconstructs the whole
live tree under start/end root fences, writes canonical JSON to a
content-addressed create-only R2 key, and advances the D1 catalog head only
after the exact object exists. When both the previous and target checkpoints
fit an 8 MiB acceleration bound, the same pass may additionally publish a
strictly smaller delta containing only target `(directory_id, data_root)` nodes
absent from the base. The complete target remains independently sufficient.
Tracked failed, superseded, and no-longer-current checkpoint/delta objects are
retired by indexed maintenance and reclaimed by exact R2 key after a 24-hour
grace period.

The implemented client uses the directory Merkle graph directly: private local
state is rooted in the authenticated directory snapshot, missing directories
are assembled from revision-pinned pages before payload scheduling, and the
live root is revalidated after the recursive closure. It then persists the
immutable file-version, verification-block, and completed-range state needed
for local incremental planning. Unchanged verified files require no provider
read, and changed files request grants directly by immutable version rather
than resolving every path again.

The native metadata boundary rejects noncanonical session and directory
identities, malformed entry unions, unsupported suites, unordered page
contents, and oversized responses before exposing them to callers. A complete
paginated directory additionally requires every continuation to retain the
exact directory identity and its ordered entries to reconstruct the advertised
Merkle root. A revision match alone is not an authenticated directory view.

Filesystem mutations and policy or token management use the same strict
boundary. The native client canonicalizes caller scopes before submission and
accepts a successful response only when its operation identity, requested
directory or token scope, normalized policy, revision transition, timestamp,
and terminal state form one valid receipt. Child-token issuance and revocation
also bind the receipt to a freshly authenticated parent session; a returned
bearer is never exposed until its canonical secret shape, exact narrowed
scope, and a fresh child session matching the receipt have been checked.

The Worker delivers the current checkpoint when the authenticated token is live
and nonsnapshot, has both `directory.list` and `content.read`, passes its current
inherited ACL checks, and has no descendant ACL inheritance break. A physical
filesystem-root view streams directly from R2. A narrow view is projected from
the verified immutable source into only the token root's complete Merkle
closure; the new logical root omits its original parent and name. The R2 key,
version, byte length, SHA-256, revision, and physical root are matched against
the exact published D1 head before either path. The native client bounds the
response at 32 MiB, verifies its independent body receipt, canonical JSON,
every directory root, and the complete reachable tree through the same portable
SDK used by Worker WASM, then publishes token-scoped content-addressed local
nodes. An ACL boundary, snapshot, absent checkpoint, or concurrent newer root
transparently uses the authenticated paginated API; corrupt metadata fails
closed.

SDK 0.3.2 full-root clients advertise an exact local base revision, root,
checkpoint SHA-256, and entity tag. If the current published delta links that
same base to the current head, the Worker streams the immutable delta directly
from R2. The portable SDK combines its changed nodes with the authenticated
local base, derives parent/name metadata from target Merkle edges, rejects
missing or unreachable changes, validates the complete target tree, and
requires its canonical JSON SHA-256 to equal the advertised target checkpoint.
Older clients, narrow roots, missed transitions, oversized sources, and deltas
that are not smaller simply receive the normal complete checkpoint.

The client distinguishes an authenticated 304 from an unavailable 204. Only a
200/304 bulk proof permits cache-only child traversal. After 204, every cached
directory requires a fresh authorized page before reuse, so a newly introduced
ACL boundary cannot be hidden by an older local Merkle node.

The client persists only a canonical SHA-256-enveloped checkpoint head after
all nodes are durable. Subsequent syncs send that strong entity tag. Full views
bind it to the body/object SHA-256; narrow views bind it to a domain-separated
digest of the immutable source and authorized root. The Worker repeats the
complete authorization and head proof, but returns HTTP 304 before opening R2
when the view is unchanged. This keeps unchanged sync metadata cost to one
bounded D1 proof plus the existing live-root fences; the local hint never
bypasses authorization or Merkle verification.

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

The Rust client exposes `ReplayableUploadSource` with an exact declared length,
`BoundedRangeUploadSource` with exact bounded range readers, and `put_reader`
with a mandatory maximum byte count for one-shot inputs. Non-file inputs are
normalized on a blocking worker into a unique mode-0600 RAII plaintext spool.
Short or overlong replayable/range readers and one-shot readers exceeding their
bound fail before control-plane or provider I/O. Cancellation and every error
path remove the private spool; the verified complete-object pipeline remains
the sole publication path.

`get_bytes` and `get_writer` require a nonzero maximum output size and reject an
oversized immutable version before provider I/O. Both reuse the ordinary
resumable file pipeline inside a unique mode-0700 private directory. The client
emits bytes only after exact length and plaintext Merkle verification succeeds;
it retains no alternate verification-before-completion path. Writer I/O runs
inline after verification so cancellation cannot detach a background task that
continues mutating the caller's writer after the future returns.

The canonical Rust client exposes the high-level filesystem methods and owns
prepare, transfer, and commit internally. Callers may schedule independent file
operations and supply bytes, local files, replayable readers, bounded range
sources, or explicitly bounded one-shot readers, but they cannot bypass Carrack
hashing, encryption, provider verification, or conditional publication. Every
source normalizes into that same path rather than creating a second transfer
implementation. No compatibility SDK implements a second product path.

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

Before requesting a download plan, the native client acquires a crash-released
cross-process fence on the caller's real staging-directory inode. The fence
remains held through provider assembly, decryption, plaintext verification,
publication, and encoded-staging cleanup, so two downloads cannot truncate or
remove the same resumable artifacts and the fence leaves no lock metadata.
Directory sync already gives each immutable version an independent staging
directory and therefore retains file-level concurrency. Independent direct
downloads that need parallelism likewise use independent staging directories;
sharing one root intentionally serializes them.

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

Before attempting that optimistic publication, Commit durably records an
immutable upload-evidence row containing the exact encoded hash, size, and
provider identity. A losing directory race therefore retains enough evidence
for a later fenced janitor instead of losing provider identity with the failed
publication transaction. A process failure between provider completion and
the Commit request remains discoverable through driver inventory and local
transfer journals.

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

Snapshot reachability is materialized in D1 as an immutable version set plus a
seal containing its canonical set digest and exact count. Retention, channel
pointers, and unexpired sealed snapshot tokens make that set protective. Token
revocation does not shorten the original protection deadline because a direct
read capability may already be in client memory. If any protective snapshot
lacks a seal or its materialized count differs, GC fails closed for the whole
filesystem. This covers snapshots created before the reachability migration,
partial publication, corruption, and manual database damage.

The read-only `safe_unreachable_vfs_locations` view subtracts current file
versions, live directory entries, and valid protective snapshot sets from
published available locations. It also requires an enabled driver and at least
one strong provider identity. The view is candidate evidence only: it does not
tombstone metadata, apply retention age, or authorize provider deletion.
Its `published_at` column lets the bounded mark query apply policy age while
using the partial published-version index before probing locations.

Every published version also records its immutable origin directory in the
same D1 publication batch. This survives entry replacement or deletion and is
the subtree boundary for future `gc.run` authorization. Migration backfill
accepts only versions with an exact committed Put receipt; a historical version
without a proven origin is absent from the candidate view and cannot be GCed.

For an upload that never published, metadata hygiene changes the intent to
`expired` and creates at most one delete task from its immutable upload
evidence. The task pins the driver revision and evidence digest, waits an
additional one-day grace, and is eligible only while no publication receipt or
non-deleted location references the provider object. A newly indexed location
supersedes the task immediately.

After grace, control-plane cron claims a short fenced task. Immediately before
I/O, it rechecks the task, deadline, immutable locator, active direct-read
leases, driver revision, and provider identity. Its hosted driver adapter
performs idempotent `Delete`; after a lost response, provider absence is
success.

Filesystem clients cannot enumerate, authorize, or execute cleanup. The
control plane owns bounded
selection, exact reachability revalidation, driver capability checks, fencing,
provider deletion, and idempotent completion. Aliyun has a native hosted
lifecycle adapter. Agent-local paths are not reachable by Cloudflare, so their
tasks become durably server-blocked and remain tombstoned; use S3, R2, or
Aliyun when automatic physical cleanup is required.

Ordinary VFS payload bytes still bypass the Worker. For `r2-default`, clients
use short-lived SigV4 URLs while the control plane uses the `CARRACK_PAYLOAD`
binding only for fenced physical deletion and multipart abort. Control metadata
continues to use its separate binding and object namespace.

The long-lived signing parent for `r2-default` is created once by the
environment provisioner as an account-owned token scoped to exactly the bound
payload bucket. Its value is converted to the documented S3 credential, passed
through the same write-only server validation as other R2 drivers, and sealed
in the environment's D1 credential envelope. The browser and filesystem SDKs
never receive that parent. The console exposes only redacted readiness; an
additional operator-owned R2 driver retains the normal write-only credential
flow.

## Implementation record

The V2 complete-object driver, local reference driver, recovery journal,
Merkle formats, VFS identities, optimistic publication, catalog checkpoints
and deltas, high-level filesystem API, R2 and Aliyun adapters, and server-owned
lifecycle protocol are implemented. After Rust parity and migration tests
passed, the legacy Go archive and command surface was removed. Future drivers
must enter through the same Rust contract and acceptance suite.
