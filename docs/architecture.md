# Carrack architecture

## Status

Carrack is a complete-object virtual filesystem. This document is the compact
architecture map; [requirements.md](requirements.md) is normative and
[vfs-v2.md](vfs-v2.md) records the detailed implemented protocol.

The former archive architecture is gone. Carrack does not split, pack, bundle,
merge, compact, or stripe user files. Multipart parts, encryption frames,
verification blocks, and HTTP ranges are private transfer units only.

## Product boundary

Carrack has two product components:

1. A Rust control plane on Cloudflare Workers, D1, and R2, with a React
   operator UI.
2. A canonical Rust client core used by the filesystem CLI, management CLI,
   applications, and WASM acceptance tests.

The CLI binaries are SDK consumers, not additional components. External
sources remain caller-owned: callers give Carrack bytes, streams, or local
files and receive bytes or local files.

### Correctness-kernel boundary

`carrack-sdk-core` is the small, portable correctness kernel used by both the
native client and Worker WASM. Its modules are deliberately one-directional:

- `canonical` parses context-free canonical wire values;
- `integrity` owns file/directory Merkle and block-manifest identity;
- `crypto` owns version-scoped key derivation and authenticated frames;
- `catalog` verifies complete checkpoint/delta closures using `integrity`;
- `acceptance` composes public APIs to prove native/WASM parity and owns no
  protocol rule.

The kernel performs no I/O and knows no provider, database, HTTP route, CLI,
or UI. `carrack-client` owns local/provider I/O, recovery, pipelines, and
publication. The Worker owns authorization and D1/R2 transaction orchestration.
Both convert boundary data into kernel value objects and accept its result;
neither reimplements the algorithm. CLI and UI are consumers whose local
checks improve UX but never create authority or establish correctness.

This boundary is intentionally stable: ordinary driver, management, CLI, and
UI work should not change it. Normative docs, module-local negative and golden
tests, a WASM build, and architecture checks make semantic changes explicit.

Payload bytes move directly between a client and a storage driver. The Worker
never relays a file body. It may contact hosted drivers for credential renewal,
exact identity checks, multipart abort, and fenced physical deletion.

Transfer observability is outside the correctness kernel. After a verified
completion, the client may attach one bounded duration/retry observation to its
normal control-plane checkpoint. The Worker asynchronously and
deterministically samples it into hourly and daily aggregates that retain the
driver, token, directory, and direction dimensions together. The management
SDK, CLI, and UI share a closed, bounded analytics query contract. Missing or
dropped telemetry only reduces diagnostic coverage and never changes VFS state.
Download telemetry v2 partitions client wall time into plan, local queue,
provider I/O, and post-provider verification/publication intervals. Legacy v1
observations remain accepted, but a separate weighted coverage counter keeps
them out of phase averages. Phase columns reuse the same sampled aggregate row
and indexes; collection adds no request, raw-event row, or correctness edge.

## Logical and physical model

A directory is simultaneously a named collection, an authorization subtree,
an encryption boundary, a quota boundary, and an effective-driver mount boundary.
Its stable UUIDv7 identity is independent of its path.

A file has a stable UUIDv7 identity. Every content change creates an immutable
UUIDv7 version. One version is stored as one complete provider object at each
location, in the same byte order. Replication creates another complete object;
it never divides a file between drivers.

A location contains an opaque random provider key, complete encoded length and
SHA-256, strong provider-native identity where available, driver identity and
revision, and lifecycle state. Provider keys reveal no virtual path, filename,
user, media type, or business meaning.

Directories contain canonical ordered entries. A file entry commits to its
current immutable version and content root; a directory entry commits to the
child data root. The root directory therefore authenticates the entire visible
tree.

## Integrity and encryption

Plaintext file identity is a fixed-block SHA-256 Merkle root. Downloads verify
every received block, complete encoded SHA-256, authenticated-decryption
frames, plaintext size, and final plaintext root before publication.

Encryption is enabled by default. Every directory owns a sealed key epoch.
HKDF derives a distinct AES-256-GCM file-version key from that epoch and the
immutable version identity. Frame nonces are deterministic only inside this
unique version domain. D1 never stores plaintext directory keys or file keys.

The plaintext root remains stable across storage drivers. The encoded identity
also remains stable for replicas of one version. A new version, encryption
epoch, or suite creates a new immutable encoded object rather than rewriting an
existing location.

## Filesystem protocols

A Put follows four durable phases:

1. Hash and, when enabled, encode the complete source locally.
2. Prepare an idempotent intent against expected namespace and policy
   revisions; acquire short-lived key and driver grants.
3. Transfer directly to one opaque provider object, resume missing units, and
   verify the complete provider identity.
4. Atomically publish the immutable version, location, namespace entry,
   ancestor Merkle roots, receipt, and catalog mutation with optimistic CAS.

A Get resolves one immutable version, acquires a durable read lease and
short-lived grants, downloads verified ranges into private staging, validates
the complete file, atomically publishes the local destination, and releases
the lease.

Remove and overwrite are logical metadata mutations. Rename and move update
namespace metadata and ancestor roots; they do not copy payload bytes. Physical
deletion is delayed and server-owned.

## Catalog and pipeline

The control plane materializes immutable, content-addressed catalog
checkpoints. A full-root token may stream a complete checkpoint; a narrow token
receives an exact authorized subtree or falls back to revision-pinned pages.

When the client holds the immediately preceding authenticated full checkpoint,
the server may return a hash-linked single-transition delta containing only
new directory nodes. The client reconstructs and verifies the complete target
root before use, durably publishes only the new content-addressed nodes, and
publishes the new local head last. Missing, oversized, incompatible, multi-hop,
or ACL-sensitive cases safely fall back to a complete checkpoint or bounded
page traversal.

The private local catalog stores metadata and recovery journals, never
credentials or directory keys. Independent files run concurrently. Each file
uses bounded multipart or range pipelines and persists durable receipts so a
restart transfers only missing or invalid units.

The token/source-scoped local state also indexes immutable version identities.
When a namespace rename moves an unchanged version, sync may copy the already
verified local plaintext into a private staging file and verify the complete
Merkle root again before atomic publication. Missing, mutable, unreadable, or
unverifiable candidates fall back to the normal provider download.

## Drivers

All product drivers are compiled Rust adapters behind one complete-object
contract. A descriptor declares upload, exact-range, multipart, concurrency,
checksum, identity, Stat, abort, Delete, proxy, and size-limit capabilities.
Unsupported capabilities produce a warning and a correctness-preserving
fallback; they never weaken verification.

`carrack-driver-contract` is the single I/O-free source for compiled driver
kinds and their data-path, credential, grant, inventory, and lifecycle posture.
Both the native SDK and Worker depend on it; the portable correctness kernel
does not. This makes a new kind an explicit exhaustive change on both sides
without mixing provider behavior into cryptographic or Merkle modules.

The native SDK has one closed, versioned registry boundary. Upload and download
orchestration submit the same immutable request types to that boundary and do
not know provider names, configuration fields, credential shapes, or transport
APIs. Each adapter owns those details and returns only verified complete-object
evidence. Adding a provider therefore extends the adapter and registry modules;
it does not modify the portable correctness kernel or publication orchestration.
Server data can select a compiled version but can never supply executable code.
The detailed extension and conformance contract is in
[driver-spi.md](driver-spi.md).

The implemented adapters are local filesystem, Aliyun Drive Open, Cloudflare
R2, and official AWS S3. The environment-owned `r2-default` is provisioned with the
environment and uses bucket-scoped credentials; operator-owned R2 identities
use the same contract and write-only credential workflow.
Credential material may rotate without changing this logical storage identity:
the Worker proves provider account continuity against the existing encrypted
credential before commit. A different account or bucket is a new driver and
requires explicit verified migration, so existing locations cannot be silently
rebound by pasting another valid credential.

Local filesystem lifecycle work is retained as server-blocked because a Worker
cannot safely reach an agent path. Hosted drivers eligible for automatic
deletion must provide stable identity, exact Stat, and idempotent Delete.

## Concurrency and lifecycle

Carrack uses optimistic revisions, immutable identifiers, idempotency keys, and
short transactions. Network I/O never holds a D1 transaction or distributed
pessimistic lock. A stale revision fails before publication and can be safely
replanned.

Read leases protect in-flight direct downloads. Server Cron alone performs
bounded metadata hygiene, reachability marking, tombstone grace, and fenced
physical cleanup. Immediately before provider I/O it rechecks reachability,
active leases, immutable locator, driver revision, provider identity, grace,
claim lease, and fencing token. Ambiguity retains data.

Current roots, sealed retained snapshots, active snapshot sessions, and
unexpired upload intents protect locations. Missing or inconsistent
reachability material fails closed for the affected filesystem.

## Authorization and management

VFS access uses attenuated bearer capabilities bound to a principal, subtree,
fixed actions, optional driver scope, expiry, and revocation ancestry. The
server also reevaluates inherited allow-only ACLs on every request. Named roles
are UI presets expanded to fixed actions, not a general policy language.

The non-secret operator account and its credential are separate from VFS data
authority. Together they open a
short-lived configuration mutation session and never grants plaintext access.
The UI is read-only until reauthentication. `carrackctl` exposes the same
validated configuration surface for humans and AI agents, with local checks,
server normalization, expected revisions, idempotency, and durable receipts.

## Environment and language boundary

Development and production have distinct Workers, D1 databases, R2 buckets,
secrets, credentials, routes, and bootstrap authorities. No token or provider
credential crosses that boundary even when both environments use one external
provider account.

Rust is the only product implementation. The retained Go packages under
`driver/`, `transfer/journal/`, and `vfs/` are narrow conformance oracles.
Architecture tests forbid a Go SDK or CLI and the removed archive model.

## Detailed contracts

- [portable correctness core](sdk-core.md)
- [synchronization scaling](sync-scaling.md)
- [VFS V2](vfs-v2.md)
- [Merkle format](vfs-merkle-v1.md)
- [Put protocol](vfs-put-v1.md)
- [catalog protocol](vfs-catalog-v1.md)
- [authorization](vfs-authorization-v1.md)
- [management API](vfs-management-v1.md)
- [management plane](management-plane-v1.md)
- [Cloudflare operations](cloudflare.md)
