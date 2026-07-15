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

Payload bytes move directly between a client and a storage driver. The Worker
never relays a file body. It may contact hosted drivers for credential renewal,
exact identity checks, multipart abort, and fenced physical deletion.

## Logical and physical model

A directory is simultaneously a named collection, an authorization subtree,
an encryption boundary, a quota boundary, and a placement-policy boundary.
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
root before use. Missing, oversized, incompatible, multi-hop, or ACL-sensitive
cases safely fall back to a complete checkpoint or bounded page traversal.

The private local catalog stores metadata and recovery journals, never
credentials or directory keys. Independent files run concurrently. Each file
uses bounded multipart or range pipelines and persists durable receipts so a
restart transfers only missing or invalid units.

## Drivers

All product drivers are compiled Rust adapters behind one complete-object
contract. A descriptor declares upload, exact-range, multipart, concurrency,
checksum, identity, Stat, abort, Delete, proxy, and size-limit capabilities.
Unsupported capabilities produce a warning and a correctness-preserving
fallback; they never weaken verification.

The implemented adapters are local filesystem, Aliyun Drive Open, and
Cloudflare R2. The environment-owned `r2-default` is provisioned with the
environment and uses bucket-scoped credentials; operator-owned R2 identities
use the same contract and write-only credential workflow.

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

The operator credential is separate from VFS data authority. It opens a
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

- [VFS V2](vfs-v2.md)
- [Merkle format](vfs-merkle-v1.md)
- [Put protocol](vfs-put-v1.md)
- [catalog protocol](vfs-catalog-v1.md)
- [authorization](vfs-authorization-v1.md)
- [management API](vfs-management-v1.md)
- [management plane](management-plane-v1.md)
- [Cloudflare operations](cloudflare.md)
