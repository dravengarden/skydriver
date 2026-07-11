# Carrack architecture

## Product boundary

Carrack is business-neutral infrastructure for locating, encrypting, moving,
and reconstructing immutable data. It contains exactly two product components:

1. The **control plane**, deployed on Cloudflare, owns metadata, authorization,
   key epochs, operation state, leases, rate budgets, and garbage-collection
   decisions.
2. The **client SDK**, written in Go, owns every payload byte. CLI programs,
   Lightsail workers, and local machines embed the same SDK.

The control plane never proxies payload bytes. It may deliver metadata,
short-lived grants, encrypted credentials, and client-bound data keys.
Consumer projects may use Carrack for synchronization, but their source
adapters, catalogs, schedules, parsers, and domain semantics remain separate.

## Correctness invariants

These are protocol requirements rather than implementation preferences:

1. A published object version and its manifest are immutable.
2. A location becomes readable only after its complete ciphertext hash and
   expected length have been verified.
3. A source location is never deleted until a destination is verified,
   published, and protected by the required replica policy.
4. A client may retry every mutation. Idempotency keys make retries safe.
5. Expired clients cannot commit through a stale lease. Every mutating lease
   carries a monotonically increasing fencing token checked by every write.
6. Garbage collection never deletes a location reachable from a published
   manifest, protected by an unexpired read lease, or required by an unfinished
   operation.
7. D1 never stores plaintext data-encryption keys, provider credentials, client
   tokens, or passwords.
8. Driver and cryptographic algorithm names are versioned identifiers from a
   compiled allowlist. The control plane cannot make a client execute arbitrary
   code by returning a new name.
9. Restores verify authenticated encryption, ciphertext hashes, plaintext
   hashes, lengths, ordering, and final manifest identity before publishing a
   local result.
10. A failure may leave an extra replica or an orphaned staging object; it must
    never cause the last verified replica to be deleted.
11. Configured sizes are targets, not storage slots. No frame, extent, pack,
    bundle, transfer window, or provider object is padded to its target size.

## Logical and physical model

Carrack separates logical data from physical placement:

- A **namespace** is an authorization, key, retention, and replica-policy
  boundary.
- An **object** is a stable logical name within a namespace.
- An **object version** is an immutable manifest generation.
- A **chunk** is an ordered plaintext extent referenced by an object version.
- A **pack** is an immutable encrypted physical blob containing one or more
  chunks. Pack entries carry byte offsets so a range-capable driver can read one
  chunk without downloading the whole pack.
- A **bundle** is a canonical gapless plaintext stream for many small files.
  Its local index maps canonical paths to exact byte ranges and hashes without
  creating one D1 row or provider object per file.
- A **location** records one complete pack replica on one driver instance.
- An **operation** is an idempotent import, copy, move, restore, compact,
  verify, reconcile, or GC state machine.

The default layout uses 8 MiB authenticated-encryption frames, 64 MiB chunks,
and an 8 GiB target logical pack. These are policy defaults. A driver
may choose a smaller physical pack target when its API, object-size limits, or
failure characteristics make that safer.

Every target has an exact short tail. Files inside a bundle are concatenated
without alignment, and a file may cross frame, extent, or pack boundaries. A
20.3 GiB stream under an 8 GiB pack target therefore produces exact plaintext
pack lengths of 8 GiB, 8 GiB, and 4.3 GiB; it never reserves three 8 GiB slots.
The canonical wire format is specified in
[bundle-format.md](bundle-format.md).

Chunk size, provider object size, and multipart part size are independent. A
driver may stream multiple 64 MiB Carrack chunks into one provider object and
may divide that object into smaller provider-specific upload parts. The control
plane assigns work in batches; it is never on the synchronous path between two
chunks. SDK-local pipelining and bounded concurrency determine throughput.

The importer groups only consecutive complete extents. It uses the driver's
preferred provider-object size, capped by the advertised maximum, and defaults
to a 1 GiB target when no preference is available. A group closes before adding
an extent that would exceed its target; an exact short tail is uploaded without
padding. If one immutable extent exceeds a hard driver maximum, the plan is
rejected instead of silently changing crypto boundaries. Every group is staged,
hashed, uploaded once, and independently read back. Its locations share one
storage key and record disjoint exact offsets and lengths.

The download scheduler performs the inverse placement optimization without
joining logical extents. Consecutive inputs whose preferred locations have the
same driver and storage key and exactly adjacent offsets may share one
`OpenRange` call up to a configured maximum range size. The range is read into
separately owned extent buffers, and every extent SHA-256 is verified before
any buffer reaches its consumer. A range, length, close, or hash failure causes
the whole window to retry through the ordinary per-extent ordered replica
path. Download concurrency and maximum range size jointly bound memory and may
be tuned without changing manifests or cryptography.

### Leaf merging and compaction

Leaf merging never mutates an existing pack. A client builds a new pack,
uploads and verifies it, then asks the control plane to publish a new location
generation. Existing readers stay pinned to the previous immutable generation.
Old locations enter GC only after publication, active-read expiry, and the GC
grace period.

Concurrent compactors may produce duplicate valid packs. A conditional publish
selects one winner; losing packs are safe staging orphans and are reclaimed
later. Correctness does not depend on preventing duplicate work.

## Driver model

The SDK receives driver parameters explicitly. It does not contain a fixed
`aliyundrive` switch.

```text
DriverRef
  id             control-plane driver-instance id
  kind           versioned kind, for example aliyundrive-open/v1
  config         kind-specific validated configuration
  credential_ref optional encrypted credential reference
  rate_policy    control-plane policy plus driver-safe defaults
  proxy_policy   direct, external proxy, or managed sing-box
```

The Go SDK owns a registry mapping `kind` to a typed factory. Adding R2 or
Google Drive registers another factory without changing transfer state
machines. Wire configuration is opaque JSON at the control-plane boundary but
is decoded into a strict driver-owned Go struct before use.

Drivers advertise capabilities rather than forcing the SDK to guess:

- stat and immutable version identity;
- exact range reads;
- streaming or multipart writes;
- list/inventory and delete;
- server-side copy;
- resumable upload;
- maximum object and part sizes;
- safe concurrency and per-operation request limits;
- checksum algorithms exposed by the provider.

The initial registry contains only `aliyundrive-open/v1`. Public HTTP/S3, R2,
Google Drive, and local filesystem drivers are added behind the same contract.

Driver implementations follow a value-based split:

- S3-compatible storage, R2, public HTTP, and local filesystems use native Go
  implementations and mature Go SDKs. They do not route through OpenList.
- Consumer cloud drives may reuse selected OpenList driver and OAuth work when
  that materially reduces provider-specific maintenance.
- OpenList-derived code is adapted behind Carrack's typed factory contract in
  the SDK process. Carrack does not require or communicate through a persistent
  OpenList HTTP/WebDAV server.

## Operation protocols

### Import

An import reads unencrypted source data, chunks and encrypts it, writes packs to
a destination driver, and commits a new immutable manifest:

```text
begin operation
  -> acquire write lease + fencing token
  -> resolve source version
  -> receive key grant
  -> stream, chunk, encrypt, hash, upload
  -> commit each verified staging location idempotently
  -> finalize immutable manifest
  -> compare-and-swap object current generation
  -> release lease
```

Manifest publication is last. A crash before publication leaves only staging
locations, never a partially readable object version.

The Worker can stage large manifest metadata through bounded D1 batches because
all staging rows remain unreachable. One final D1 batch verifies the current
incarnation and lease fence, marks the version published, compare-and-swaps the
object pointer, records both recovery copies, succeeds the operation, and
releases the lease. A crash before that batch is harmless; a retry adopts the
same rows. If a lease expires between batches, an exact uncommitted intent can
be rebound to the new live fence, while any changed identity is rejected.

Publication also has a recovery barrier. The client writes a portable,
immutable recovery sidecar to the destination driver, then submits the same
small metadata document to the Worker. The Worker validates its complete
pack/frame/extent/location structure and archives it under a recovery-hash key
in control-plane R2 before D1 publishes the object version. Payload extents
never pass through the Worker. If D1 later rolls back, inventory can adopt
manifests created after the restored point. If D1 is lost, root recovery
material, portable manifests, and ciphertext are sufficient to reconstruct the
data index.

### Copy

Copy preserves the source. A client reads from any healthy source location and
writes a destination location. The control plane records the destination only
after verification. Server-side copy is allowed only when a driver advertises
it and Carrack can still verify the resulting object identity.

### Move

Move is a saga, not a cross-provider transaction:

```text
planned -> copying -> verifying -> destination_published
        -> source_delete_pending -> deleting -> succeeded
```

After `destination_published`, failure leaves an extra replica. Source deletion
requires the same operation id, current fencing token, verified destination,
and satisfied replica policy. Deletion is idempotent. A missing source after a
verified destination is success; a missing destination is never success.

### Restore

A restore pins one manifest generation and creates a renewable read lease. The
SDK downloads only missing or invalid local chunks, decrypts into temporary
files, verifies plaintext, then atomically publishes the local output. Its
resume journal contains no key material and is safe to discard.

Each restore operation stores its immutable version and manifest identity in a
`restore_intents` row. Its operation-scoped read lease permits concurrent
readers of the same version while giving GC an exact
`lease -> operation -> restore intent -> version` protection path. Successful
completion rechecks the manifest and plaintext identities under the live read
fence, advances the operation through verification and commit states, and
releases the lease in one D1 batch.

The portable recovery manifest is metadata and may be returned by the control
plane, but only under that same live read fence. The Worker resolves the
operation's pinned intent to its durable R2 object, revalidates the complete
manifest and content identity, and never returns provider payload bytes.

The SDK coordinator renews the read lease independently of provider progress.
It always completes with the newest returned fence. If renewal fails, it
cancels the restore context so pending provider reads terminate and the local
staging file cannot be atomically published.

A terminal frame-authentication or final plaintext-integrity failure is
recorded under the current read fence using a stable, non-sensitive error code;
the operation becomes failed and the lease is released in one D1 batch.
Transient provider and cancellation failures remain resumable and simply let
their read lease expire rather than being mislabeled as permanent corruption.

Restore creates one `restore` operation component and one attempt per fencing
token. The SDK reports cumulative wire-read, useful-verified, active-time, and
replica-retry counters after each verified extent. Samples use the existing
sequence and monotonic-counter protocol, so duplicate responses and reordered
delivery cannot move progress backwards. Telemetry remains isolated from
restore correctness; an unreported final sample becomes an explicit client
warning rather than a false restore failure.

### Driver-to-driver transfer

The same copy or move state machine applies whether the source is encrypted or
plaintext. Encryption metadata in the source manifest determines whether the
SDK decrypts, rewraps, or re-encrypts. A location-only replication can copy
ciphertext unchanged and merely add another location.

## Concurrency model

### Reads

Published manifests and packs are immutable, so concurrent readers need no
exclusive lock. Each reader pins a manifest generation and obtains a renewable
read lease. Returning an older immutable generation from a stale replica is
safe; mutation and GC decisions always execute against the primary state.

### Mutations

Carrack uses optimistic compare-and-swap for metadata publication:

```sql
UPDATE objects
SET current_generation = ?1, revision = revision + 1
WHERE id = ?2 AND revision = ?3
RETURNING revision;
```

Zero returned rows means conflict; the client reloads state and either retries
or accepts that another equivalent operation won.

Long network operations never hold a database transaction or pessimistic lock.
They use renewable leases with short expirations and fencing tokens. Acquiring
an expired lease increments its token. Every heartbeat, staging commit,
finalize, move, and delete compares that token, so a paused old client cannot
resume and overwrite a newer owner.

Locations identify both an extent's immutable ciphertext hash and its physical
`(driver, storage key, offset, length)` range. Multiple locations may therefore
reference disjoint ranges in one provider pack object without coupling crypto
or restore logic to that provider's object layout.

D1 is the authoritative online coordination ledger. It is not the sole
recovery source for published data: portable manifests and root-seed recovery
material allow the index to be rebuilt. A per-namespace Durable Object may
reduce hot-key contention, but D1 conditional writes remain the live mutation
boundary; Durable Object eviction cannot weaken the protocol.

### Distributed rate coordination

Local driver limiters are insufficient when many SDK instances share one cloud
credential. The control plane uses a Durable Object per `(driver credential,
operation class)` to allocate small, expiring token batches. Each SDK shapes
requests locally within its grant and uses additive-increase/multiplicative-
decrease behavior for throughput:

- honor `Retry-After` and provider reset metadata;
- reduce concurrency on throttling, timeouts, and transient provider errors;
- increase slowly after sustained success;
- cap all tuning at driver-safe and control-plane policy limits;
- keep Aliyun Drive concurrency at one until canary measurements justify more.

This limits aggregate account traffic without putting payload bytes through the
Durable Object.

## Progress and throughput observability

The control plane exposes both **who is running** and **what each operation is
doing**. It models two levels:

- A **client instance** is one live SDK process, with version, capabilities,
  last heartbeat, lease state, current operations, and bounded operator labels.
- An **operation component** is one stage or transfer leg, such as source read,
  decrypt, chunk, encrypt, destination upload, verify, merge, restore, or
  delete. One operation can have components on several clients.

SDKs do not report an authoritative instantaneous speed. They report monotonic
counters with a sequence number, attempt id, lease id, and fencing token:

```text
observed_at
wire_bytes_read
wire_bytes_written
useful_bytes_verified
chunks_completed
chunks_total
retries
throttle_events
active_nanoseconds
```

V1 import operation creation also creates one deterministic transfer component.
Claiming the operation starts an attempt whose number is the current fencing
token. Progress ingestion atomically records per-minute counter deltas and the
new cumulative attempt, component, and operation totals. Exact duplicates are
idempotent, older sequences return the newer snapshot, and regressions or stale
fences are rejected. Later multi-leg schedulers can add components without
changing this attempt protocol.

The control plane accepts a sample only when its sequence is newer, its
counters do not go backwards within an attempt, and its fencing token still
owns the component. Retransmitted samples are idempotent. A resumed component
starts a new attempt, so a reset counter cannot corrupt the previous series.

Carrack distinguishes:

- **wire bytes**, which include retries and reveal bandwidth/cost;
- **useful verified bytes**, which advance only when a unique chunk is
  committed and determine logical progress;
- **active throughput**, bytes divided by actual transfer time;
- **wall-clock throughput**, bytes divided by elapsed time including stalls.

This prevents a retry from falsely increasing progress while still showing its
real network cost.

### Aggregation

Frequent raw heartbeats are too expensive and noisy for D1. A Durable Object
sharded by operation accepts samples every 5–10 seconds, validates ordering,
maintains live state, and emits one durable D1 bucket per component per minute.
The D1 write is an idempotent upsert keyed by `(component_id, attempt,
bucket_start)`.

Each minute bucket stores counter deltas, active duration, samples, retries,
throttles, and min/max timestamps. Query-time rollups calculate:

- current EWMA speed;
- 1, 5, and 15 minute averages;
- hourly and daily averages;
- current-attempt, operation-lifetime active, and wall-clock averages;
- progress and estimated completion time when the total is known.

Durable Object state is a cache and live fan-out point, not the historical
source of truth. Important counters are recoverable from D1 component state and
minute buckets after eviction.

### Retention and UI

Retention is resolution-aware:

- live samples: Durable Object memory/storage only;
- one-minute buckets: 30 days by default;
- hourly rollups: one year by default;
- lifetime operation totals and audit events: retained with operation metadata.

A scheduled rollup writes the coarser bucket before conditionally deleting the
finer buckets. GC of telemetry is independent from payload GC.

The UI initially polls a compact live snapshot. A hibernating Durable Object
WebSocket may later push updates without keeping compute active. Required views
are:

- client/component health: running, stalled, lease-expired, offline;
- operation progress and ETA;
- stage-by-stage current and average throughput;
- driver and credential rate-budget utilization;
- retry, throttle, verification failure, and error timelines;
- historical 1m/5m/15m/1h/day rate charts;
- wire-versus-useful byte efficiency.

Metric labels never contain object paths, tokens, keys, signed URLs, or driver
credentials. Label sets are bounded to prevent untrusted cardinality growth.
Workers Analytics Engine can become an optional high-volume analytics sink, but
its retention and query model do not replace D1 as Carrack's durable operation
ledger.

## Cryptography and key delivery

Carrack deliberately accepts a namespace-level security boundary in exchange
for a small, recoverable secret set and a control plane that never scales with
payload size:

1. A random 256-bit client token authenticates an SDK instance. D1 stores only
   its verifier, name, namespace permissions, status, and audit metadata.
2. Provider credentials remain authenticated encrypted envelopes because they
   cannot be deterministically derived.
3. One versioned 256-bit root seed lives in Cloudflare Secrets Store or a
   Worker secret and in offline recovery storage. It never enters D1.
4. The Worker derives one epoch key per authorized namespace operation. The
   client derives every pack key locally. D1 stores no data-encryption key or
   pack-key envelope.

The derivation tree is fixed and domain separated:

```text
epoch_key = HKDF-SHA-256(
  root_seed,
  salt = namespace_id || epoch_id,
  info = "carrack/epoch-key/v1"
)

pack_key = first 16 bytes of HKDF-SHA-256(
  epoch_key,
  salt = pack_id,
  info = "carrack/pack-key/v1"
)
```

An authenticated client receives the small epoch key once at operation start
over HTTPS after namespace, operation, lease, and fencing checks. The client
keeps it only in memory and may continue its current batch while the control
plane is temporarily unavailable. Possession of an epoch key permits deriving
every pack key in that epoch; this is an explicit V1 tradeoff for non-sensitive
archive data.

For restore, the grant request also pins the portable manifest digest, root
version, and key epoch. D1 proves that every pack in the immutable version uses
that same crypto context before the Worker reads the versioned root secret.
The audit event records only operation and public crypto identities; root and
epoch key bytes never enter D1 or logs.

The initial data suite is versioned and fixed:

```text
carrack-aes128gcm-hkdfsha256-v1
```

- AES-128-GCM uses Go's hardware-accelerated standard-library implementation
  on modern amd64 and arm64 clients.
- Each pack has an independently derived key, so its 96-bit frame nonce is the
  big-endian frame ordinal.
- AAD binds suite version, root version, namespace, epoch, pack, frame size,
  total plaintext size, frame ordinal, and frame plaintext length.
- Eight MiB frames authenticate independently and may be processed in parallel.
- Manifests record ciphertext and plaintext SHA-256 values and exact lengths.

Encryption and transfer are orthogonal packages. Transfer operates only on
opaque ciphertext extents and their SHA-256 identities; crypto never imports a
driver or provider type. Every replica of an extent is byte-identical even when
different provider objects contain it at different offsets. Source selection,
range scheduling, hedging, caching, proxies, and rate limiting therefore cannot
change or interpret crypto bytes.

Creating a new root version or crypto suite affects only new immutable packs.
Old root versions remain available for restore until their packs are explicitly
re-encrypted. Root seeds plus portable manifests and ciphertext are sufficient
for offline index reconstruction; D1 is not a cryptographic recovery dependency.

## Garbage collection and reconciliation

GC is mandatory but intentionally conservative. A scheduled Worker runs the
mark phase; clients with appropriate driver grants perform payload deletion.

### Mark

A location is a candidate only when it is unreachable from every published
manifest, not protected by an active lease or operation, not the last verified
replica required by policy, and older than the staging/retention threshold.
Marking writes `tombstoned_at`, `gc_epoch`, and a new revision. It does not
delete provider data.

### Grace period

Candidates remain readable during a configurable grace period. A late reader,
repair, or operator can cancel a tombstone by a conditional revision update.

### Sweep

After grace, the control plane emits idempotent delete tasks. An SDK rechecks
the candidate and fencing token, deletes through the driver, then records
`deleted`. Provider failure keeps the tombstone for retry. The index row is
retained as an audit record until metadata-retention expiry.

### Inventory reconciliation

Failed clients can upload a provider object before its staging record reaches
D1. Periodic, rate-limited inventory compares Carrack-owned provider prefixes
with indexed locations. Unknown objects enter a separate quarantine grace
period before deletion. Missing indexed objects become `missing` or `corrupt`
and trigger repair; reconciliation never silently edits manifests.

Cloudflare Cron Triggers schedule mark, expired-lease cleanup, and reconciliation
planning. D1 Time Travel is a control-plane recovery mechanism, not a substitute
for payload replicas.

## Disaster recovery and stale clients

The control plane carries a random incarnation identifier. Every lease,
operation attempt, fencing decision, and destructive task is bound to it. A D1
point-in-time restore occurs with mutations disabled and is followed by an
atomic incarnation change before any client can claim new work. This prevents
clients holding pre-restore leases from committing against rolled-back fencing
counters.

Recovery invalidates unfinished operations and GC epochs, verifies root-seed
canaries, scans the portable manifest archive and Carrack-owned provider
prefixes, rebuilds unindexed versions, and classifies unresolved locations.
Provider unavailability, missing data, corrupt data, unavailable key material,
unsupported suites, quarantined orphans, and exhausted recovery paths remain
distinct states. Only the last state is permanent data loss, and cleanup still
requires operator acknowledgement, tombstoning, grace, and a final fenced
recheck.

Physical deletion is preferably executed by explicitly authorized janitor
clients. Normal clients may request move or GC work, but a janitor revalidates
incarnation, fencing, reachability, read leases, and replica policy immediately
before each provider delete.

## Proxy transport

Proxying is a transport policy injected below drivers, not a property of an
object or location. All HTTP-capable drivers receive an SDK-owned transport.

Supported policy shapes are:

- `direct`;
- external HTTP or SOCKS5 endpoint;
- managed sing-box, where the SDK starts a pinned sing-box binary with an
  ephemeral local SOCKS endpoint from a validated outbound configuration such
  as VLESS.

Embedding sing-box internals directly would couple Carrack to an unstable and
large implementation surface. A managed subprocess keeps the boundary explicit
and lets all drivers share the same proxy. Proxy credentials stay in memory or
`0600` ephemeral files and never enter manifests or logs.

Host routing such as hawk's direct Aliyun Drive policy remains an Omega concern.
It is independent from Carrack unless an operator explicitly selects a Carrack
proxy policy.

## Cloudflare mapping

- Worker: authorization, API, immutable-index reads, CAS mutation endpoints,
  epoch-key grants, telemetry queries, and scheduled maintenance planning.
- D1: manifests, versions, chunks, packs, locations, operation state, leases,
  client/token verifiers, encrypted provider-credential envelopes, tombstones,
  telemetry buckets, rollups, and audit records.
- Durable Objects: distributed rate-budget coordination, live telemetry
  aggregation/fan-out, and optional hot-key admission control, sharded by stable
  identifiers.
- Secrets Store / Worker secrets: versioned root seeds and session-signing keys.
- Cron Triggers: expired-lease cleanup, GC mark, and reconciliation planning.

Cloudflare provides D1 Sessions for sequential consistency and Time Travel for
point-in-time control-plane recovery. Carrack still uses immutable generations,
conditional writes, and payload replicas as its application-level correctness
model.

## Implementation order

1. Add the driver registry and typed `aliyundrive-open/v1` factory.
2. Introduce new append-only D1 migrations for namespaces, immutable versions,
   packs, locations, operations, leases, clients, key epochs, components, and
   telemetry buckets.
3. Add client authentication, idempotency, lease, fencing, and snapshot APIs.
4. Implement framed encryption and import to Aliyun Drive.
5. Implement incremental restore and full plaintext verification on hawk.
6. Add copy, move, compaction, mark/grace/sweep GC, and inventory reconciliation.
7. Add distributed rate grants, live telemetry aggregation, and proxy transport.
8. Add R2 and further drivers without changing operation state machines.

The first production canary remains single-client and concurrency one. Scale is
enabled only after crash, retry, stale-lease, duplicate-commit, move, and GC
fault-injection tests pass.
