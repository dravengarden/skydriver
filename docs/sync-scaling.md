# Synchronization scaling and correctness budget

## Supported shape

Carrack synchronizes complete files. It is designed for thousands to tens of
thousands of medium or large objects and remains correct for much larger
namespaces. Callers such as Seaway own dataset partitioning and should not use
Carrack as a small-object compaction or query engine.

The planner is linear in reachable entries. File and new-state plans use
private disk spools. Previous state uses a token/source-scoped SQLite primary
key rather than an in-memory table, plus an immutable-version index for
namespace rename reuse. A directory up to 20,000 entries may use a whole-node
memory/cache representation; wider revision-pinned directories are verified
and planned through a streaming spool. The portable directory Merkle
accumulator retains only the prior bounded name and logarithmically many
subtree hashes. The breadth-first pending-directory frontier is also advanced
through private generation spools, so a wide level does not become an
unbounded in-memory queue.

Checkpoint limits of 5,000 directories, 20,000 entries, and 32 MiB are
acceleration limits. Exceeding them falls back to revision-pinned pages and is
not a filesystem capacity failure.

## Warm local verification

An unchanged catalog version transfers no provider payload, but Carrack reads
the local file to recompute its exact plaintext root. Size, mtime, inode, and a
user-writable content-addressed hardlink are insufficient correctness proofs.

For a namespace rename, a matching immutable version may be copied from its
old local path instead of downloaded. Carrack verifies the old path, copies it
without creating a shared inode, then verifies the complete staging file again
before atomic publication. Any lookup, copy, or proof failure retains the
provider download path, so this acceleration cannot publish unverified bytes.

Verified plaintext publication is bound to the already-open staging file, not
to a pathname looked up again after verification. Native Unix builds link that
descriptor through the operating system's fd namespace into a random sibling
and then use a directory-fd-relative atomic rename; ordinary `get` links the
same descriptor directly with no replacement. A missing fd-link primitive
fails closed. A concurrent staging-path substitution therefore cannot change
the inode selected for publication.

Warm-file hashing and rename staging run through the same configured bounded
file concurrency as provider downloads, but in a separate phase so the two
budgets do not multiply. Blocking workers may return only RAII-owned private
staging files; the active coordinator performs final rename. Cancellation drops
and removes returned staging, and no worker can publish after the sync future
has gone away.

Content-addressed local catalog envelope, canonical JSON, entry-union, and
Merkle verification also runs in the bounded directory worker pool rather than
serially blocking the async runtime. A worker may discard only an invalid
token-scoped cache artifact; it never publishes a destination file. A cache
miss, corrupt artifact, or unavailable acceleration still follows the
authenticated revision-pinned network path.

An optional future fs-verity backend may skip that read only when it can bind a
previously recorded measurement to a kernel-enforced immutable inode. Missing
support, a measurement mismatch, unsupported filesystems, or any adapter error
must fall back to the ordinary Carrack Merkle pass. The current implementation
does not trust the available third-party ioctl wrapper because it documents
architecture-dependent constants as unverified; correctness takes precedence
over this optimization.

## Control-plane request model

Changed files independently request one immutable download plan and create one
read lease. Plans run concurrently under the configured file bound and payload
bytes bypass the Worker. Planning and provider transfer are separate bounded
pipeline stages: while at most `maximum_concurrency` complete files perform
provider I/O, the next bounded window of plans can be authenticated and queued.
The queue and planner each retain at most `maximum_concurrency` items, every
plan response is capped at 256 KiB, and abandoned directory keys and credential
grants are zeroized. Producer cancellation cannot publish a local file; an
already-created unused lease simply follows its server-owned expiry path.

Successful lease completions are written to an
owner-private bounded record spool so they do not occupy a payload concurrency
slot, then released in batches of at most 64. A batch is one authenticated HTTP
request, one D1 identity query, and one atomic D1 update batch; malformed or
partial responses fall back to the original idempotent per-lease endpoint, and
any remaining failure safely relies on lease expiry. Completion metadata is
never an input to file verification or publication.

Every private sync spool record carries an ordinal-bound HMAC under an
in-memory per-spool random key and is authenticated before deserialization or
use. Exhaustion additionally verifies the expected record count, order, and
complete spool SHA-256. Mutation, reordering, and record-boundary truncation
therefore fail closed; no spool is durable or irreplaceable state.

A single download-plan HTTP batch would not remove the per-version location,
inherited ACL, credential freshness, lease, and audit decisions. It would
enlarge the secret response and failure domain while saving only multiplexed
request framing.

Carrack therefore keeps the simple single-version authority protocol until
measurements show control-plane framing, rather than provider payload or the
required per-version decisions, is material. A future batch is acceptable only
if it preserves an independent result per version, caps request count and
encoded response bytes, reuses the same authorization function, creates leases
atomically per successful item, and retains the current endpoint as fallback.

Catalog-head notifications use a separate optional hibernating WebSocket. A
sync opens it only when changed files require provider payload. Every event is
freshly reauthorized by the server and can only trigger an early root-fence
check; it cannot authorize or publish a file. A missing endpoint, disconnect,
malformed event, or Durable Object failure returns immediately to the ordinary
HTTP catalog path and mandatory final fence. This can avoid finishing a large
download for a namespace that already changed without adding a correctness
dependency or routing payload bytes through Cloudflare.

The native catalog cache stores only VFS metadata and Merkle directory nodes,
never provider payload or irreplaceable state. Each record is authenticated and
encrypted with a cache-only key derived from the exact VFS token; its logical
content address is authenticated as associated data. Clients sharing the same
owner-private state directory and token may therefore reuse immutable nodes,
while another token or a copied, stale, or modified record fails authentication
and is discarded. Cache schema upgrades deliberately fail closed into normal
checkpoint or paginated hydration. Head comparison and publication are
serialized across processes so an older client cannot overwrite a newer delta
base. Deleting the complete cache remains a supported recovery operation.
After a verified head publication, maintenance scans exactly one of 256
content-address shards and deletes nodes outside that head's complete verified
closure. The encrypted shard cursor advances only as a disposable hint; a
missing or corrupt cursor restarts at shard zero. Publication and maintenance
share the cross-process head lock, and any cleanup failure is ignored, so GC
cannot reject a sync or make cache data authoritative.

## Acceptance matrix

- Normal CI authenticates 100,000 ordered directory entries while asserting
  logarithmic accumulator state.
- An explicit release-mode test authenticates the protocol maximum of one
  million entries.
- Client tests cover private unique spools, corrupt indexed-state fallback,
  v1-to-v2 migration, immutable-version rename reuse, atomic state replacement,
  destination overlap, final live-root fencing, and checkpoint/page identity.
- Worker protocol tests cover concurrent namespace mutation, ACL and token
  boundaries, catalog materialization, put publication, and environment
  isolation against local D1.

Performance measurements must report namespace shape, changed-file count,
payload size, cache posture, control-plane calls, provider concurrency, local
bytes hashed, peak resident memory, spool bytes, and elapsed time. A faster
result is acceptable only when all roots and final fences are identical.

Five explicit release-only acceptances make the local scaling costs repeatable
without adding a benchmark framework to the product dependency graph:

```console
nix develop -c just performance-acceptance
```

The first acceptance reports disk-spool, SQLite build, indexed lookup, and
database-size costs for 100,000 records. The second reports the mandatory
complete local-Merkle pass over 10,000 unchanged files and asserts that every
decision is local reuse. The third streams 100,000 entries through the actual
page JSON, fence, Merkle, and private-spool primitives. The fourth measures
1,000 bearer-carrying download-plan requests for distinct paths referencing
one immutable version against a loopback mock. The fifth proves that a one-million-entry
directory uses logarithmic Merkle accumulator state. These are machine-local
acceptance measurements, not production throughput claims; provider and
control-plane latency require a separately identified environment and must
report the full measurement fields above. Wall-clock values are observations,
not pass/fail thresholds, so host load cannot turn a correct build into a
flaky failure.

## Recorded local acceptance observations

These observations are append-only reference data, not product limits or
performance guarantees. They were produced on `hawk` on 2026-07-17 from exact
Git revision `a4344ac` with `nix develop -c just performance-acceptance` in the
release profile. Each test's internal timer excludes Rust compilation. The
temporary files and SQLite database were on hawk's ordinary local temporary
filesystem; there was no control-plane or provider traffic.

| Acceptance | Shape | Measured result |
|---|---|---|
| Indexed sync state | 100,000 records | record spool 26 ms; SQLite publication 183 ms; 100,000 primary-key lookups 353 ms; database 18,763,776 B |
| Mandatory warm verification | 10,000 files of 4,096 B; 1,024 B Merkle blocks | 40,960,000 local bytes rehashed in 44 ms; provider bytes 0 |
| Streaming directory Merkle | 1,000,000 ordered directory entries | 287 ms; peak retained subtree digests 19 |

The indexed-state result is linear construction plus indexed lookup, not an
all-pairs search. The warm result deliberately excludes file creation and
proves that unchanged authenticated files still incur the required complete
local read while transferring no provider payload. Its tiny synthetic files
are useful for fixed per-file overhead, not for predicting large-file disk
throughput. The million-entry result measures the portable Merkle accumulator,
not JSON decoding, D1 reads, paginated HTTP, or catalog hydration; it proves
the logarithmic hash-state bound but does not make a one-million-entry flat
directory cheap to transfer.

On this run, none of these local primitives supports weakening correctness for
speed. The next evidence needed before implementing a content-addressed page
tree is a real or hermetic wide-directory hydration measurement that separates
canonical JSON bytes, page count, control-plane latency, local cache hits, and
Merkle time. Likewise, download-plan batching needs a changed-small-file run
showing that authenticated plan latency, rather than provider I/O, dominates.

### 2026-07-17 wide-directory follow-up

The complete four-test acceptance was repeated on `hawk` from exact Git
revision `c496440`. This is a separate observation; it does not replace the
earlier `a4344ac` measurements.

| Acceptance | Shape | Measured result |
|---|---|---|
| Indexed sync state | 100,000 records | record spool 27 ms; SQLite publication 187 ms; 100,000 primary-key lookups 352 ms; database 18,763,776 B |
| Mandatory warm verification | 10,000 files of 4,096 B; 1,024 B Merkle blocks | 40,960,000 local bytes rehashed in 44 ms; provider bytes 0 |
| Wide-directory hydration | 100,000 file entries in 100 pages | wire JSON 38,244,379 B; private spool 34,800,000 B; JSON encode/decode 42 ms; fence, Merkle, and spool append 117 ms; complete spool decode 64 ms; total 264 ms; whole-node cache not retained |
| Streaming directory Merkle | 1,000,000 ordered directory entries | 283 ms; peak retained subtree digests 19 |

The wide-directory acceptance constructs deterministic revision-consistent
pages locally, so its `wire JSON` value is the uncompressed HTTP-body shape but
its elapsed time excludes network, Worker execution, and D1. It follows the
same 1,000-entry page size and 20,000-entry whole-node retention bound as the
client. The result shows that local parsing, verification, and spooling are
small relative to a potential 38.2 MB metadata transfer, but it does not prove
that a page tree is worthwhile for normal directory shapes.

A content-addressed page tree is therefore justified only for repeatedly
changing directories above the whole-node cache bound, where subsequent syncs
would otherwise fetch most or all of these pages. It must authenticate an
exact page closure beneath the existing directory `data_root`, preserve the
current revision-pinned page fallback, and never make a cached page an
authorization source. Ordinary nested directories already reuse immutable
subtrees and should not pay this additional protocol or D1 complexity.

### 2026-07-17 changed-small-file planning follow-up

The five-test acceptance was run on `hawk` from a working tree based on Git
revision `04639ec` with only the new measurement and this documentation added.
The benchmark exercises the real client response limits, identity checks,
bounded plan producer, bearer header, and HTTP client against a loopback mock.
The mock does not perform server-side bearer authorization. It deliberately
excludes Cloudflare, D1, provider payload, lease completion, and filesystem
publication.

| Acceptance | Shape | Measured result |
|---|---|---|
| Indexed sync state | 100,000 records | record spool 50 ms; SQLite publication 226 ms; 100,000 primary-key lookups 360 ms; database 18,763,776 B |
| Mandatory warm verification | 10,000 files of 4,096 B; 1,024 B Merkle blocks | 40,960,000 local bytes rehashed in 53 ms; provider bytes 0 |
| Wide-directory hydration | 100,000 file entries in 100 pages | wire JSON 38,244,379 B; private spool 38,000,000 B; JSON encode/decode 41 ms; fence, Merkle, and spool append 151 ms; complete spool decode 116 ms; total 349 ms; whole-node cache not retained |
| Changed-path planning | 1,000 distinct paths referencing one immutable zero-byte version; concurrency 16 | 1,000 bearer HTTP requests; 1,186 B response JSON per request; 1,186,000 B total; 21.0 ms elapsed |
| Streaming directory Merkle | 1,000,000 ordered directory entries | 286 ms; peak retained subtree digests 19 |

The changed-path result is a client fixed-cost lower bound, not an estimate of
remote sync latency or a realistic unique-version workload. It shows that plan
decoding and identity validation do not dominate on this host, but it cannot
measure network RTT, Worker authorization, D1 lease creation, provider
throttling, or per-version database locality. Therefore it does not justify a
download-plan batch endpoint. A production-like dev measurement with distinct
versions must still separate those costs before adding protocol complexity;
until then the current per-version authority and bounded prefetch remain the
simpler correctness boundary.
