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
read lease. Plans run concurrently under the configured file bound, payload
bytes bypass the Worker, and completion is idempotent. A single HTTP batch
would not remove the per-version location, inherited ACL, credential freshness,
lease, and audit decisions. It would enlarge the secret response and failure
domain while saving only multiplexed request framing.

Carrack therefore keeps the simple single-version authority protocol until
measurements show control-plane framing, rather than provider payload or the
required per-version decisions, is material. A future batch is acceptable only
if it preserves an independent result per version, caps request count and
encoded response bytes, reuses the same authorization function, creates leases
atomically per successful item, and retains the current endpoint as fallback.

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

Two explicit release-only client acceptances make the local scaling costs
repeatable without adding a benchmark framework to the product dependency
graph:

```console
nix develop -c cargo test -p carrack-client \
  sync::tests::indexed_state_accepts_one_hundred_thousand_records_without_linear_lookup \
  --release -- --ignored --exact --nocapture
nix develop -c cargo test -p carrack-client \
  sync::tests::warm_sync_rehashes_ten_thousand_files_without_provider_payload \
  --release -- --ignored --exact --nocapture
```

The first acceptance reports disk-spool, SQLite build, indexed lookup, and
database-size costs for 100,000 records. The second reports the mandatory
complete local-Merkle pass over 10,000 unchanged files and asserts that every
decision is local reuse. These are machine-local acceptance measurements, not
production throughput claims; provider and control-plane latency require a
separately identified environment and must report the full measurement fields
above.
