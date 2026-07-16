# Carrack VFS Local Catalog V1

## Status and purpose

V1 implements an incrementally synchronized, content-addressed local namespace
catalog. It lets a client prefetch and verify directory metadata before payload
planning, then skip every unchanged subtree on later synchronizations.

The namespace catalog contains directory identities, names, file and version
IDs, plaintext lengths, file roots, metadata roots, child-directory IDs, and
child-directory roots. The Rust sync state separately retains authenticated
file-version and verification-block identities plus completed local ranges.
Credentials, directory keys, and signed provider URLs are never persisted in
either cache. Catalog nodes and sync state are scoped beneath the non-secret
server-issued `token_id`; a narrower token can never consume metadata cached by
a broader token even when both commands share one state directory. A fresh
scoped transfer grant is still required before provider I/O, so "offline
planning" never means offline authorization.

## Why the catalog is a Merkle DAG

Every VFS directory already has a canonical `data_root`. A parent entry commits
to both a child directory ID and its `data_root`. Carrack therefore uses the
pair `(directory_id, data_root)` as one immutable local catalog-node key rather
than introducing a second directory hash.

An update changes the leaf directory root and every ancestor root, while
unchanged sibling roots remain identical. A client that observes one new root
downloads the changed ancestor path and reuses every cached sibling subtree.
No per-file control-plane call is required to discover the namespace.

The current whole-directory node is intentionally simple. Very large flat
directories are fetched through revision-pinned pages and assembled locally.
A future content-addressed page tree may reduce metadata transfer for one-entry
changes inside a huge flat directory without changing the directory root or
the public cache key.

## Synchronization protocol

The Rust `carrack sync` implementation performs these steps:

1. Read the first live page of the requested root directory with the current
   VFS bearer token.
2. Use the authenticated `data_root` and directory revision as the recursive
   synchronization fence.
3. Load the root node from the private local store when it already exists and
   passes envelope, canonical-JSON, entry-union, and Merkle-root validation.
4. On a cache miss, follow the opaque revision-pinned cursor, assemble the
   complete directory, recompute its canonical Merkle root, and durably publish
   the immutable node.
5. Schedule child directories through a bounded worker pool. Cached nodes are
   still traversed so an interrupted earlier synchronization cannot be mistaken
   for a complete recursive closure.
6. Re-read the live root and require the same filesystem ID, directory
   revision, and `data_root` observed at the start.

The final revalidation makes the result a coherent recursive snapshot. A
concurrent content mutation either changes an expected child root, invalidates
a page cursor, or changes the final root revision. Synchronization then fails;
the caller retries from the live root. Valid immutable nodes written before the
failure remain reusable.

ACL and placement revisions are deliberately not part of the content-node key.
They are re-evaluated online for each request and do not alter the directory
content root. Revocation or ACL removal during synchronization fails subsequent
authorization immediately.

## Local node format

One node uses schema `carrack.vfs.catalog-node.v1` and contains only fields
committed by the directory Merkle format:

```json
{
  "schema": "carrack.vfs.catalog-node.v1",
  "directory_id": "<32 lowercase hex>",
  "data_root": "<64 lowercase hex>",
  "entries": [
    {
      "name": "release.tar.zst",
      "kind": "file",
      "file_id": "<file-id>",
      "version_id": "<version-id>",
      "child_directory_id": null,
      "size_bytes": 1234,
      "data_root": "<file-root>",
      "metadata_root": "<metadata-root>"
    }
  ]
}
```

Mutable D1 row timestamps and revisions are excluded because the content root
does not authenticate them. Local planning must never infer content correctness
from an uncommitted convenience field.

The payload is wrapped by
`carrack.vfs.catalog-node-envelope.v1` with its exact SHA-256. Loading requires:

- a private regular file under the expected content-addressed path;
- strict JSON with no unknown fields or trailing value;
- byte-canonical re-encoding and matching envelope SHA-256;
- exact requested directory ID and data root;
- canonical entry ordering and a valid file/directory union; and
- a recomputed directory root equal to `data_root`.

The envelope detects local corruption. The Merkle root provides end-to-end
content authenticity because the root node is observed over the authenticated
control-plane request and every child root is committed by its verified parent.

## Local durability and secrecy

The store root contains one namespace per non-secret VFS token ID; token
bearers and their verifiers are never written. Every token namespace and node
shard must be a real directory with no group or other permissions. Node files
use mode `0600`; directories use `0700`. Publication writes and fsyncs a
private temporary file, creates the final name with an atomic no-replace hard
link, fsyncs the directory, and removes the temporary name. An existing exact
node is accepted. An existing malformed or different node is a hard error and
is never silently replaced.

The cache contains filenames and stable VFS identities, so it is sensitive
metadata. It never contains bearer tokens, provider credentials, directory
keys, or file payload bytes. Removing the cache affects performance only; the
next synchronization reconstructs it from authenticated metadata.

## SDK and CLI

The canonical CLI surface is:

```bash
export CARRACK_CONTROL_URL='https://dev.carrack.stormbird.xyz'
export CARRACK_VFS_TOKEN='<attenuated bearer>'

carrack sync /releases ./local-releases \
  --maximum-concurrency 4 \
  --maximum-file-concurrency 4
```

The client fetches and authenticates the complete recursive catalog before it
schedules payloads. It then runs changed files concurrently, uses bounded
ranged pipelines within each file, resumes only verified completed ranges, and
atomically publishes each fully verified local file. Untracked local files are
preserved. Success requires the pinned recursive closure and every requested
plaintext Merkle root to match.

## R2 materialization and outbox correctness

The server now implements the conservative second form of outbox processing:
it materializes only a filesystem's current mutation head as a complete
checkpoint. One bounded Cron pass claims the current head, reads every active
directory and entry, recomputes every directory Merkle root, proves that the
graph is a single tree reachable from the filesystem root, and rechecks the
same live root and revision after assembly.

A failed current-head materialization remains pending with a durable
`retry_at`. Retries use exponential backoff from one minute to roughly six
hours, and Activity exposes the attempt, error, and next deadline. A concurrent
newer head is a normal supersession rather than a provider failure, so it is
released without a retry schedule and later resolved by the collapse proof.

The canonical JSON checkpoint is written to `CARRACK_MANIFESTS` under its
SHA-256 with an R2 create-only condition. D1 records the planned artifact before
the R2 side effect, then publishes `vfs_catalog_heads` only after the immutable
object exists with the exact bytes, SHA-256, R2 version, and size. A concurrent
mutation makes the final D1 CAS fail. The staged object is then marked orphaned
and deleted after a grace period without requiring a bucket-wide listing.

Older pending revisions are not mislabeled as materialized. Only after the
newer complete checkpoint is published are their outbox rows marked done with
an immutable `vfs_catalog_revision_collapses` record. The original revision and
mutation receipt remain durable evidence. Collapse cleanup is limited to 500
revisions per Cron pass and uses dedicated pending-revision and reverse-collapse
indexes, so an accumulated outbox cannot turn one maintenance run into an
unbounded D1 scan or write transaction.

This first checkpoint format is deliberately uncompressed and bounded at 32
MiB, 5,000 directories, and 20,000 entries. Exceeding a bound fails the optional
acceleration and leaves the revision retryable; it never weakens the live
paginated API.

`GET /api/v2/catalog/checkpoint` accepts a live nonsnapshot token with both
`directory.list` and `content.read`, effective inherited ACL grants at its root,
and no descendant ACL inheritance break. A physical-root token streams the
immutable R2 object without buffering. A narrower token causes the Worker to
verify that same immutable source and deterministically project only the
complete Merkle closure rooted at the token directory. The projected root has
no parent or original name, so neither sibling entries nor parent-navigation
metadata cross the authority boundary. Snapshot tokens and subtrees containing
an ACL boundary receive HTTP 204 and transparently keep the individually
authorized paginated path. Projection is also conservatively limited to an
8 MiB source artifact so Worker deserialization cannot approach its memory
ceiling; larger artifacts retain the same correct page fallback.

HTTP 204 and HTTP 304 are distinct client states. A 304 carries a fresh
server-side proof that the cached closure is still bulk-authorized. A 204 has
no such proof, so the client requires one current authorized page from every
directory before it may reuse that directory's immutable cached node. An ACL
boundary introduced after an earlier checkpoint therefore fails or narrows the
next sync immediately, including an otherwise empty cached subtree.

Before either delivery, the Worker matches the key, R2 version, byte length,
SHA-256, revision, filesystem root, token chain, and current ACL state to the
exact published D1 head. A projected response also proves that its selected
root equals the current D1 root. The client rechecks the bounded body SHA-256,
canonical JSON, every directory Merkle root, the complete reachable tree, and
the token root using the shared native/WASM SDK validator before hydrating its
private token-scoped DAG. A concurrent newer live root simply misses those
content addresses and falls back to pages; corrupt delivery fails closed.

The D1 proof preserves separate bounded cost paths. Physical-root tokens scan
only the partial active-ACL-boundary index. Narrow tokens walk only their active
descendants through the active-parent index; the published checkpoint bound
limits that closure to 5,000 directories. Token parents, grants, memberships,
head artifacts, and selected directory identities use their existing primary
or covering indexes.

After every complete hydration, the client atomically stores a small
SHA-256-enveloped head receipt beside that token's private nodes. A later sync
sends its exact strong `If-None-Match` tag. Full views use the immutable object
SHA-256 as the tag. Projected views use a domain-separated digest of the source
artifact and authorized root, letting the Worker reauthorize and return HTTP
304 before opening R2. The response body has a separate exact SHA-256 receipt;
the two values are intentionally not conflated. A missing, partial,
noncanonical, or corrupt local receipt cannot create a hit: the client requests
and revalidates the complete checkpoint instead. The receipt is only an
acceleration hint and never replaces the live root page and final fence.

Projection was added in Rust SDK `0.3.1`. The Worker keeps accepting protocol
epoch 2 SDK `0.3.0`, but returns HTTP 204 for its narrow roots so rolling or
offline clients preserve the old correct pagination behavior instead of
misinterpreting the new view-specific entity tag.

Rust SDK `0.3.2` adds an explicitly negotiated full-root delta. During
materialization, when the previous and target complete checkpoints are both at
most 8 MiB, Carrack compares their authenticated directory content addresses.
It stores a delta only when the canonical body is strictly smaller than the
complete target. The delta commits the exact base and target revision, root,
and checkpoint SHA-256 and contains only target directory nodes whose
`(directory_id, data_root)` is absent from the base.

A client advertises all four base receipt dimensions plus its old entity tag.
The Worker serves a delta only when a published D1 artifact matches every one
of them and the current full-root authorization proof has already passed. The
client reconstructs its complete base closure from independently checked local
nodes, applies the changed nodes, derives navigation metadata from target
Merkle edges, rejects missing or unreachable changes, revalidates the complete
target tree, and requires the resulting canonical body to match the target
checkpoint SHA-256. A missed transition, narrow token, SDK before `0.3.2`,
oversized source, or absent delta receives the complete checkpoint instead.

Delta availability is never a correctness dependency. Once a catalog head
moves, its predecessor checkpoint and previous delta are marked orphaned in
bounded indexed batches. Server maintenance deletes at most one aged delta and
one aged checkpoint by their exact recorded R2 keys per Cron pass after a
24-hour grace period; no bucket listing or client GC concept is involved.
Multi-hop delivery and narrow-view content-addressed pages remain optional
future accelerations and may not broaden a token closure or weaken the final
live-root fence.
