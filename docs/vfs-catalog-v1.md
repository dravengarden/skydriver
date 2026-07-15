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

The D1 schema already reserves catalog revisions and an outbox, but the current
outbox row stores only a revision pointer. Live directory rows are mutable, so
a delayed worker cannot safely reconstruct arbitrary historical revision `N`
after revision `N+1` has committed. Publishing a later live view under the old
revision identity would be a correctness bug.

Before R2 checkpoint or delta publication is enabled, mutation transactions
must persist enough immutable canonical event data to reconstruct the exact
revision, or a materializer must explicitly collapse pending work into a newly
verified latest checkpoint and never claim to have materialized skipped
historical states. R2 objects must be content addressed, root verified, and
published through a conditional head only after the immutable object exists.

Until then, the authenticated paginated directory API is the source for missing
nodes. Local DAG reuse still removes all unchanged subtree reads and lets
metadata synchronization run ahead of provider payload pipelines.
