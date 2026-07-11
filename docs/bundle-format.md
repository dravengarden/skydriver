# Carrack bundle V1

Carrack bundles reduce provider object count for small immutable files without
reserving fixed-size slots. This format is provider-neutral plaintext input to
the normal Carrack pack encryption pipeline.

## Non-padding invariant

For bundle entries ordered by canonical path:

```text
entry[0].offset = 0
entry[n].offset = entry[n-1].offset + entry[n-1].size
data_bytes = sum(entry.size)
```

No alignment bytes, zero fill, sparse ranges, or capacity reservation may
appear between entries. A zero-length file consumes no data-region bytes. Frame,
extent, logical-pack, transfer-window, multipart-part, and provider-object sizes
are targets or upper bounds; they never allocate a fixed logical slot.

## Encoding

One `carrack.bundle.v1` byte stream is:

```text
exact concatenated file bytes
canonical JSON bundle index
56-byte footer
```

The canonical JSON index has this shape:

```json
{
  "schema_version": "carrack.bundle.v1",
  "data_bytes": 13,
  "entries": [
    {
      "path": "a/file",
      "offset": 0,
      "size": 5,
      "sha256": "..."
    }
  ]
}
```

Entries are strictly sorted by canonical relative path. Paths containing NUL,
backslash, absolute roots, `.` components, or `..` traversal are invalid. Each
entry authenticates its exact file bytes independently with SHA-256.

The footer is big-endian and contains no padding fields:

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 8 | ASCII magic `CRKBNDL1` |
| 8 | 8 | index offset, equal to `data_bytes` |
| 16 | 8 | index byte length |
| 24 | 32 | SHA-256 of the exact canonical index bytes |

The index must end exactly where the footer starts. The total encoded length is
therefore always:

```text
sum(file sizes) + canonical index bytes + 56
```

Metadata is overhead, not padding: every byte has defined recovery semantics.

## Interaction with encrypted packs

The complete bundle stream is ordinary Carrack plaintext. Files may cross
authenticated-frame, integrity-extent, and logical-pack boundaries. Carrack
records exact offsets and never aligns a file to any of those boundaries.

The final authenticated frame contains only its actual remaining plaintext.
AES-GCM adds one 16-byte tag per non-empty frame; it adds no padding. Provider
objects likewise use exact ciphertext lengths. A driver may group contiguous
extents or split them across provider objects without changing bundle or crypto
identity.

## Determinism and retry

Bundle membership, canonical paths, declared sizes, and ordering must be fixed
before the bundle is consumed by an import. `PlanBundle` produces a strict
`carrack.bundle-plan.v1` document containing the sorted membership, exact sizes,
and contiguous offsets. `WritePlannedBundle` rejects missing or extra readers
and any source that ends before or after its declared size.

Bundle creation and encrypted import are deliberately two persisted stages:

```text
persist bundle plan
  -> write and fsync exact bundle bytes
  -> persist normal Carrack import plan for that bundle object
  -> encrypt and transfer
```

Replaying the same exact sources emits the same bundle bytes, index, and footer;
Carrack's normal import plan then preserves random pack identities across
transfer retries. Neither retry may silently regroup bundle members.
