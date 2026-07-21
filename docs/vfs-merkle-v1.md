# Skydriver VFS Merkle V1

## Scope

This document fixes the cross-language binary format for VFS plaintext file
roots and directory data roots. Go and Rust must match
`testdata/vfs-merkle-v1.json` byte for byte. Changing any domain, field order,
integer width, tree shape, or normalization rule requires a new format version;
an in-place interpretation change is forbidden.

These roots authenticate logical VFS content. The complete provider-object
SHA-256 separately authenticates encoded bytes after optional encryption.
Multipart parts, HTTP ranges, and provider ETags do not participate in this
logical format.

## Primitive encoding

- Hash: SHA-256, stored as 32 raw bytes and displayed as 64 lowercase hex.
- Domain: the listed ASCII bytes followed by one NUL byte.
- `u32` and `u64`: unsigned big-endian fixed width.
- Identifier: 16 raw nonzero bytes.
- Name: `u32` UTF-8 byte length followed by those bytes.
- Concatenation: exactly the listed order, with no padding or implicit fields.

Stable directory and file IDs, and immutable file-version IDs, are independent
128-bit identifiers. The control plane should allocate UUIDv7 values for D1
index locality, but the hash format treats them as opaque bytes. IDs are never
derived from a name or content root. Provider storage names are a separate
random 192-bit-or-stronger namespace and never expose these IDs.

## Canonical binary tree

Given `N > 1` ordered leaf digests, split at the largest power of two strictly
less than `N`. Recurse over the prefix and suffix. The node record is:

```text
domain || first_leaf:u64 || leaf_count:u64 || left:hash || right:hash
```

For one leaf, the tree digest is the leaf digest itself. Empty file and
directory trees use their dedicated empty domains. This left-complete shape is
unique for every leaf count; odd nodes are neither duplicated nor silently
promoted.

## File tree

A file uses one positive fixed verification-block size. Blocks are zero-based,
gapless, and exact; only the final block may be shorter. At most 1,000,000
blocks are retained in V1 metadata.

```text
file leaf = SHA256(
  "skydriver.vfs.file.leaf.v1\0" ||
  block_index:u64 || exact_block_bytes:u64 || plaintext
)

file node domain  = "skydriver.vfs.file.node.v1\0"
empty tree        = SHA256("skydriver.vfs.file.empty.v1\0")

file root = SHA256(
  "skydriver.vfs.file.root.v1\0" ||
  configured_block_bytes:u64 || exact_file_bytes:u64 ||
  block_count:u64 || tree_digest:hash
)
```

The block size is part of the identity, so the same bytes with a different
layout intentionally have a different V1 root. Upload and download must also
verify exact length and EOF; a matching prefix is never sufficient.

## Block manifest

The content-addressed block manifest lets the control plane and another client
recompute a file root without receiving payload bytes. Its canonical binary
encoding is:

```text
"skydriver.vfs.block-manifest.v1\0" ||
exact_file_bytes:u64 || configured_block_bytes:u64 || block_count:u64 ||
block_0_leaf:hash || ... || block_n_leaf:hash || file_root:hash
```

Leaf digests are the domain-separated file leaf values above, in ascending
zero-based order. Index, offset, and final-block length are derived from the
three header integers and are not redundantly encoded. A parser must require
the exact canonical byte length, a nonzero digest for every nonempty block,
the canonical block count, a recomputed matching file root, and EOF. Empty
files contain no leaf digests but still include their nonzero empty file root.

The SHA-256 of this entire binary record is the `block_manifest_sha256` stored
in D1. R2 stores the exact record under a content-addressed control-metadata
key. The record contains no payload bytes, filename, virtual path, encryption
key, provider locator, or user identity. Shared Go/Rust binary vectors live in
`testdata/vfs-block-manifest-v1.json`.

## Directory tree

One directory is a case-sensitive collection of at most 1,000,000 immediate
entries. Names must be valid Unicode NFC, 1 to 255 UTF-8 bytes, and a single
component other than `.` or `..`. Entries sort by unsigned UTF-8 bytes and
duplicate normalized names are invalid.

```text
file entry = SHA256(
  "skydriver.vfs.directory.file-entry.v1\0" ||
  name || stable_file_id:16 || immutable_version_id:16 ||
  plaintext_bytes:u64 || file_root:hash || portable_metadata_root:hash
)

directory entry = SHA256(
  "skydriver.vfs.directory.child-entry.v1\0" ||
  name || stable_directory_id:16 || child_data_root:hash
)

directory node domain = "skydriver.vfs.directory.node.v1\0"
empty tree = SHA256("skydriver.vfs.directory.empty.v1\0")

directory root = SHA256(
  "skydriver.vfs.directory.root.v1\0" ||
  entry_count:u64 || tree_digest:hash
)
```

V1's empty portable-metadata commitment is
`SHA256("skydriver.vfs.metadata.empty.v1\0")`. A future portable metadata schema
gets its own domain and supplies its digest through the existing entry field.
ACL, token, encryption-epoch, and placement-policy roots remain separate, so
an authorization change cannot pretend that file bytes changed.

## Implementations

- Go authority and streaming API: `vfs/merkle`.
- Rust control-plane verifier: `control-plane/src/vfs_merkle.rs`.
- Shared golden vectors: `testdata/vfs-merkle-v1.json`.

Both implementations reject malformed layouts, zero required IDs or digests,
unknown entry unions, non-NFC names, duplicate names, non-canonical hex, and
roots that differ from the shared vectors.
