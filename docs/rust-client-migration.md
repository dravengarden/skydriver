# Rust client migration

Carrack's public binaries and canonical client core are Rust. Migration is
complete: the former Go archive SDK and internal CLI have been removed. The
remaining Go packages are narrow conformance oracles and do not build a public
`carrack` or `carrackctl` binary.

## Target boundary

- `carrack` is a filesystem facade: put, get, list, stat, mkdir, remove, rename,
  and incremental sync.
- `carrackctl` is the non-interactive JSON-first management facade used by the
  UI, operators, and AI agents.
- `carrack-client` owns protocol compatibility, local filesystem I/O, streaming
  encryption, hashing, bounded transfer execution, automatic resume state, and
  verification.
- The control plane owns hosted-driver configuration, credentials, capability
  probing, transfer planning, publication, retention, and physical garbage
  collection.
- OpenList is neither linked nor executed. A pinned upstream implementation may
  be reviewed as provider-behavior evidence while a narrow Rust adapter is
  implemented and tested.

## Compatibility gate

Every Rust request sends `Carrack-Protocol-Epoch` and `Carrack-SDK-Version`.
Before metadata mutation or provider I/O, the client reads
`GET /api/compatibility`. An incompatible epoch, an SDK below the server
minimum, a malformed contract, or HTTP 426 fails the command before side
effects. Version output is stable JSON so an agent can decide whether to
upgrade without scraping prose.

Protocol epoch 2 currently requires SDK `0.3.0` or newer. This floor covers the
strict credential-expiry management contract; a `0.1.x` CLI or SDK receives
HTTP 426 before VFS or management I/O and must be upgraded rather than parsing
or applying a partial response.

## Completed replacement boundary

1. `carrack` provides list, stat, mkdir, put, get, remove, and rename.
2. `carrackctl` provides the redacted UI snapshot, directory inspection,
   typed driver/config/credential mutations, token annotation, ACL and
   placement replacement, and attenuated token issue/revoke.
3. Rust owns the native local and Aliyun complete-object adapters. Neither
   links to, launches, or calls OpenList.
4. Direct downloads acquire a durable server read lease and explicitly release
   it. Server cron alone owns reachability marking and physical cleanup.
5. Go remains only for the complete-object driver contract, durable transfer
   journal, and shared Merkle/crypto conformance vectors. It is not a product
   SDK, provider implementation, or installation surface.

The removed surface included packs, bundles, extents, archive manifests,
compaction, the provider-oriented Go transfer stack, and every Go command
adapter. Architecture tests reject their reintroduction.

The migration must never expose provider credentials, GC leases, storage keys,
Merkle internals, or journal maintenance to ordinary filesystem users.
