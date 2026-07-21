# Skydriver portable correctness core

## Stability contract

`skydriver-sdk-core` is the smallest Rust layer allowed to define Skydriver wire
identity and cryptographic correctness. It is compiled for native targets and
`wasm32-unknown-unknown`. It has no filesystem, network, async runtime,
database, provider, CLI, UI, or Cloudflare dependency.

Outer layers adapt values and orchestrate effects:

- `skydriver-client` owns local files, direct provider I/O, concurrency,
  recovery journals, and atomic publication;
- the Worker owns authorization, D1 transactions, R2 metadata, leases, and
  server lifecycle;
- `skydriver` and `skydriverctl` expose client operations and stable diagnostics;
- the web UI renders server state and submits validated mutation drafts.

None of those layers may establish final content, crypto, or catalog validity
without a core result.

## Orthogonal modules

| Module | Owns | May depend on |
|---|---|---|
| `canonical` | Context-free canonical wire parsing | shared `Error` |
| `integrity` | File/directory Merkle, metadata root, block manifest | shared `Error` |
| `crypto` | Version key derivation, frame AAD, seal/open | shared `Error` |
| `catalog` | Checkpoint/delta schemas and complete closure proofs | `integrity`, shared `Error` |
| `acceptance` | Native/WASM composition proof | public APIs of all required modules |

Leaf modules do not call each other or inspect private state. `catalog` has a
one-way dependency on directory integrity because a catalog closure commits to
directory roots. `acceptance` owns no protocol rule and exists only to prove
that the same public implementation runs under Worker WASM.

Disposable metadata-cache encryption is deliberately outside this crate in
`skydriver-metadata-cache`. That orthogonal primitive knows only authority scope,
logical record context, byte bounds, and authenticated encryption; it owns no
VFS or Merkle semantics and cannot establish protocol correctness.

## Change policy

A driver, UI, CLI, telemetry, quota, or provider change should not edit this
crate. A core change requires all of the following:

1. an identified normative requirement and updated wire document when bytes
   or acceptance rules change;
2. module-local positive, negative, and boundary tests;
3. language-neutral golden vectors for stable binary formats;
4. native tests and a `wasm32-unknown-unknown` build;
5. Worker and native-client conformance tests;
6. architecture-boundary checks proving the algorithm was not copied outward.

The normal gate includes a 100,000-entry ordered-directory test. The explicit
million-entry scale acceptance is run with:

```bash
nix develop -c cargo test -p skydriver-sdk-core \
  integrity::tests::streaming_directory_accepts_one_million_entries_with_logarithmic_state \
  --release -- --ignored --exact
```

Optional caches, fs-verity receipts, page spools, batching, and other
accelerations live outside this crate. They may skip work only after proving
equivalence to a core identity and must fall back to the ordinary core proof
when unsupported, missing, stale, corrupt, or over a bound.
