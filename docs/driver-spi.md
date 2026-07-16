# Native driver SPI

This document defines the stable internal boundary for horizontally extending
Carrack storage drivers. [requirements.md](requirements.md) remains normative.

## Boundary

`carrack-driver-contract` is an I/O-free shared model containing every
compiled versioned kind, its native data-path capabilities, credential posture,
grant mode, inventory location, lifecycle location, and strict serialized
configuration shape. It contains no provider implementation or policy-bound
environment validation. Both `carrack-client` and the Worker use its exhaustive
enum and config types, so their interpretation of a kind cannot silently drift.

The Worker adds a pure `driver_configuration` policy layer over those shared
types. It performs strict normalization, provider-safe field validation,
credential-posture checks, and environment-registration restrictions without
D1 or provider I/O. Registration, credential replacement, and enablement all
reuse it; none may depend on another management transaction module for config
meaning.

Provider credential wire shapes, local validation, OAuth exchange, and bucket
verification live behind `driver_authorization`. The management transaction
validates authority before taking its D1 claim, then releases the exact fenced
claim on every provider rejection, retryable outage, or adapter error. It alone
seals the returned credential material and commits receipts and audit state.

`carrack-client` exposes one compiled `DriverRegistry` to native transfer
orchestration. The registry accepts a versioned driver kind, JSON grant
envelopes, and one uniform immutable upload or download request. It rejects an
unknown kind before provider I/O. Server-controlled values never select a
library, executable, symbol, URL handler, or script.

The registry owns:

- exact mapping from a wire driver kind to one compiled adapter;
- complete, internally consistent capability descriptors;
- credential-presence posture and one-use credential consumption;
- uniform correctness-preserving fallback warnings;
- conversion of adapter results into complete provider-object evidence.

The Worker has a separate `driver_registry` execution facade over the same
shared contract. After a VFS subsystem has authorized an operation, opened its
credential envelope, and pinned all revisions and expiry, that facade alone
projects provider authority into a least-privilege object grant. The caller
retains zeroization and D1 fencing; the registry retains provider signing and
refresh-authority omission. This keeps authorization modules provider-neutral
without hiding their correctness-critical transactions.

Provider-specific multipart grant projection also enters through this facade.
The VFS handler owns immutable intent authorization, upload-identity binding,
cleanup-task fencing, audit, and credential zeroization; the registry checks
the declared capability posture and dispatches only to a compiled multipart
signer.

Hosted inventory and lifecycle use two additional orthogonal execution
facades. `driver_inventory` performs one bounded provider listing page;
`driver_lifecycle` performs one already-fenced object deletion or incomplete
upload cleanup. Neither facade may access D1, claim work, publish state, choose
retention, or retry. Their VFS callers retain generation commits, quarantine,
reachability and read-lease fences, credential-envelope opening and
zeroization, and fenced outcome transitions. Therefore adding a provider
cannot silently weaken lifecycle safety or inventory publication.

The inventory facade also owns provider execution reachability, strict config
decoding, credential decoding, and cursor wire schemas. Its caller uses only
the shared inventory posture to decide whether a hosted credential envelope
must be renewed and opened; it never interprets provider configuration or
credential fields.

An adapter owns:

- typed parsing and validation of its configuration and object-scoped grant;
- provider request and response semantics;
- bounded multipart or exact-range pipelines when supported;
- full encoded-length and SHA-256 readback before returning success;
- stable native identity and provider-version extraction;
- provider-specific failure classification and resumable receipts.

The registry and adapters do not own plaintext publication, Merkle algorithms,
encryption derivation, ACLs, placement, quotas, credential renewal, or garbage
collection. The portable kernel and control plane retain those responsibilities.

## Capability rules

Every compiled adapter declares every capability; omission is not interpreted
as support. `Native` means the provider directly supplies the property,
`Emulated` means the adapter preserves it with additional verified work, and
`Unavailable` means the caller receives an explicit safe fallback warning or
the operation fails closed. A descriptor is invalid when a required
complete-object property is unavailable or when one capability depends on an
unavailable prerequisite.

Capability declarations describe implemented behavior, not provider marketing
claims. For example, SOCKS support remains false until the native HTTP stack is
compiled, configured, and tested for SOCKS operation.

## Adding a driver

A new driver change is complete only when it:

1. adds the exact versioned kind and complete posture to
   `carrack-driver-contract`;
2. adds a native adapter with private typed configuration and grant types and
   registers it in `driver.rs`;
3. implements the uniform upload and download requests without changing their
   provider-independent meaning;
4. verifies complete encoded length and SHA-256 before returning success;
5. classifies permanent loss, provider unavailability, authorization failure,
   and corrupt ciphertext without parsing display text;
6. adds positive, negative, corruption, interruption, concurrency, and
   capability-fallback tests appropriate to the adapter;
7. leaves `carrack-sdk-core`, `transfer.rs`, and `download.rs` free of provider
   identifiers and provider-module calls;
8. implements and tests the matching Worker registration, grant, inventory,
   renewal, Stat, Delete, and GC branches where its declared posture requires
   control-plane ownership.

Provider HTTP and wire schemas belong in the corresponding driver facade, not
in VFS authorization, inventory-state, or lifecycle-state modules. A new
hosted provider must enter these exhaustive dispatchers; an agent-host-only
provider must fail closed before hosted provider I/O.

`tests/architecture-boundaries.sh` mechanically enforces the most important
dependency directions. Adapter conformance tests prove behavior; the registry
alone is not a correctness proof.
