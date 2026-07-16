# Native driver SPI

This document defines the stable internal boundary for horizontally extending
Carrack storage drivers. [requirements.md](requirements.md) remains normative.

## Boundary

`carrack-driver-contract` is a dependency-free shared model containing every
compiled versioned kind, its native data-path capabilities, credential posture,
grant mode, inventory location, and lifecycle location. It performs no I/O and
contains no provider implementation. Both `carrack-client` and the Worker use
its exhaustive enum, so their interpretation of a kind cannot silently drift.

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

`tests/architecture-boundaries.sh` mechanically enforces the most important
dependency directions. Adapter conformance tests prove behavior; the registry
alone is not a correctness proof.
