# Native driver SPI

This document defines the stable internal boundary for horizontally extending
Carrack storage drivers. [requirements.md](requirements.md) remains normative.

## Boundary

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

1. adds a versioned adapter with private typed configuration and grant types;
2. registers the exact wire kind in `driver.rs` and declares all capabilities;
3. implements the uniform upload and download requests without changing their
   provider-independent meaning;
4. verifies complete encoded length and SHA-256 before returning success;
5. classifies permanent loss, provider unavailability, authorization failure,
   and corrupt ciphertext without parsing display text;
6. adds positive, negative, corruption, interruption, concurrency, and
   capability-fallback tests appropriate to the adapter;
7. leaves `carrack-sdk-core`, `transfer.rs`, and `download.rs` free of provider
   identifiers and provider-module calls;
8. documents server-owned Stat, Delete, renewal, and GC behavior and tests it
   independently when the Worker can reach the provider.

`tests/architecture-boundaries.sh` mechanically enforces the most important
dependency directions. Adapter conformance tests prove behavior; the registry
alone is not a correctness proof.
