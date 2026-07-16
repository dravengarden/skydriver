# Carrack requirements

This document is the normative product and correctness baseline. The key words
**MUST**, **MUST NOT**, **SHOULD**, and **MAY** are normative.

## Product boundary

- Carrack MUST remain business-neutral. Source adapters, dataset catalogs,
  schedules, parsers, and consumer semantics belong to callers.
- Carrack MUST have exactly two product components: a Rust Cloudflare control
  plane and a canonical Rust client core.
- `carrack` MUST expose filesystem-like byte and local-file operations.
  `carrackctl` MUST expose every supported operator UI mutation through the
  same server validation contract.
- Payload bytes MUST flow directly between clients and drivers. The Worker
  MUST NOT relay a file body.
- GC tasks, refresh tokens, driver parent credentials, key envelopes, provider
  locators, and fencing tokens MUST remain hidden from ordinary filesystem
  callers.
- Carrack MUST NOT split, pack, bundle, merge, compact, or stripe user files.
  One input file MUST remain one complete provider object at every location.

## Stable correctness core

- `carrack-sdk-core` MUST be the portable, provider-free correctness kernel
  shared by native clients and Worker WASM. It MUST NOT depend on filesystems,
  sockets, async runtimes, databases, Cloudflare APIs, drivers, CLI, or UI.
- Core responsibilities MUST remain in orthogonal modules: canonical wire
  values, content integrity, encryption, authenticated catalog closure, and a
  composition-only native/WASM acceptance proof. A module MUST NOT duplicate
  or reach into another module's private algorithm.
- Integrity domains, Merkle construction, block-manifest encoding and
  validation, key derivation, frame authentication, and catalog closure MUST
  have exactly one Rust product implementation in `carrack-sdk-core`.
- `carrack-client` and the Worker MAY adapt owned transport or database values
  into core value objects, but MUST delegate the final canonical validation to
  the core. CLI and UI validation is advisory UX only; server and core
  validation remain authoritative.
- Every core module MUST have independent positive, negative, boundary, and
  golden-vector tests where a language-neutral format exists. Changes to core
  wire semantics MUST update normative documentation and pass native plus WASM
  gates. Outer-layer feature work SHOULD NOT modify the core.
- Optional acceleration MUST remain outside the correctness kernel and MUST
  safely fall back to the same core proof when absent, stale, corrupt,
  unsupported, or over its resource bound.

## Namespace and object model

- Directory, file, and version identities MUST be stable opaque identifiers
  independent of paths. Server-created identities SHOULD be UUIDv7 for D1
  locality.
- Every content change MUST create a new immutable file version. Publication
  MUST only move a file's current-version pointer atomically with its namespace
  and Merkle changes.
- Rename and move MUST be metadata-only. They MUST NOT copy or re-encrypt an
  unchanged file version.
- A location MUST identify one complete encoded object with its exact length,
  encoded SHA-256, driver identity and revision, opaque provider key, lifecycle
  state, and every available strong provider-native identity.
- Provider object names MUST NOT reveal virtual paths, original filenames,
  principals, media types, directory identities, or consumer meaning.
- Multipart parts, encryption frames, verification blocks, HTTP ranges, and
  staging files MUST remain private transport units and MUST NOT become
  independently addressable VFS objects.
- Different files in one directory MAY use different drivers. The authenticated
  directory tree MUST remain independent of provider directory trees.

## Integrity and cryptography

- Every plaintext file MUST have a canonical SHA-256 Merkle root over fixed
  verification blocks. Every directory MUST have a canonical ordered Merkle
  root that commits to all visible child roots.
- Upload MUST hash the complete plaintext, verify the complete encoded provider
  object, and publish metadata only after all proofs pass.
- Download MUST verify each received block or range, complete encoded identity,
  authenticated decryption, plaintext length, and final plaintext Merkle root
  before exposing success.
- A corrupt, short, long, reordered, stale, or unauthenticated response MUST be
  rejected. Correctness MUST NOT depend on provider ETags being content hashes.
- Encryption MUST be enabled by default and MAY be disabled by explicit
  directory policy.
- Each directory MUST own a versioned sealed key epoch. Each immutable file
  version MUST derive a distinct key and nonce domain from that epoch and its
  version identity.
- D1 MUST NOT store plaintext directory keys or file keys. Provider and key
  credentials MUST be stored only in authenticated encrypted envelopes.
- A supported client MUST distinguish missing authority, unsupported suite,
  corrupt ciphertext, corrupt plaintext, provider unavailability, and
  permanent loss.
- Memory use MUST be bounded by configured frame, block, range, multipart, and
  concurrency limits rather than file size.

## Catalog and incremental synchronization

- A client MUST authenticate every catalog checkpoint, subtree, page, and
  delta before it plans payload work.
- A directory checkpoint MUST commit to the exact filesystem, revision, root
  directory, data root, node count, and canonical node bytes.
- A catalog delta MUST commit to an exact authenticated base and target and
  MUST reconstruct a complete target that independently verifies to the target
  root.
- Missing, incompatible, oversized, multi-hop, narrow-authorization, or
  ACL-sensitive acceleration MUST fall back to a complete checkpoint or
  revision-pinned traversal without weakening correctness.
- Incremental sync MUST transfer no provider payload for an unchanged
  authenticated file whose destination bytes still verify. A missing or corrupt
  destination MUST NOT be accepted from metadata alone: the client MUST either
  redownload it or copy an independently complete local candidate into private
  staging and fully reverify the expected immutable version, size, and plaintext
  Merkle root before publication.
- A final live-root recheck MUST reject a plan whose namespace changed during
  synchronization unless the caller explicitly requested a pinned snapshot.

## Transfer and recovery

- Transfer APIs MUST support bytes, local files, replayable readers, bounded
  range sources, and private spooling for one-shot streams.
- Uploads and downloads MUST support bounded concurrency, pipelining,
  interruption, and resume where the driver permits it.
- Recovery journals MUST persist no payload bytes, plaintext keys, refresh
  tokens, or provider parent credentials.
- A journal MUST bind the source identity, immutable plan, destination,
  expected revisions, driver descriptor, provider object, checksums, and
  completion receipts with an integrity-protected revision history.
- Resume MUST revalidate local source or staging identity, reacquire short-lived
  authority, compare remote identity, and transfer only missing or invalid
  units.
- A driver lacking exact ranges or multipart resume MAY restart the current
  complete file after an explicit capability warning. It MUST NOT report a
  partial object as published.
- Provider-object publication MUST be atomic no-replace. A concurrent key
  collision MAY be adopted only after complete independent readback proves the
  exact encoded length and SHA-256; otherwise the existing provider object
  MUST remain untouched and publication MUST fail closed.
- Local destination publication MUST be atomic. A failed verification MUST
  leave the prior destination intact.

## Driver contract

- Product drivers MUST be compiled, versioned Rust adapters selected through a
  typed registry. Server data MUST NOT cause a client to load arbitrary code.
- A driver descriptor MUST declare complete upload, exact range, multipart,
  concurrency, checksum, stable identity, Stat, abort, Delete, maximum object,
  and proxy capabilities.
- Unsupported optimization capabilities MUST produce a warning that names the
  fallback and a suitable replacement when one exists.
- Every fallback MUST preserve complete-object identity and full verification.
- Driver configuration and credentials MUST pass client-side checks and
  authoritative server-side validation before persistence.
- Credential rotation MUST preserve the driver's provider authority identity.
  Rebinding a driver to another provider account or bucket requires a distinct
  driver identity and an explicit verified data migration.
- Refresh authority MUST stay in the control plane. Filesystem clients MUST
  receive only short-lived object-scoped grants and MUST NOT implement
  credential renewal.
- Renewal MUST use a bounded lease and fencing token, validate provider
  identity and expiry, atomically rotate the encrypted bundle, retry transient
  failures, and fail closed as reauthorization-required after permanent
  rejection.
- OpenList MAY be reviewed as provider-behavior reference material and MAY be
  used interactively as an OAuth issuer. Carrack MUST NOT link to, launch,
  supervise, or route payloads through OpenList.
- Carrack MUST NOT embed a proxy daemon. A component MAY use an external HTTP,
  HTTPS, SOCKS5, or SOCKS5H proxy through its native network stack.

## Concurrency and publication

- Network or provider I/O MUST NOT hold a D1 transaction or distributed
  pessimistic lock.
- Metadata mutation MUST use immutable identities, expected revisions,
  idempotency keys, and short optimistic transactions.
- An idempotent replay with identical canonical input MUST return its durable
  receipt. Reusing a key with different input MUST fail.
- A stale namespace, ACL, placement, driver, quota, key epoch, lease, or fence
  MUST fail before publication or deletion.
- Provider success followed by a lost response MUST be recoverable by exact
  identity inspection and idempotent retry.
- Duplicate physical work MAY exist temporarily after a race or crash, but at
  most one logical version may win publication. Losing objects MUST be
  reclaimable only through the normal delayed lifecycle protocol.

## Authorization and management

- VFS bearer tokens MUST be attenuated by principal, subtree, fixed actions,
  expiry, revocation ancestry, and optional driver scope.
- The server MUST reevaluate current inherited allow-only ACLs on every request.
  A token MUST NOT preserve an ACL grant that was later removed.
- A child token MUST NOT outlive or exceed any ancestor authority.
- Named roles MAY be UI presets expanded to fixed actions. Carrack MUST NOT
  require a general RBAC or policy-language engine.
- Operator configuration authority MUST remain separate from VFS plaintext
  authority. The bootstrap all-actions VFS token is recovery authority, not an
  everyday agent credential.
- The UI MUST be read-only by default. Reauthentication MAY open only a
  short-lived mutation session and MUST NOT grant file-content access.
- Every UI mutation MUST have an equivalent `carrackctl` operation with stable
  JSON, local validation, server normalization, expected revision, idempotency,
  and durable audit receipt.
- Secret input MUST use stdin, an owner-private file, browser paste, or an
  equivalent non-argv channel. A secret MUST never be returned after storage;
  only redacted health and expiry metadata may be displayed.

## Quota and placement

- A directory policy MAY set maximum single-file bytes, logical subtree bytes,
  active file count, and allowed or preferred drivers.
- A Put MUST satisfy every inherited ancestor quota and placement policy in the
  same publication decision.
- A driver hard quota MUST include committed encoded bytes plus conservatively
  reserved in-flight bytes. A failed or expired intent MUST eventually release
  its reservation exactly once.
- Quota and placement changes MUST be revisioned, validated, auditable, and
  immediately visible to both UI and management clients.
- Quotas are safety limits, not billing promises. Provider-side quota
  exhaustion MUST remain a distinct diagnosable error.

## Retention and garbage collection

- Logical remove MUST tombstone namespace state without synchronously deleting
  provider bytes.
- Filesystem clients and the public SDK MUST NOT enumerate, claim, authorize,
  or execute GC.
- Server Cron MUST own bounded metadata hygiene, reachability marking,
  tombstone grace, abandoned-upload cleanup, and hosted-provider deletion.
- Current roots, valid retained snapshots, active snapshot sessions, unexpired
  upload intents, and active direct-read leases MUST protect reachable
  locations.
- Missing, unsealed, inconsistent, or ambiguous reachability evidence MUST fail
  closed and retain data.
- Immediately before provider deletion, the server MUST recheck reachability,
  read leases, immutable locator, provider identity, driver revision, grace,
  claim lease, and fencing token.
- Automatic deletion MUST require stable provider identity, exact Stat, and
  idempotent Delete. Unsupported drivers MUST remain tombstoned and
  server-blocked rather than guessed clean.
- Provider absence after a lost delete response MAY complete a task only after
  the same final fences and exact identity checks.

## Compatibility and upgrades

- Every native request MUST identify a protocol epoch and SDK version.
- The server MUST reject an unsupported epoch or SDK below its minimum with a
  machine-readable upgrade-required response before metadata mutation or
  provider I/O.
- Clients MUST fail closed on an unknown mandatory field, schema, algorithm,
  capability, or state transition.
- Optional acceleration MAY be version-negotiated. Its absence MUST only reduce
  performance and MUST NOT alter identity or correctness.
- Rust is the sole product implementation. Retained Go conformance packages
  MUST NOT expose a CLI, SDK, hosted provider, archive model, or product policy.

## Transfer observability

- Transfer telemetry MUST remain advisory and MUST NOT authorize, publish,
  reject, retry, or otherwise alter a filesystem operation.
- Payload progress MUST remain client-local. The control plane MAY accept one
  bounded completion observation after a verified transfer and process it
  asynchronously; telemetry failure MUST NOT change the transfer result.
- Transfer analytics MAY use deterministic sampling and weighted estimates.
  The API and UI MUST label estimated values and MUST NOT present them as
  billing, integrity, quota, or authorization evidence.
- Correlated filter dimensions MUST be retained in the same aggregate fact.
  Independently aggregated driver, token, and directory totals MUST NOT be
  combined as though they prove an intersection.
- Analytics queries MUST use a closed set of dimensions, bounded time ranges,
  bounded result sizes, indexed retention, and server-selected time buckets.
- Raw bearer values, credentials, filenames, virtual paths, provider keys,
  plaintext metadata, and client-supplied free-form labels MUST NOT enter
  transfer analytics.

## Security and environments

- Secrets and credentials MUST never enter Git, command arguments, logs,
  analytics, browser storage, plaintext D1 columns, or API responses.
- Provider credentials MUST be least-privilege and environment-scoped. A
  default R2 parent credential MUST be scoped to exactly its environment bucket.
- Development and production MUST use distinct Workers, custom routes, D1
  databases, R2 buckets, secrets, credentials, bootstrap authorities, and
  provider roots.
- Production MUST use `carrack.stormbird.xyz`; development MUST use
  `dev.carrack.stormbird.xyz`. Both MUST disable workers.dev and preview URLs.
- Deployment tooling MUST reject overlapping dev/prod resource identifiers and
  MUST run environment-specific acceptance before promotion.
- Public health and every operator surface MUST identify the active
  environment without revealing secrets.
- Configuration changes and security-sensitive lifecycle actions MUST emit
  durable audit records with actor, exact target, revision, result, and time.

## Verification gate

- Every commit MUST pass formatting, strict Rust/Go/TypeScript lint, race
  tests, unit tests, native and WASM SDK tests, local Worker+D1 protocols, UI
  tests, architecture boundaries, and dev/prod deployment dry-runs.
- Shared binary formats MUST have deterministic cross-language golden vectors
  while more than one conformance implementation exists.
- Driver acceptance MUST cover partial and wrong ranges, stale identity,
  throttling, authorization loss, quota exhaustion, interruption, resume,
  success-with-lost-response, and corruption.
- Lifecycle acceptance MUST inject crashes and stale fences around every remote
  side effect and D1 transition before a driver is eligible for automatic
  production deletion.
- D1 query shapes used by bounded production loops MUST have explicit tested
  indexes. New indexes MUST correspond to a concrete read or maintenance path.
- Tests MUST prove that stale clients cannot publish, move, authorize, or
  delete after their expected revision, token, lease, or fence becomes invalid.
