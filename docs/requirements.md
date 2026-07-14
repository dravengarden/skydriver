# Carrack requirements

This document is the product and correctness baseline for Carrack. It records
requirements, not a particular database schema or implementation plan. The
architecture may evolve only if these guarantees remain true or this document
is deliberately revised.

The key words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are normative.

## Product boundary

- Carrack MUST remain business-neutral. Exchange adapters, market-data
  catalogs, dataset schedules, parsers, and trading semantics belong to
  consumer projects.
- Carrack MUST contain exactly two product components: a language-neutral
  client data plane with a canonical Rust implementation, and a Rust control
  plane deployed on Cloudflare with a TypeScript operator UI.
- The `carrack` CLI MUST expose filesystem operations only. Provider selection,
  transfer planning, catalog synchronization, encryption, recovery journals,
  snapshots, leases, and garbage collection MUST remain implementation details.
- The separate `carrackctl` CLI MUST expose every operation available through
  the operator UI through the same management API and validation rules. It is
  an SDK consumer for operators and AI agents, not a third product component.
- The public filesystem SDK MUST NOT expose garbage-collection candidates,
  delete tasks, janitor leases, fencing tokens, or provider delete grants.
- Payload bytes MUST flow directly between clients and storage drivers. The
  control plane MUST NOT relay payload bytes in V1.
- The control plane MAY access a driver for credential refresh, transfer-plan
  creation, exact object Stat, multipart abort, and physical deletion. These
  control operations MUST NOT relay file payload bytes through the Worker.
- A filesystem client MUST be able to put, get, list, stat, create, remove,
  rename, and incrementally synchronize files through one simple SDK facade.
- Adding a driver or changing a transfer scheduler MUST NOT require changing
  the archive encryption format.

## Data and archive model

- Logical objects MUST be independent from physical provider paths.
- Object versions, manifests, packs, and ciphertext extents MUST be immutable
  after publication.
- Every published object version MUST reference an ordered, content-addressed
  manifest.
- Every readable location MUST have an exact expected length and ciphertext
  SHA-256 identity. Its physical provider offset and length MUST be recorded
  independently so many extents can safely share one provider object.
- Frame, extent, logical-pack, multipart-part, transfer-window, and provider-
  object sizes MUST be targets or upper bounds, never preallocated logical
  slots. Carrack MUST NOT add zero padding to reach any configured target.
- A final frame, extent, pack, or provider object MUST use its exact actual
  length. Authenticated-encryption tags and defined recovery metadata are
  overhead, not padding.
- Small-file bundles MUST concatenate file payloads without alignment gaps.
  The bundle data-region length MUST equal the sum of member file lengths.
  File entries MAY cross frame, extent, and pack boundaries.
- The defaults MUST be 64 MiB plaintext chunks, 8 MiB authenticated frames,
  and an 8 GiB logical pack target. They MUST be independently configurable
  within protocol-safe bounds.
- Chunk size, crypto frame size, provider object size, multipart part size,
  and transfer concurrency MUST remain independent controls.
- A download scheduler MAY coalesce only exactly adjacent preferred ranges
  with the same driver and storage key. It MUST enforce a configured range
  bound, verify every constituent extent independently before consumption, and
  fall back to ordinary per-extent replica selection after a coalesced failure.
- Compaction MUST create and conditionally publish a new immutable pack. It
  MUST NOT rewrite an existing pack in place.

## Cryptography and recovery material

- Encryption and decryption MUST be provider-free streaming transforms.
- Transfer code MUST treat encrypted extents as opaque bytes.
- V1 MUST use the versioned
  `carrack-aes128gcm-hkdfsha256-v1` suite with independently authenticated
  frames.
- Pack keys MUST be deterministically derived from a versioned root seed,
  namespace, key epoch, and pack identifier. D1 MUST NOT contain root, epoch,
  pack, or plaintext data-encryption keys.
- Root seeds MUST live in Cloudflare secrets and tested offline recovery
  storage. Losing D1 MUST NOT lose a root seed.
- Every manifest MUST identify its crypto suite, root version, namespace, key
  epoch, pack identifiers, sizes, ordering, and authenticated hashes without
  containing secret material.
- Missing key material, an unsupported crypto suite, corrupt ciphertext, and
  missing ciphertext MUST be reported as different conditions.
- Encryption and decryption MUST be fast enough that storage or network I/O,
  rather than crypto, remains the expected bottleneck on supported modern
  amd64 and arm64 clients.
- Memory use MUST be bounded by configured frame, transfer-window, and
  concurrency limits, not by object or pack size.
- Bundle membership, canonical paths, declared lengths, and ordering MUST be
  fixed before transfer. A retry MUST NOT silently regroup or reorder members.

## Driver requirements

- Hosted VFS drivers MUST be selected through versioned, compiled, typed
  server-side factories. Control-plane data MUST NOT cause a client to execute
  arbitrary provider code.
- Provider-specific lifecycle policy MUST be authoritative on the control
  plane. Clients SHOULD execute a bounded, validated direct-transfer plan
  instead of independently deciding provider publication or deletion rules.
- A VFS backend driver MUST declare server-side credential refresh, exact Stat,
  multipart abort, and Delete capabilities. A backend without stable object
  identity MUST remain ineligible for automatic physical garbage collection.
- Native Rust adapters SHOULD be used for S3-compatible storage, R2, public
  HTTP, and supported cloud drives. Local filesystems are client-side external
  sources or destinations, not hosted VFS backends.
- OpenList MAY be used as a reviewed behavioral reference for consumer cloud
  drives. Its OAuth broker MAY be configured as a control-plane-only token
  issuer when Carrack has no provider application credential. OpenList code,
  modules, storage servers, WebDAV endpoints, and runtime processes MUST NOT be
  dependencies of Carrack clients or the payload data path.
- Drivers MUST advertise capabilities, size limits, checksum support,
  resumability, safe concurrency, and rate-limit constraints.
- Hosted access-token credentials MUST expose a non-secret absolute expiry when
  the provider token carries one. The server MUST reject malformed or expired
  credentials before persistence, and management clients MUST warn before
  expiry without ever returning credential material.
- Refresh authority MUST remain inside an authenticated encrypted control-plane
  envelope. Filesystem SDKs and the `carrack` CLI MUST receive only access
  credentials, MUST NOT receive refresh tokens, and MUST NOT implement renewal.
- Credential renewal MUST use a D1 CAS lease and fencing token, rotate the
  encrypted access and refresh tokens in one D1 batch, validate provider
  identity and expiry before commit, retry transient failures with bounded
  backoff, and fail closed as `reauth_required` after permanent rejection.
- Cron MUST renew hosted credentials proactively. A transfer grant MUST also
  refuse an access token with less than five minutes of validity unless the
  control plane first completes a fenced renewal.
- Provider-object grouping MUST use only whole consecutive extents, respect a
  driver's hard maximum, and emit an exact short tail. Changing provider-object
  policy MUST NOT change bundle, frame, extent, or ciphertext identities.
- Proxy policy MUST be injected below the driver and MUST NOT appear in object
  identity, manifests, or crypto metadata.
- Carrack MUST NOT embed, download, configure, supervise, or launch a proxy
  daemon. HTTP-capable components MUST use their native HTTP stack with either
  direct routing or an external `http`, `https`, `socks5`, or `socks5h` proxy.
- A driver MUST distinguish transient, throttled, authorization, quota,
  not-found, integrity, and permanent errors when its provider exposes enough
  evidence to do so.
- A provider-wide outage or authorization failure MUST NOT cause all of its
  locations to be immediately classified as missing.
- One `404`, stale inventory response, expired signed URL, or timed-out request
  MUST NOT be sufficient evidence for permanent data loss.
- Upload, stat, range-read, and delete implementations MUST tolerate a request
  succeeding remotely while its response is lost locally.

## Operation safety

- All control-plane mutations MUST be idempotent.
- Import publication MUST occur only after all referenced payload locations and
  recovery manifests have been durably written and verified.
- A crash before publication MAY leave staging objects but MUST NOT expose a
  partially published object version.
- Publication metadata MAY be staged across bounded D1 batches, but the final
  object pointer, published version, durable recovery record, operation state,
  and lease release MUST switch in one fenced atomic batch.
- Copy MUST preserve the source and MUST publish a destination only after
  verifying its complete identity.
- Move MUST be implemented as copy, verify, publish destination, tombstone
  source, and delayed delete. It MUST NOT be implemented as an atomic-looking
  copy-and-delete request.
- Source deletion MUST require a currently verified destination and the active
  replica policy to remain satisfied.
- Restore MUST pin one immutable manifest generation, use resumable local
  state without key material, verify every layer, and atomically publish the
  final local result.
- Failures SHOULD prefer duplicate work, staging orphans, and temporary extra
  replicas over ambiguous publication or deletion.
- Garbage collection MUST be an internal control-plane maintenance operation.
  Ordinary clients and the public filesystem SDK MUST NOT enumerate candidates,
  claim delete work, receive delete credentials, or physically delete VFS
  backend objects.
- Server-side garbage collection MUST use bounded indexed selection, a grace
  period, exact reachability revalidation, stable provider identity, and a
  fenced idempotent completion transition. If D1, snapshot materialization,
  driver identity, or authorization evidence is unavailable, deletion MUST stop.

## Concurrent client correctness

- Network transfer MUST NOT hold a D1 transaction or distributed pessimistic
  lock.
- Metadata publication MUST use short transactions, unique constraints, and
  compare-and-swap revisions.
- Work ownership MUST use renewable leases for scheduling and fencing tokens
  for correctness. Every mutating heartbeat, stage commit, publish, move, and
  delete MUST validate the current fencing token.
- Lease expiry MUST use control-plane time. Correctness MUST NOT depend on a
  client clock.
- Losing a lease MUST prevent a client from publishing metadata or deleting
  provider data, even if its in-flight upload later completes.
- An uncommitted publication intent MAY be rebound after lease takeover only
  when every immutable object, manifest, recovery, and CAS identity is exactly
  unchanged. A committed or conflicting intent MUST NOT be rebound.
- Two clients importing the same bytes MAY both transfer data, but publication
  MUST converge on one valid immutable result.
- Conflicting content for the same logical object MUST produce explicit object
  versions or a visible CAS conflict. It MUST NOT silently overwrite data.
- Concurrent repair or compaction winners MUST be selected by conditional
  publication. Valid losing outputs MAY be adopted or quarantined for later
  GC.
- Read operations MUST use durable read leases bounded by the issuing token's
  original expiry and explicitly complete them when transfer stops. A resumed
  client MAY acquire a fresh lease through a new immutable plan. GC MUST NOT delete the final
  usable replica needed by an active read lease.
- Progress reports MUST carry operation, attempt, monotonically increasing
  sequence, lease, and fencing identities. Duplicate or reordered reports MUST
  be harmless.
- Progress reports MUST use cumulative counters. Retries MUST increase wire
  bytes but MUST NOT increase unique verified progress.
- Distributed rate coordination MUST prevent many clients sharing a credential
  from independently selecting an unsafe aggregate request rate.
- Normal transfer clients MUST NOT physically delete VFS backend objects.
  Destructive work MUST be performed by control-plane maintenance after final
  D1 revalidation. A provider request may outlive its Worker invocation, so
  response-loss recovery MUST converge through exact Stat and fenced retry.

## Public command and management surfaces

- `carrack` MUST behave like a filesystem tool. Its ordinary users MUST NOT
  need to understand driver IDs, storage keys, locations, Merkle nodes, key
  epochs, catalog revisions, GC state, or provider credentials.
- `carrackctl` MUST be non-interactive and machine-readable by default. Every
  response and error MUST have a stable schema and every mutation MUST carry an
  idempotency identity and optimistic expected revision where applicable.
- UI and `carrackctl` mutations MUST use one server-side validate/apply
  protocol. Validation results MUST be bound to the complete desired state and
  current revision; apply MUST reject stale or modified validation evidence.
- Secrets MUST enter `carrackctl` through approved private input, never argv,
  plans, logs, audit payloads, or ordinary output.
- The management operation registry, permission requirement, request schema,
  response schema, and examples MUST be discoverable by an AI agent. The UI
  MUST NOT have management capabilities absent from `carrackctl`.

## Control-plane recovery

- D1 MUST be the authoritative online coordination ledger, but MUST NOT be the
  only copy of information required to locate and decode published data.
- Each published object version MUST have a portable, immutable recovery
  manifest outside D1.
- V1 publication MUST durably store the recovery manifest in the control-plane
  R2 manifest archive and as a sidecar on the destination driver before the D1
  version becomes published.
- Portable manifests MUST be discoverable by bounded provider-prefix inventory
  and verifiable without D1.
- Root seeds, portable manifests, and ciphertext MUST be sufficient to rebuild
  the data index in a fresh control plane.
- D1 MUST be exported periodically to longer-lived storage. Backups MUST be
  restored in drills; merely creating backup files is insufficient.
- A D1 point-in-time restore MUST occur in maintenance mode with mutations
  disabled.
- The control plane MUST have a random `control_plane_incarnation`. After any
  D1 restore, the operator MUST write a new incarnation before reopening
  mutations.
- Every lease, fencing token, operation attempt, and destructive mutation MUST
  be bound to the current incarnation. Clients from an earlier incarnation
  MUST be rejected even if restored counters collide with their old values.
- Recovery MUST invalidate or supersede all previously running operations,
  scan portable manifests and provider inventory, classify differences, and
  repair the index before normal mutation resumes.
- Client registrations, credentials, and operational history MAY require
  separate restoration or re-enrollment; this MUST NOT prevent offline data
  reconstruction.

## Integrity states and operator action

The control plane MUST distinguish at least these conditions:

- `driver_unavailable`: the provider or credential cannot currently be used;
- `unindexed`: a valid recovery manifest or owned object is absent from D1;
- `degraded`: valid data exists but replica policy is not satisfied;
- `missing`: an indexed location is absent while other evidence is available;
- `corrupt`: length, hash, or authenticated-decryption verification failed;
- `key_unavailable`: required root material is not currently available;
- `unsupported_suite`: the inspecting client cannot decode the format;
- `orphan`: provider data cannot yet be associated with a published manifest;
- `quarantined`: suspicious data is retained but cannot be selected for reads;
- `unrecoverable`: all known recovery paths have been exhausted.

The control plane MUST NOT automatically delete data classified as
`key_unavailable`, `unsupported_suite`, ambiguous `orphan`, or `unrecoverable`.
Permanent cleanup MUST require explicit loss acknowledgement, a tombstone, a
grace period, and a final fenced recheck. The audit record SHOULD outlive the
provider object.

The operator UI MUST show the reason, supporting evidence, manifest identity,
root version, locations attempted, last successful verification, available
repair sources, and required manual action.

## Reconciliation and garbage collection

- Reconciliation MUST operate in both directions: D1-to-provider validation
  and provider-to-D1 inventory discovery.
- Newly discovered owned objects MUST enter quarantine before adoption or
  deletion.
- Quarantine deletion MUST require explicit acknowledgement, an exact-revision
  tombstone, a second policy-derived grace period, and a janitor task bound to
  the inventoried driver revision and provider identity.
- Quarantine action retries MUST recover an exact committed receipt without a
  new claim. Completion replay with a changed lease, incarnation, or fencing
  token MUST be rejected, and a recovery-invalidated action MUST remain
  terminal.
- Immediately before deleting a quarantined object, the janitor MUST compare
  provider `Stat` identity and the control plane MUST recheck references,
  recovery sidecars, grace, driver revision, incarnation, role, and fencing.
- A changed or newly referenced quarantined object MUST supersede the prior
  delete authorization without provider I/O.
- Missing or corrupt replicas MUST trigger repair from a separately verified
  replica when policy permits.
- Important archives SHOULD have at least two replicas in independent failure
  domains. Two paths in one provider account do not count as independent.
- Verification MUST include scheduled full ciphertext hashing or authenticated
  reads; metadata-only `stat` checks are not sufficient evidence against bit
  rot.
- GC MUST use mark, grace, and sweep phases. Marking MUST NOT delete payload.
- The sweep phase MUST recheck reachability, revision, incarnation, fencing,
  active leases, and replica policy immediately before deletion.
- A provider delete MUST be idempotent. If its response is lost, the janitor
  MUST re-observe state instead of assuming either success or failure.
- A D1 restore MUST invalidate unfinished GC epochs and delete tasks.

## Observability

- The UI MUST show registered clients, versions, capabilities, health,
  operations, stages, progress, retries, throttling, verification failures,
  current speed, and historical average speeds.
- The UI MUST expose redacted driver statistics, token scopes and annotations,
  and a navigable VFS view with file sizes, directory aggregates, placements,
  integrity roots, and access-policy context.
- Authenticated UI pages MUST start read-only. Entering a mutation-capable
  configuration mode MUST require fresh operator reauthentication, have a
  short absolute lifetime, and be independently revocable.
- CLI and UI configuration changes MUST use the same strict server-side
  schemas, complete desired-state validation, optimistic revisions,
  idempotency identities, redacted audit events, and durable receipts. Client
  validation MUST NOT replace validation inside the commit transaction.
- A management-state change made by any UI, CLI, or SDK client MUST become
  observable to other active UI sessions through a monotonic event cursor.
- Metrics MUST distinguish wire bytes from uniquely verified useful bytes and
  active throughput from wall-clock throughput.
- Telemetry ingestion MUST tolerate duplicate, delayed, and reordered samples
  without affecting operation correctness.
- High-frequency telemetry MUST be isolated from correctness-critical metadata
  writes and compacted into bounded-cardinality time buckets.
- Tokens, keys, credentials, signed URLs, provider paths containing secrets,
  and plaintext data MUST never appear in metric labels or logs.
- Recovery, corruption, replica loss, key unavailability, and manual cleanup
  requirements MUST produce explicit alerts rather than silent state changes.

## Security boundary

- Development and production MUST use distinct Worker names, D1 database
  UUIDs, R2 bucket names, runtime secrets, and administrator credentials.
- The operator UI MUST use one environment-scoped credential without username
  accounts. Browser sessions MUST be random, revocable, time-bounded, and
  represented in D1 only by a one-way verifier. This operator credential MUST
  remain separate from VFS principals, ACLs, and attenuated capability tokens.
- Environment configuration authority MUST NOT imply content plaintext access.
  Normal agents MUST use the operator credential only through the validated
  management CLI and use a separate short-lived attenuated VFS token for file
  operations. The bootstrap all-actions VFS bearer is a recovery authority,
  not an everyday automation credential.
- Deployment tooling MUST reject a configuration that overlaps any dev and
  prod Worker, D1, or R2 identity. The default local configuration MUST NOT be
  remotely routable.
- Production MUST use `carrack.stormbird.xyz`; development MUST use
  `dev.carrack.stormbird.xyz`. Both environments MUST disable workers.dev and
  version preview URLs.
- Public health responses and every operator UI surface MUST identify the
  active environment. Development tokens and provider credentials MUST NOT be
  accepted by production.
- V1 MAY trade narrow key isolation for simplicity and throughput because its
  intended archives are not highly confidential.
- Authentication tokens, provider credentials, and root seeds MUST never be
  committed to Git or stored in plaintext in D1.
- A fully compromised client authorized to restore plaintext is outside the
  V1 confidentiality boundary; Carrack MUST still limit the blast radius of a
  leaked token through namespace permissions, expiry, revocation, and audit.
- Key rotation MUST affect new immutable packs only. Existing packs MUST remain
  decodable until explicitly re-encrypted and republished.

## Verification gate

Production multi-client concurrency, move deletion, and automatic GC MUST
remain disabled until the following tests pass:

- unit, race, fuzz, and property tests for crypto, manifests, state transitions,
  retries, and counters;
- shared Go/Rust golden vectors for every derivation or wire contract used by
  both components;
- provider contract tests with partial reads, wrong ranges, stale listings,
  duplicate responses, throttling, authorization loss, quota exhaustion, and
  success-with-lost-response faults;
- deterministic bounded interleaving tests for competing imports, repairs,
  compactions, restores, moves, lease expiry, and GC;
- crash injection before and after every remote side effect and D1 state
  transition;
- stale-client tests proving that an expired lease or old control-plane
  incarnation cannot publish or delete;
- disaster tests rebuilding a fresh D1 index from only root recovery material,
  portable manifests, and ciphertext;
- corruption tests distinguishing missing key, unsupported suite, missing
  replica, corrupt replica, provider outage, and permanent loss;
- throughput and bounded-memory benchmarks on supported amd64 and arm64 hosts.

The system's safety target is deliberate: retries, crashes, partitions, stale
clients, and provider ambiguity may create duplicate work or retained garbage,
but they MUST NOT cause silent overwrite, false successful restore, or deletion
of the last verified recoverable copy.
