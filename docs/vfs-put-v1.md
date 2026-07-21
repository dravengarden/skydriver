# Skydriver VFS Put Protocol V1

## Scope

This protocol publishes one local byte sequence as one immutable VFS file
version and one complete provider object. It does not relay payload bytes
through the control plane, split a file across objects, or hold a D1 transaction
while provider I/O runs.

The protocol has five calls:

```text
POST /api/v2/puts/prepare
POST /api/v2/puts/{intent_id}/key-grant
POST /api/v2/puts/{intent_id}/driver-grant
POST /api/v2/puts/{intent_id}/block-manifest
POST /api/v2/puts/{intent_id}/commit
```

All calls require a 32-byte base64url VFS bearer token. The token must currently
authorize `content.write` and `driver.use` on the target directory, satisfy its
directory and driver attenuation, and still be allowed by the inherited ACL.
The token used to commit may differ from the short-lived token used to prepare,
but it must bind the same principal. This permits safe credential refresh during
a long or resumed transfer. Token and ACL authority are checked again inside the
final D1 publication transaction.

The key and driver responses use `Cache-Control: no-store` and expire no later
than either the token or Put intent. They are operation grants, not durable
configuration exports. A caller reacquires them after restart and clears the
decoded key and credential bytes from memory as soon as the transform or driver
has been opened. The endpoints remain replayable for an already committed
intent until its expiry so a client that lost the commit response can recover
without persisting secrets.

## Prepare

The JSON request schema is:

```json
{
  "directory_id": "32 lowercase hex",
  "entry_name": "canonical NFC component",
  "expected_entry_revision": 0,
  "plaintext_bytes": 3,
  "verification_block_bytes": 4194304,
  "verification_block_count": 1,
  "file_root": "64 lowercase hex",
  "metadata_root": "64 lowercase hex",
  "block_manifest_sha256": "64 lowercase hex",
  "block_manifest_bytes": 128,
  "encryption_frame_bytes": 4194304,
  "preferred_driver_id": null,
  "idempotency_key": "caller-stable key"
}
```

`expected_entry_revision` is zero only when the name must be absent. A positive
value pins an existing file entry; the control plane also pins its stable file
ID, current version, and file revision. A directory at that name is always a
conflict. The block count and frame alignment must already be canonical.

The response uses schema `skydriver.vfs.put-preparation.v1`. It allocates an
expiring intent ID, immutable version and location IDs, an existing or new
stable file ID, an authorized driver, a content-addressed block-manifest key,
and a separate random 192-bit provider storage name. Metadata identities are
hyphenless UUIDv7 values; provider names never contain those IDs or virtual
names. An omitted preferred driver selects the directory's one effective mount
driver. If supplied, the preferred driver must equal that effective driver and
remain allowed by the token scope.

The idempotency identity covers every request field. Repeating the same request
returns the original allocation. Reusing the key with any changed field returns
`409` and never reallocates storage.

## Key and driver grants

After prepare, the client requests the directory epoch key and selected driver
instance separately and concurrently; neither grant is trusted until its full
intent identity is validated, and each response is bounded to 256 KiB. The key
response schema is `skydriver.vfs.directory-key-grant.v1`. An encrypted directory
returns one base64url 256-bit directory key plus the pinned crypto suite, epoch,
directory, version, and intent identities. A `plaintext/v1` directory returns no key. The
client derives the per-version content key locally; the control plane never
receives or relays payload bytes.

The native async client performs source Merkle hashing and encoded staging on
bounded blocking workers rather than occupying its network executor. Encoded
staging and the authenticated block-manifest request overlap after both grants
validate. A cancellation-safe owner removes any encoded file returned after
the caller future was cancelled; normal resumable staging is disarmed from that
owner and retains the existing retry semantics. Source bytes are hashed again
after staging, and any divergence removes staging and fails before provider I/O.

The driver response schema is `skydriver.vfs.driver-grant.v1`. It returns the
prepared driver ID, compiled versioned kind, configuration revision, strict
non-secret JSON configuration, and an optional decrypted credential JSON value.
The Worker rechecks the token, inherited ACL, directory placement, driver
attenuation, intent state, and expiry before either grant. Grant issuance is
audited without recording key or credential material.

The first compiled V2 kind is `local-filesystem/v2`. Its configuration is
`{"root":"/absolute/client/path"}` and it has no credential grant. The path is
opened by the native client driver; the Cloudflare Worker never accesses it.

## Transfer and block-manifest staging

After prepare, the canonical Rust client obtains short-lived key and provider
grants, then uses the selected compiled driver directly. It must publish the
exact encoded length and SHA-256 to the fresh provider key and satisfy either a
trusted strong provider checksum or complete independent readback. Provider multipart parts
remain transport state and disappear behind one completed object. Publication
uses provider-native atomic no-replace, including multipart completion. A
precondition collision is an idempotent replay only after complete readback
matches both encoded length and SHA-256; a different existing object is never
overwritten. The provider ETag recorded at commit comes from that verified
readback rather than a client-derived fallback.

The block-manifest call has an
`application/octet-stream` body in the canonical format from
`vfs-merkle-v1.md`. This is control metadata containing plaintext verification
leaf hashes, not file bytes. The Worker requires exact bytes, SHA-256, layout,
block count, recomputed file root, and EOF before a conditional
content-addressed R2 write. A key collision is accepted only when the existing
R2 bytes are identical. The response schema is
`skydriver.vfs.block-manifest-stage.v1` and includes the immutable R2 version used
at commit.

## Commit

The JSON request schema is:

```json
{
  "block_manifest_r2_version": "immutable R2 version",
  "encoded_bytes": 3,
  "encoded_sha256": "64 lowercase hex",
  "verification_method": "complete_readback",
  "native_id": null,
  "provider_version": null,
  "etag": null
}
```

`verification_method` is `provider_checksum` or `complete_readback`. It is an
attestation produced only after the Go driver contract has verified the exact
complete object; the control plane deliberately does not open provider payload
objects. Optional provider identities are retained for future pinned reads and
deletes. For `plaintext/v1`, encoded and plaintext lengths must match.
For `skydriver-vfs-aes256gcm-hkdfsha256-v1`, the required encoded length is
exactly:

```text
plaintext_bytes + ceil(plaintext_bytes / encryption_frame_bytes) * 16
```

An empty file remains empty. The Worker independently computes this length and
rejects a caller-supplied value that differs.

Before D1 publication, the Worker re-reads every affected directory, recomputes
its current Merkle root, applies the new file entry locally, then recomputes the
target-to-root chain. A mismatch between stored entries and the current root is
metadata corruption, not a rebase hint.

The Worker first writes immutable upload evidence in its own short D1
transaction. The evidence pins the commit digest, encoded object identity, and
provider identity even if the following optimistic publication loses a race.
An exact retry reuses it; conflicting evidence is rejected.

One D1 batch then:

1. records the expected root/revision evidence for every ancestor;
2. inserts the immutable version and complete-object location;
3. advances both through verified and published/available states;
4. conditionally creates or updates the stable file and target entry;
5. conditionally advances every directory root and child-root entry;
6. appends a catalog revision and pending materialization outbox item;
7. advances the catalog mutation head;
8. inserts an immutable commit receipt; and
9. reauthorizes and marks the put intent committed.

The final database trigger rejects a partial statement set, stale revision,
missing ancestor link, changed placement, revoked token, removed ACL, or receipt
that differs from the published metadata. A failure rolls back the entire
batch. Changes to another entry may cause the Worker to recompute and retry the
root plan up to four times. A change to the same entry fails with `409`; it is
never silently overwritten.

The durable response schema is `skydriver.vfs.put-receipt.v1`. Lost-response
replay with the same commit identity returns the original receipt. Changed
provider evidence for the same intent returns `409`.

## Expired upload deletion

Metadata hygiene expires an uncommitted intent and plans at most one delete
task from its immutable upload evidence after an additional one-day grace. The
task is internal control-plane state and is never exposed to a filesystem
token, SDK, or CLI.

The bounded server lifecycle executor opens only a compiled registered driver,
requires advertised Stat and exact Delete support, and compares storage key,
encoded length, every recorded native ID, provider version, and ETag. At least
one strong provider identity must be present. Only then does final
revalidation rotate the fencing token immediately before `Delete`. Provider
absence is idempotent success; failure releases the claim for retry. A stale
lease, fence, driver revision, new location, publication receipt, or changed
evidence makes provider deletion impossible.

## Current implementation boundary

The D1 invariants, Merkle verification, encrypted and plaintext paths, token
refresh, grants, create/overwrite flow, exact idempotent replay,
ACL-revocation tests, and fenced expired-upload cleanup are implemented by the
Worker and canonical Rust client. The former Go SDK and legacy CLI have been
removed. The supported command is:

```bash
export SKYDRIVER_VFS_TOKEN='<bootstrap or attenuated token>'

skydriver put ./release.tar.zst /releases/release.tar.zst \
  --idempotency-key release-2026-07-13
```

The CLI accepts a canonical local regular file. Applications may use the Rust
client's byte API for in-memory content. Encoded staging defaults to the
private Skydriver state directory and may be overridden with
`--staging-directory`.

Resume is automatic and intentionally has no public journal-management
surface. Retry the identical source, destination, expected revision, placement,
and idempotency key. The client reacquires current key and driver grants,
revalidates the source and complete encoded identity, and lets the typed driver
reuse only verified multipart or range receipts. Changed source or plan
identity is a hard error.

Cleanup is not exposed through the filesystem CLI or SDK. Expired upload
evidence remains durable until the control plane's bounded lifecycle executor
can perform exact Stat, final reachability revalidation, fenced idempotent
Delete, and completion through a capable hosted-driver adapter. Missing exact
delete support is a hard stop, never a weaker client-side delete.

R2 and Aliyun complete-object transfers, download, directory synchronization,
catalog prefetch, replacement reachability, and server-owned expired-upload
cleanup are implemented. None weakens publication checks or makes the control
plane a payload proxy.
