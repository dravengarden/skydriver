# Carrack VFS Put Protocol V1

## Scope

This protocol publishes one local byte sequence as one immutable VFS file
version and one complete provider object. It does not relay payload bytes
through the control plane, split a file across objects, or hold a D1 transaction
while provider I/O runs.

The protocol has three calls:

```text
POST /api/v2/puts/prepare
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

The response uses schema `carrack.vfs.put-preparation.v1`. It allocates an
expiring intent ID, immutable version and location IDs, an existing or new
stable file ID, an authorized driver, a content-addressed block-manifest key,
and a separate random 192-bit provider storage name. Metadata identities are
hyphenless UUIDv7 values; provider names never contain those IDs or virtual
names. An omitted preferred driver selects the lowest active write priority
allowed by both directory placement and token scope.

The idempotency identity covers every request field. Repeating the same request
returns the original allocation. Reusing the key with any changed field returns
`409` and never reallocates storage.

## Transfer and block-manifest staging

After prepare, the Go client obtains short-lived key and provider grants, then
uses the selected compiled driver directly. It must publish the exact encoded
length and SHA-256 to the fresh provider key and satisfy either a trusted strong
provider checksum or complete independent readback. Provider multipart parts
remain transport state and disappear behind one completed object.

The block-manifest call has an
`application/octet-stream` body in the canonical format from
`vfs-merkle-v1.md`. This is control metadata containing plaintext verification
leaf hashes, not file bytes. The Worker requires exact bytes, SHA-256, layout,
block count, recomputed file root, and EOF before a conditional
content-addressed R2 write. A key collision is accepted only when the existing
R2 bytes are identical. The response schema is
`carrack.vfs.block-manifest-stage.v1` and includes the immutable R2 version used
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

Before D1 publication, the Worker re-reads every affected directory, recomputes
its current Merkle root, applies the new file entry locally, then recomputes the
target-to-root chain. A mismatch between stored entries and the current root is
metadata corruption, not a rebase hint.

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

The durable response schema is `carrack.vfs.put-receipt.v1`. Lost-response
replay with the same commit identity returns the original receipt. Changed
provider evidence for the same intent returns `409`.

## Current implementation boundary

The protocol, D1 invariants, Merkle verification, plaintext integration path,
token refresh, create/overwrite flow, idempotent replay, and ACL-revocation
tests are implemented. Directory key-grant and provider credential-grant APIs
are the next layer; until those exist, encrypted directories and real remote
driver transfer cannot be driven solely through these HTTP calls. This staged
boundary does not weaken publication checks or make the control plane a payload
proxy.
