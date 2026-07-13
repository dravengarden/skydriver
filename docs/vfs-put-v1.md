# Carrack VFS Put Protocol V1

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

## Key and driver grants

After prepare, the client requests the directory epoch key and selected driver
instance separately. The key response schema is
`carrack.vfs.directory-key-grant.v1`. An encrypted directory returns one
base64url 256-bit directory key plus the pinned crypto suite, epoch, directory,
version, and intent identities. A `plaintext/v1` directory returns no key. The
client derives the per-version content key locally; the control plane never
receives or relays payload bytes.

The driver response schema is `carrack.vfs.driver-grant.v1`. It returns the
prepared driver ID, compiled versioned kind, configuration revision, strict
non-secret JSON configuration, and an optional decrypted credential JSON value.
The Worker rechecks the token, inherited ACL, directory placement, driver
attenuation, intent state, and expiry before either grant. Grant issuance is
audited without recording key or credential material.

The first compiled V2 kind is `local-filesystem/v2`. Its configuration is
`{"root":"/absolute/client/path"}` and it has no credential grant. The path is
opened by the Go client; the Cloudflare Worker never accesses it.

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
For `carrack-vfs-aes256gcm-hkdfsha256-v1`, the required encoded length is
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

The protocol, D1 invariants, Merkle verification, encrypted and plaintext
local-filesystem paths, token refresh, grants, create/overwrite flow, exact
idempotent replay, and ACL-revocation tests are implemented. The Go SDK exposes
`Put`, `PutFile`, and `PutBytes`; the CLI exposes one-file upload:

```bash
export CARRACK_VFS_TOKEN='<bootstrap or attenuated token>'

carrack vfs put ./release.tar.zst release.tar.zst \
  --control-url https://carrack.example.com \
  --directory-id <directory-id> \
  --preferred-driver-id local-main \
  --idempotency-key release-2026-07-13 \
  --format json
```

Use `-` as `LOCAL_FILE` to spool stdin into a private staging file before
hashing and upload. Journal and encoded staging roots default to private XDG
state and cache directories and can be overridden explicitly.

After the upload journal exists, an SDK transfer or commit error unwraps through
`VFSPutRecoveryError` and carries its `JournalID`. Retry the identical source,
destination, expected revision, and idempotency key with that ID:

```bash
carrack vfs put ./release.tar.zst release.tar.zst \
  --control-url https://carrack.example.com \
  --directory-id <directory-id> \
  --preferred-driver-id local-main \
  --idempotency-key release-2026-07-13 \
  --resume-journal-id <journal-id> \
  --format json
```

Resume reacquires current key and driver grants, revalidates the source,
complete encoded identity, storage key, exact driver descriptor, capability
requirements, and hash-chained journal, then transfers only missing valid
parts. A journal already in `complete` state reuses its verified provider
object and retries only conditional metadata publication. The immutable part
layout in the journal takes precedence over new tuning flags. A journal for a
different staging path, object, or driver is a hard integrity error.

If a process is killed before it can report the ID, discover every local
candidate without a control-plane token:

```bash
carrack vfs journal list --format json
```

The command reads the same XDG state root as Put, validates every immutable plan,
state hash-chain, and progress receipt, and returns stable source, driver,
storage-key, checksum, status, and completed-piece fields. It refuses the whole
listing on an unexpected or corrupt published entry rather than hiding it.
Private temporary directories left before atomic journal publication are
ignored because provider I/O cannot have started yet. Use `--journal-directory`
when Put used a non-default root.

A dedicated durable receipt-recovery API beyond intent lifetime, remote V2
drivers, download, directory synchronization, and catalog-prefetch planning
remain later V2 slices. This boundary does not weaken publication checks or
make the control plane a payload proxy.
