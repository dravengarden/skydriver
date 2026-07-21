# Skydriver VFS Management API V1

## Status and boundary

This document defines the implemented live VFS directory, token, ACL, and
placement-management API. The Cloudflare Worker is the transaction authority;
the canonical Rust `skydriver-client`, `skydriver`, and `skydriverctl` surfaces expose
the supported operations. There is no compatibility SDK or second command
implementation.

Management requests never carry or relay file payload bytes, provider
credentials, plaintext directory secrets, or provider-object locators. Payload
I/O remains a direct Rust-client-to-driver operation.

The currently implemented management surface is:

| Surface | Worker | Rust client | CLI |
|---|---:|---:|---:|
| Revision-consistent directory listing | Yes | `list_path` | `skydriver list` |
| Empty child-directory creation | Yes | `mkdir` | `skydriver mkdir` |
| Attenuated child-token issue | Yes | `issue_token` | `skydriverctl vfs token issue` |
| Same-principal token revocation | Yes | `revoke_token` | `skydriverctl vfs token revoke` |
| Direct ACL inspection and principal replacement | Yes | `acl`, `replace_acl` | `skydriverctl vfs acl show`, `skydriverctl vfs acl replace` |
| Mount inspection and replacement | Yes | `mount`, `set_mount`, `inherit_mount` | `skydriverctl vfs mount show`, `skydriverctl vfs mount set`, `skydriverctl vfs mount inherit` |
| Recursive verified namespace prefetch | Existing directory pages | Filesystem catalog cache | `skydriver sync` uses it internally |
| Principal lifecycle | Yes | `AdminClient::access`, validated access mutation | `skydriverctl access principal` |
| Group lifecycle and membership | Yes | `AdminClient::access`, validated access mutation | `skydriverctl access group` |
| Group ACL replacement | Yes | `replace_group_acl` | `skydriverctl vfs acl replace --group-id` |
| Typed driver registration or credential rotation | Operator API | `AdminClient` | `skydriverctl driver register`, `skydriverctl driver credential set` |
| Snapshot-pinned metadata reads | No | No | No |
| Operator Files browser entry pages | Yes | `AdminClient::directory_entries` | `skydriverctl directory --revision` |

These operator-authorized driver mutations are deliberately outside the VFS
token routes documented below. The V2 payload implementation currently has
compiled `local-filesystem/v2`, `aliyundrive-open/v2`, `r2/v1`, and
`aws-s3/v1` drivers.
R2 supports streaming single PUT, resumable multipart upload, concurrent exact
ranges, and server-owned deletion; Aliyun preserves complete objects and exact
range reads while intentionally limiting upload concurrency to one. Google
Drive, generic S3-compatible, and WebDAV payload implementations remain later
slices. The official AWS adapter is intentionally narrower than generic S3;
see [aws-s3-v1.md](aws-s3-v1.md).

## Common authentication and errors

All routes require:

```http
Authorization: Bearer <unpadded-base64url-32-byte-token>
```

The Worker validates the complete parent-token chain, expiry, revocation,
principal state, subtree scope, action scope, optional driver scope, and the
principal's current inherited ACL. Authority is re-evaluated on every request;
an earlier token cannot preserve a removed ACL grant.

These routes operate on live state. A snapshot-scoped token is rejected rather
than silently reading or mutating the live namespace. Snapshot reads will use a
separate future endpoint.

Common status meanings are:

| Status | Meaning |
|---:|---|
| `400` | Malformed identity, scope, cursor, policy, or unsupported live-token mode |
| `401` | Missing, expired, revoked, invalid, or descendant-of-revoked token |
| `403` | Current token and ACL do not authorize the exact action or driver scope |
| `404` | The requested live identity does not exist |
| `409` | Revision conflict or an idempotency key was reused for different input |

Every mutation uses a caller-selected idempotency key. The key is scoped to the
authorizing token and operation kind. An exact replay returns the durable
receipt; reuse with a different canonical request returns `409`.

## Route summary

| Method and route | Required action | Concurrency input | Result schema |
|---|---|---|---|
| `GET /api/v2/directories/:id/entries` | `directory.list` | Opaque cursor pins directory revision | `carrack.vfs.directory-list.v1` |
| `POST /api/v2/directories/:id/children` | `content.write` | Idempotent exact create | `carrack.vfs.directory-create-receipt.v1` |
| `POST /api/v2/tokens` | `token.issue` | Idempotent attenuation | `carrack.vfs.token-issue-receipt.v1` |
| `POST /api/v2/tokens/:id/revoke` | `token.issue` | Idempotent monotonic revoke | `carrack.vfs.token-revoke-receipt.v1` |
| `GET /api/v2/directories/:id/acl` | `acl.manage` | Returns `acl_revision` | `carrack.vfs.acl.v1` |
| `POST /api/v2/directories/:id/acl/replace` | `acl.manage` | Exact `expected_acl_revision` | `carrack.vfs.policy-mutation-receipt.v1` |
| `GET /api/v2/directories/:id/placements` | Unscoped `driver.manage` | Returns `placement_revision` | `carrack.vfs.placements.v1` |
| `POST /api/v2/directories/:id/placements/replace` | Unscoped `driver.manage` | Exact `expected_placement_revision` | `carrack.vfs.policy-mutation-receipt.v1` |

Actions are exact and non-implying. Administrative actions do not imply
`content.read`, and content actions do not imply management authority.

## Directory listing

```http
GET /api/v2/directories/:id/entries?limit=1000&cursor=<opaque>
```

`limit` defaults on the server and may be from 1 through 1,000. Entries are
ordered canonically. The response includes the directory content root,
namespace revision, ACL revision, placement revision, and one optional opaque
continuation cursor.

The cursor embeds the observed directory revision. The client must pass it
back unchanged. If the directory changes before the next page, the Worker
returns `409` instead of mixing entries from different revisions. Clients that
receive `409` restart from the first page.

## Operator Files browser

The operator console reads directory identity and recursive totals separately
from a bounded, revision-pinned entry stream. The summary request is:

```http
GET /api/admin/directories/:id?entries=false
```

The entry request is:

```http
GET /api/admin/directories/:id/entries?revision=7&prefix=archive-&after_kind=directory&after_name=archive-a&limit=100
```

Pages are ordered by `(kind, name)`, with directories before files, and use an
exclusive keyset cursor. `prefix` is a case-sensitive direct-entry name prefix;
it does not recursively search descendants. The Worker checks the exact active
directory revision both before and after the D1 page query. A concurrent
namespace mutation therefore returns `409` rather than mixing revisions. The
console restarts from the new summary revision.

The page size is from 1 through 250. The Files UI defaults to 100, debounces
prefix changes, and requests more pages only on operator demand. This makes a
directory with more than 1,000 direct entries fully browsable without loading
the entire directory into Worker, browser, or CLI memory. The legacy unpaged
operator directory response remains bounded to 1,000 entries for compatibility
and must not be used to infer that a directory is complete.

## Child-directory creation

```json
{
  "name": "releases",
  "crypto_suite": "carrack-vfs-aes256gcm-hkdfsha256-v1",
  "idempotency_key": "mkdir-releases-v1"
}
```

`crypto_suite` may be omitted to inherit the parent's suite. An encrypted child
always receives a fresh independent directory secret and key epoch; it never
reuses the parent key. The child initially inherits the parent's active
placement set.

The Worker creates the empty child and its parent entry, recomputes every
affected parent-to-root Merkle link, advances the catalog revision, and records
the durable receipt in one short transaction. Concurrent creation of the same
name conflicts. No provider I/O occurs during directory creation.

## Token issue and revocation

Issue request:

```json
{
  "root_directory_id": "<directory-id>",
  "actions": ["content.read", "directory.list"],
  "driver_ids": ["local-main"],
  "expires_at": 2000000000,
  "idempotency_key": "ai-reader-v1"
}
```

The child token keeps the same principal and may only narrow the parent token:

- the root must be the same directory or a descendant;
- actions must be a nonempty subset;
- expiry must be no later than the parent;
- `driver_ids` may narrow a parent allowlist but never widen it;
- omitting `driver_ids` is allowed only when the parent is driver-unrestricted.

The response contains the bearer exactly once and uses
`Cache-Control: no-store, max-age=0`. D1 stores only its SHA-256 verifier. CLI
and SDK callers must move the bearer directly into the intended secret store;
the SDK's `VFSIssuedToken.Clear` erases its in-memory copy.

Revocation targets another token for the same principal. It is monotonic and
immediately invalidates the target's complete descendant chain. A token cannot
revoke itself through this route.

## ACL inspection and replacement

`GET /api/v2/directories/:id/acl` returns only grants written directly on that
directory. Effective authority is still computed dynamically through the
inherited allow-only ACL chain described in `vfs-authorization-v1.md`.

Replacement changes every direct grant for exactly one principal. It is not a
patch. Callers submit either explicit actions:

```json
{
  "principal_id": "<principal-id>",
  "actions": ["content.read", "directory.list"],
  "role": null,
  "expected_acl_revision": 7,
  "idempotency_key": "reader-actions-v1"
}
```

or one fixed role preset:

```json
{
  "principal_id": "<principal-id>",
  "actions": null,
  "role": "viewer",
  "expected_acl_revision": 7,
  "idempotency_key": "reader-viewer-v1"
}
```

An explicit empty `actions` array removes all direct grants for that principal.
Exactly one of `actions` and `role` must be present. A role is expanded into
fixed action rows at commit time; later software changes cannot silently alter
an existing grant. Supported presets are `viewer`, `editor`, `publisher`,
`security_administrator`, `storage_operator`, `janitor`, and
`system_administrator`.

The caller must first read `acl_revision`, then submit that exact value. A
concurrent ACL mutation returns `409`; the caller re-reads policy and decides
whether to retry with a new idempotency key. Revision values are monotonic but
need not increase by exactly one because a replace-all mutation may remove and
insert several rows.

CLI examples:

```bash
skydriverctl acl show "$directory_id" \
  --control-url "$control_url" --format json

skydriverctl acl replace "$directory_id" "$principal_id" \
  --control-url "$control_url" \
  --role viewer \
  --expected-acl-revision "$acl_revision" \
  --idempotency-key reader-viewer-v1

skydriverctl acl replace "$directory_id" "$principal_id" \
  --control-url "$control_url" \
  --clear \
  --expected-acl-revision "$acl_revision" \
  --idempotency-key reader-clear-v1
```

The CLI requires exactly one of `--role`, one or more `--action`, or `--clear`.

## Mount inspection and replacement

Mount inspection returns the non-secret effective driver identity, kind,
revision, and whether it is the root `default`, an explicit `mount`, or
`inherited`. It never returns provider
credentials. Both read and replace require a token with `driver.manage` whose
token scope has no driver allowlist. This prevents a driver-scoped token from
using the management API to widen its own view or policy.

The compatibility wire shape retains one placement entry, but it is now a
single-driver mount operation rather than a preference list:

```json
{
  "placements": [
    {"driver_id": "local-main", "write_priority": 0}
  ],
  "expected_placement_revision": 3,
  "idempotency_key": "placement-primary-backup-v1"
}
```

Exactly one enabled registered driver and priority zero are required. On root,
replacement changes the filesystem default. On a non-root empty directory, a
driver different from the parent's effective driver creates an explicit mount;
selecting the parent driver removes that mount. A mounted subtree cannot contain
another mount. The exact current `placement_revision` is required, and a
concurrent mutation returns `409`.

CLI examples:

```bash
skydriverctl vfs mount show /collection \
  --control-url "$control_url" --format json

skydriverctl vfs mount set /collection \
  --control-url "$control_url" \
  --driver local-main \
  --expected-revision "$placement_revision" \
  --idempotency-key placement-primary-backup-v1

skydriverctl vfs mount inherit /collection \
  --control-url "$control_url" \
  --expected-revision "$placement_revision" \
  --idempotency-key placement-inherit-v1
```

The legacy `vfs placement` spelling remains an alias during migration. Mount
replacement never migrates existing files and therefore requires an empty
target whenever the effective driver changes.

Mount policy chooses one destination; it does not promise that every
driver supports every acceleration feature. Before payload I/O, the Rust planner
evaluates the selected driver's declared and probed capabilities. Missing
range, resumable, parallel, or strong-checksum acceleration produces a
structured correctness-preserving warning and fallback. A missing correctness
property remains a hard error.

## Race and recovery rules

Skydriver does not hold pessimistic locks across management or provider I/O.
Directory, ACL, and mount mutations use short D1 transactions, exact
expected revisions where caller reconciliation is required, immutable
operation IDs, canonical request hashes, and durable receipts.

Callers handle races as follows:

1. Read the current policy and revision.
2. Compute the complete desired replacement locally.
3. Submit one idempotent mutation with the exact observed revision.
4. On an ambiguous network result, replay the identical request and key.
5. On `409`, re-read current state and make a new policy decision with a new
   idempotency key.

GC is not part of these metadata races. Mount replacement does not delete
existing complete file locations. Later reachability analysis and the fenced
server-side lifecycle executor handles abandoned or unreachable provider
objects after a grace period.
