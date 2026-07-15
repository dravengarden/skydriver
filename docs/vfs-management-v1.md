# Carrack VFS Management API V1

## Status and boundary

This document defines the implemented live VFS directory, token, ACL, and
placement-management API. The Cloudflare Worker is the transaction authority;
the canonical Rust `carrack-client`, `carrack`, and `carrackctl` surfaces expose
the supported operations. The Go SDK is retained only as a compatibility and
conformance oracle.

Management requests never carry or relay file payload bytes, provider
credentials, plaintext directory secrets, or provider-object locators. Payload
I/O remains a direct Rust-client-to-driver operation.

The currently implemented management surface is:

| Surface | Worker | Rust client | CLI |
|---|---:|---:|---:|
| Revision-consistent directory listing | Yes | `list_path` | `carrack list` |
| Empty child-directory creation | Yes | `mkdir` | `carrack mkdir` |
| Attenuated child-token issue | Yes | `issue_token` | `carrackctl vfs token issue` |
| Same-principal token revocation | Yes | `revoke_token` | `carrackctl vfs token revoke` |
| Direct ACL inspection and principal replacement | Yes | `acl`, `replace_acl` | `carrackctl vfs acl show`, `carrackctl vfs acl replace` |
| Placement inspection and replace-all | Yes | `placements`, `replace_placements` | `carrackctl vfs placement show`, `carrackctl vfs placement replace` |
| Recursive verified namespace prefetch | Existing directory pages | Filesystem catalog cache | `carrack sync` uses it internally |
| Group membership management | No | No | No |
| Typed driver registration or credential rotation | Operator API | `AdminClient` | `carrackctl driver register`, `carrackctl driver credential set` |
| Snapshot-pinned metadata reads | No | No | No |

These operator-authorized driver mutations are deliberately outside the VFS
token routes documented below. The V2 payload implementation currently has
compiled `local-filesystem/v2`, `aliyundrive-open/v2`, and `r2/v1` drivers.
R2 supports streaming single PUT, resumable multipart upload, concurrent exact
ranges, and server-owned deletion; Aliyun preserves complete objects and exact
range reads while intentionally limiting upload concurrency to one. Google
Drive, generic S3, and WebDAV payload implementations remain later slices.

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
carrackctl acl show "$directory_id" \
  --control-url "$control_url" --format json

carrackctl acl replace "$directory_id" "$principal_id" \
  --control-url "$control_url" \
  --role viewer \
  --expected-acl-revision "$acl_revision" \
  --idempotency-key reader-viewer-v1

carrackctl acl replace "$directory_id" "$principal_id" \
  --control-url "$control_url" \
  --clear \
  --expected-acl-revision "$acl_revision" \
  --idempotency-key reader-clear-v1
```

The CLI requires exactly one of `--role`, one or more `--action`, or `--clear`.

## Placement inspection and replacement

Placement inspection returns non-secret driver identity, kind, driver
revision, write priority, and active/disabled state. It never returns provider
credentials. Both read and replace require a token with `driver.manage` whose
token scope has no driver allowlist. This prevents a driver-scoped token from
using the management API to widen its own view or policy.

Replacement is replace-all, not a patch:

```json
{
  "placements": [
    {"driver_id": "local-main", "write_priority": 0},
    {"driver_id": "archive-backup", "write_priority": 10}
  ],
  "expected_placement_revision": 3,
  "idempotency_key": "placement-primary-backup-v1"
}
```

At least one enabled registered driver is required. Driver IDs and priorities
must each be unique; smaller priorities are preferred. The exact current
`placement_revision` is required, and a concurrent mutation returns `409`.

CLI examples:

```bash
carrackctl placement list "$directory_id" \
  --control-url "$control_url" --format json

carrackctl placement replace "$directory_id" \
  --control-url "$control_url" \
  --placement local-main=0 \
  --placement archive-backup=10 \
  --expected-placement-revision "$placement_revision" \
  --idempotency-key placement-primary-backup-v1
```

Each `--placement` value splits on its final `=` so the priority remains
unambiguous. The complete set must be supplied on every replacement.

Placement policy chooses allowed destinations; it does not promise that every
driver supports every acceleration feature. Before payload I/O, the Go planner
evaluates the selected driver's declared and probed capabilities. Missing
range, resumable, parallel, or strong-checksum acceleration produces a
structured correctness-preserving warning and fallback. A missing correctness
property remains a hard error.

## Race and recovery rules

Carrack does not hold pessimistic locks across management or provider I/O.
Directory, ACL, and placement mutations use short D1 transactions, exact
expected revisions where caller reconciliation is required, immutable
operation IDs, canonical request hashes, and durable receipts.

Callers handle races as follows:

1. Read the current policy and revision.
2. Compute the complete desired replacement locally.
3. Submit one idempotent mutation with the exact observed revision.
4. On an ambiguous network result, replay the identical request and key.
5. On `409`, re-read current state and make a new policy decision with a new
   idempotency key.

GC is not part of these metadata races. Placement replacement does not delete
existing complete file locations. Later reachability analysis and the fenced
server-side lifecycle executor handles abandoned or unreachable provider
objects after a grace period.
