# Carrack Management Plane V1

## Purpose

The management plane gives humans and agents one complete, auditable view of
Carrack without putting payload bytes, plaintext directory keys, bearer
secrets, or provider credentials in the browser or Worker responses. The Web
UI and `carrackctl` are two clients of the same server-side read models,
validation rules, optimistic revisions, and mutation receipts.

The management plane is not a second authorization system. VFS tokens continue
to authorize filesystem and payload operations. Operator authentication
authorizes environment configuration and does not implicitly grant
`content.read`.

## Information architecture

The authenticated UI has six stable destinations:

| Destination | Primary question |
|---|---|
| Overview | Is Carrack healthy, safe, and moving data? |
| Files | What collections and complete files exist in the VFS? |
| Drivers | Where is data stored and what can each driver do? |
| Access | Which principals and tokens can perform which actions? |
| Activity | What is running or recently changed? |
| Settings | What environment-wide policy is currently effective? |

Overview is a concise operational landing page. It must not duplicate the
complete driver, token, or filesystem tables. Files is a navigable directory
browser with canonical names, logical sizes, integrity state, and driver
locations. Directory headers show recursive logical bytes, file and child
counts, Merkle root, encryption suite, active key epoch, placements, and ACL
inheritance. Driver and token details link back to the affected collections.

Driver rows show identity, kind, enabled state, revision, capabilities,
configured non-secret fields, credential presence, provider-declared expiry,
rotation age, placement
count, complete object count, encoded bytes, integrity state, and last use.
Provider credentials are never returned. A missing legacy expiry is shown as
unknown, credentials expiring within 24 hours are warned, and expired
credentials are shown as errors. The environment-owned `r2-default` signing
parent is provisioner-only: the UI shows its redacted readiness but exposes no
credential input or rotation action. Unsupported acceleration features are
shown as warnings with the correctness-preserving fallback and a recommended
replacement driver when one exists.

Token rows show a human label and note, principal, root collection, explicit
actions, optional driver scope, optional snapshot, parent, creation and expiry,
revocation state, and last use. The bearer is shown exactly once at issuance
and never appears in list or detail responses.

## Read mode and configuration mode

Every authenticated UI screen starts in read mode. Read mode may navigate,
filter, copy non-secret identifiers, and export redacted JSON. It cannot reveal
credentials or submit mutations.

Selecting **Enable changes** requires the operator credential again. A
successful reauthentication creates a separate HttpOnly, SameSite=Strict,
Secure configuration session with a maximum lifetime of 15 minutes and an
absolute expiry visible in the UI. It is scoped to management mutations and is
revoked on logout. Closing configuration mode revokes it immediately.

Configuration controls use review-before-apply:

1. Edit a local draft without changing server state.
2. Validate the complete desired object on the client.
3. Send the desired object and observed revision to the server validation API.
4. Show the normalized diff, warnings, affected objects, and server validation
   digest.
5. Require an explicit apply action.
6. Submit the same desired object, observed revision, idempotency key, and
   validation digest.
7. Revalidate inside the commit transaction and return a durable receipt.

The server rejects unknown fields, invalid identifiers, unknown driver kinds,
unsupported capability requirements, secret-looking values in non-secret
configuration, missing credentials, self-escalating token scopes, stale
revisions, expired validation digests, and any normalized request different
from the validated request. Client validation improves UX but never replaces
server validation.

Aliyun credential validation also requires a canonical three-segment access
token with a positive, unexpired JWT `exp` claim. The expiry is persisted next
to the encrypted envelope and returned only as non-secret metadata. Provider
authorization remains authoritative when Carrack first uses the credential;
the control plane never treats the unverified JWT claim as proof of access.

## Configuration resources

V1 exposes versioned configuration resources rather than one unstructured
global document:

- driver instances and encrypted credential rotations;
- filesystem state and defaults;
- directory placement policy and ACL inheritance;
- principals, direct groups, and direct ACL grants;
- token issuance, metadata, and revocation;
- retention, verification, and GC policy;
- named release channels and snapshot publication policy.

Each resource has a monotonic revision. Collection replacements are complete
desired-state replacements, not ambiguous patches. Secret inputs use dedicated
write-only fields and are never echoed in validation results, receipts, audit
details, logs, or later reads.

## Operator credential and VFS root token

Carrack does not require a permanent everyday root bearer token.
`CARRACK_ADMIN_TOKEN` is the environment's break-glass operator credential. It
authenticates short-lived browser or CLI management sessions and must remain in
the host secret store, never in arguments, Git, shell history, or agent output.

The bootstrap VFS token remains a recovery and authority anchor because VFS
attenuation is rooted in its immutable parent chain. Normal automation must
use short-lived child tokens with exact directory, action, driver, and expiry
scope. The bootstrap bearer should be kept offline after provisioning. A Hawk
agent that needs configuration authority uses `carrackctl`; an agent that
needs file access receives a separate attenuated VFS token. Combining these
credentials is an explicit exceptional workflow.

## Agent-safe CLI

`carrackctl` is non-interactive and JSON-first. Every command accepts
`--control-url`; credentials are read from `CARRACK_OPERATOR_CREDENTIAL` or a
private file descriptor, never a command-line flag. The implemented operator
commands are:

```text
carrackctl snapshot
carrackctl watch
carrackctl directory <directory-id>
carrackctl token annotate <token-id>
carrackctl driver register <driver-id>
carrackctl driver credential set <driver-id>
carrackctl driver enable <driver-id>
carrackctl driver disable <driver-id>
carrackctl quota set directory <directory-id>
carrackctl quota set driver <driver-id>
```

Mutation commands accept explicit desired-state flags. Server validation
returns normalized desired state, warnings, affected counts, the observed
revision, and a short-lived validation digest. Apply requires that digest, the
exact observed revision, and an idempotency key. `--check` performs client and
server validation without applying. `--format json` emits stable schemas and
no decorative text; warnings go to structured output, not ad-hoc stderr
strings.

Quota replacement uses the same validate/apply protocol. Directory policies
set nullable `max_file_bytes`, `max_logical_bytes`, and `max_file_count` fields;
driver policies set nullable `max_physical_bytes` and `max_object_count` fields.
Null means unlimited. UI and CLI display the independent quota revision and
must re-read the committed policy after apply. Put intents are the server-owned
reservations, so filesystem clients never implement quota accounting or GC.

Driver registration and enablement are fail-closed by kind. Registration
normalizes a typed non-secret configuration and creates a disabled revision-1
driver. `local-filesystem/v2` requires an exact `{root}` configuration, no
credential, a canonical absolute root, and a successful local probe from the
CLI host. `aliyundrive-open/v2` accepts only its documented endpoint, drive,
root-folder, and upload-part fields; its write-only refresh authorization is
sealed with AES-256-GCM and is never returned. The control plane exchanges and
renews access tokens with fenced CAS updates. `r2/v1` accepts an exact
`{endpoint,bucket,prefix,managed}` configuration. Managed instances are bound
to the current environment's `carrack-payload-dev` or `carrack-payload-prod`
bucket; external instances may use another Cloudflare R2 bucket. Its write-only
credential is `{access_key_id,secret_access_key}`. For `r2-default`, only the
environment provisioner may submit that object; ordinary UI and agent flows may
use it only for additional operator-owned R2 instances. Validation performs a
temporary PUT and DELETE before commit, and VFS clients receive only
object-scoped signed URLs valid for at most 15 minutes. Uploads at or above
100 MiB use a private resumable multipart journal and bounded concurrent part
grants; large downloads use concurrent signed ranges. The server records every
R2 Put grant and, after an unpublished intent expires, aborts any multipart
upload and idempotently removes the object. CLI and filesystem SDK APIs expose
no GC controls. Disablement is allowed even
when placements or available locations exist, but those counts and warnings
are covered by the signed validation. Disabling does not delete locations or
provider objects; it makes them unavailable through that driver until a later
validated enablement.

The CLI treats any local validation, authorization, server validation,
revision, transport, or receipt mismatch as failure. It verifies every
response schema, identity, revision, validation digest, and receipt before
reporting success. Configuration mutations also re-read the redacted effective
snapshot and require it to match the receipt before printing success. Every
failure writes exactly one `carrack.cli-error.v1` JSON object to stderr. Its
string `code` and numeric `exit_status` carry the same stable classification:

| Exit status | Code | Agent action |
|---:|---|---|
| `2` | `invalid_arguments` | Correct the command before retrying. |
| `3` | `invalid_input` | Correct or replace the local input. |
| `4` | `invalid_control_plane` | Select a canonical HTTPS control URL. |
| `5` | `sdk_upgrade_required` | Upgrade before any further operation. |
| `6` | `invalid_control_plane_response` | Stop; do not trust or mutate through this peer. |
| `7` | `permission_denied` | Obtain the intended narrower authority. |
| `8` | `not_found` | Re-read state and verify the environment and identity. |
| `9` | `revision_conflict` | Re-read, decide again, and use a new idempotency key. |
| `10` | `request_rejected` | Inspect the bounded server message; do not blind-retry. |
| `11` | `control_plane_transport_error` | Retry only with the same idempotency key and desired state. |
| `12` | `management_verification_failed` | Treat the outcome as ambiguous and reconcile by readback. |
| `13` | `internal_output_error` | Stop because the structured result was not emitted safely. |
| `14` | `missing_environment` | Inject the named private input without placing it in argv. |
| `15` | `unsupported_suite` | Upgrade or select a supported directory crypto suite. |
| `16` | `corrupt_ciphertext` | Preserve evidence; retry another verified location if available. |
| `17` | `corrupt_plaintext` | Stop; never publish or consume the destination. |
| `18` | `provider_unavailable` | Retry the same immutable operation with bounded backoff. |
| `19` | `permanent_loss` | Reconcile replicas and report durable loss; blind retry cannot repair it. |

Status `0` remains the only success status. No other nonzero value is part of
the Carrack CLI contract.

## Change observation

Every successful mutation appends a redacted VFS audit event in the same D1
transaction. The event ID is the global management cursor. The UI polls a
small indexed cursor endpoint every 15 seconds while visible, refreshes on
window focus, and pauses while hidden. When the
cursor advances outside the current browser mutation, TanStack Query
invalidates only affected resources and shows a snackbar naming the source and
resource when available.

`carrackctl watch --after <cursor> --limit <1..250>` uses the same cursor and
returns one ascending, bounded JSON event page. The page pins the current
server high-water mark and reports `next_after` plus `has_more`; agents consume
all pages, then persist only the last successfully processed cursor. A cursor
ahead of the selected environment fails closed instead of silently switching
streams. V1 does not require WebSockets, a Durable Object, or a resident CLI
process. The cursor protocol can later back SSE or WebSocket delivery without
changing event identity.

## Races and failure handling

Carrack uses optimistic concurrency for management state. It does not hold a
lock while a human reviews a draft or an agent plans a change. Validation does
not reserve state. Apply succeeds only if every observed resource revision is
still current; otherwise it returns `409` with no partial mutation.

An ambiguous apply is replayed with the identical canonical request and
idempotency key. A stale revision requires a fresh read, a new decision, a new
validation digest, and a new idempotency key. GC is not used to resolve
metadata races. GC remains necessary only for unreachable immutable provider
objects, expired staging objects, tombstoned locations, and obsolete catalog
artifacts after their grace periods.

## Skill contract

The repository-owned Carrack management skill must teach agents to:

- inspect current state before proposing a change;
- keep configuration and content credentials separate;
- create a complete desired-state document;
- run local plus server validation;
- review normalized diffs and warnings;
- apply only with an exact revision and validation digest;
- verify the durable receipt and re-read effective state;
- replay ambiguous outcomes exactly, but never blindly retry conflicts;
- avoid printing, persisting, or committing secret inputs.

The skill must call the CLI rather than reconstructing HTTP requests. Protocol
schemas and validation remain executable code and tests, not prose that an
agent is expected to reproduce.
