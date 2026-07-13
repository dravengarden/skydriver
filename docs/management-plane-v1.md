# Carrack Management Plane V1

## Purpose

The management plane gives humans and agents one complete, auditable view of
Carrack without putting payload bytes, plaintext directory keys, bearer
secrets, or provider credentials in the browser or Worker responses. The Web
UI and `carrack admin` CLI are two clients of the same server-side read models,
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
configured non-secret fields, credential presence and rotation age, placement
count, complete object count, encoded bytes, integrity state, and last use.
Provider credentials are never returned. Unsupported acceleration features are
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
agent that needs configuration authority uses `carrack admin`; an agent that
needs file access receives a separate attenuated VFS token. Combining these
credentials is an explicit exceptional workflow.

## Agent-safe CLI

`carrack admin` is non-interactive and JSON-first. Every command accepts
`--control-url`; credentials are read from `CARRACK_OPERATOR_CREDENTIAL` or a
private file descriptor, never a command-line flag. Commands support:

```text
carrack admin status
carrack admin export
carrack admin watch --after <event-id>
carrack admin driver list|show|validate|apply|disable|rotate-credential
carrack admin filesystem list|show|validate|apply
carrack admin directory stat|list
carrack admin token list|show|issue|revoke|annotate
carrack admin acl show|validate|apply
carrack admin placement show|validate|apply
carrack admin settings show|validate|apply
```

Mutation input defaults to a JSON or YAML desired-state file. `validate`
returns normalized desired state, warnings, diff, observed revision, and a
short-lived validation digest. `apply` requires that digest, the exact observed
revision, and an idempotency key. `--check` performs client and server
validation without applying. `--format json` emits stable schemas and no
decorative text; warnings go to structured output, not ad-hoc stderr strings.

Exit status is stable: `0` success, `2` local validation failure, `3` server
validation failure, `4` authorization failure, `5` revision conflict, and `6`
ambiguous transport outcome requiring exact idempotent replay. The CLI verifies
every response schema, identity, revision, validation digest, and receipt before
reporting success.

## Change observation

Every successful mutation appends a redacted VFS audit event in the same D1
transaction. The event ID is the global management cursor. The UI polls a
small conditional endpoint while visible and backs off while hidden. When the
cursor advances outside the current browser mutation, TanStack Query
invalidates only affected resources and shows a snackbar naming the source and
resource when available.

`carrack admin watch` uses the same cursor and returns bounded event pages. V1
does not require WebSockets or a Durable Object. The cursor protocol can later
back an SSE or WebSocket transport without changing event identity.

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
