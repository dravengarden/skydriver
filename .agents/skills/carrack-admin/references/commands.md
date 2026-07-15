# Carrack management commands

## Authentication

| Surface | Environment variable | Authority |
|---|---|---|
| `carrackctl snapshot`, `directory`, `driver`, `quota`, `token annotate` | `CARRACK_OPERATOR_CREDENTIAL` | Redacted environment management |
| `carrackctl vfs acl`, `vfs placement`, `vfs token` | `CARRACK_VFS_TOKEN` | Explicit token actions and directory scope |

Both credentials are canonical unpadded base64url values encoding 32 bytes.
Keep them out of argv and output.

## Read commands

```bash
carrackctl snapshot --control-url "$CARRACK_CONTROL_URL" --format json
carrackctl directory "$directory_id" --control-url "$CARRACK_CONTROL_URL" --format json
carrackctl vfs acl show /collection --control-url "$CARRACK_CONTROL_URL" --format json
carrackctl vfs placement show /collection --control-url "$CARRACK_CONTROL_URL" --format json
```

The admin snapshot contains only redacted driver configuration and non-secret
token metadata. It never contains provider credentials, token bearers, token
verifiers, directory keys, or plaintext file bytes.

## Existing mutation commands

Replace one complete hard-quota policy. Omitted limits mean unlimited; first
use `--check`, then repeat with a stable idempotency key:

```bash
carrackctl quota set directory "$directory_id" \
  --control-url "$CARRACK_CONTROL_URL" \
  --max-logical-bytes 107374182400 \
  --max-file-count 100000 \
  --max-file-bytes 10737418240 \
  --expected-revision "$quota_revision" \
  --check --format json

carrackctl quota set driver "$driver_id" \
  --control-url "$CARRACK_CONTROL_URL" \
  --max-physical-bytes 1099511627776 \
  --max-object-count 1000000 \
  --expected-revision "$quota_revision" \
  --idempotency-key "$idempotency_key" --format json
```

Directory limits cover the complete subtree across drivers. Driver limits
cover retained physical objects plus live put reservations. Lowering a limit
never deletes data. The control plane rejects new reservations until effective
usage is below every applicable hard limit.

Register a typed driver in the disabled state. Validate first:

```bash
carrackctl driver register "$driver_id" \
  --control-url "$CARRACK_CONTROL_URL" \
  --kind aliyundrive-open/v2 \
  --config-file "$config_file" \
  --check --format json
```

Apply the same config with a stable idempotency key. The resulting driver is
revision 1 and disabled:

```bash
carrackctl driver register "$driver_id" \
  --control-url "$CARRACK_CONTROL_URL" \
  --kind aliyundrive-open/v2 \
  --config-file "$config_file" \
  --idempotency-key "$idempotency_key" --format json
```

Set or rotate its write-only credential before enabling it:

```bash
chmod 600 "$credential_file"
carrackctl driver credential set "$driver_id" \
  --control-url "$CARRACK_CONTROL_URL" \
  --credential-file "$credential_file" \
  --expected-revision "$driver_revision" \
  --check --format json
```

After reviewing the redacted validation, repeat without `--check` and add a
stable idempotency key. The credential file must be a private regular JSON file
containing exactly `{ "refresh_token": "...", "refresh_issuer":
"openlist-online/v1" }`. Never pass the token in argv, print it, or commit the
file. The refresh token must be JWT-shaped and contain an unexpired `exp`
claim. Apply exchanges and validates it with the provider before committing.
Confirm the final snapshot reports a `ready` refresh state, a last successful
refresh time, and `credential_refresh_token_expires_at`. Thereafter the control
plane owns all access-token generation and renewal; only repeat this command if
the server reports `reauth_required`.

Dev and production materialize the disabled `r2-default` identity automatically.
Do not register or edit that identity. Read its current revision from
`carrackctl snapshot`, then connect the environment bucket's private
credential file:

```json
{"access_key_id":"...","secret_access_key":"..."}
```

Run `carrackctl driver credential set r2-default --check` first, apply with the
same private file and a stable idempotency key, re-read the snapshot, then
validate and enable the next exact driver revision. Add directory placement
only after enablement succeeds.

For an additional R2 bucket, register this configuration first:

```json
{"endpoint":"https://ACCOUNT_ID.r2.cloudflarestorage.com","bucket":"third-party-bucket","prefix":"carrack/","managed":false}
```

The server validates each key with a temporary object and stores it sealed;
never print or commit either file. R2 multipart journals and abandoned-object
cleanup are internal. The built-in driver's server cleanup uses the Worker
binding and does not depend on the signing key. Agents should retry the same
VFS Put idempotency key and staging directory to resume; never manually list,
complete, abort, or delete multipart uploads through provider tools.

Validate a token annotation without changing state:

```bash
carrackctl token annotate "$token_id" \
  --control-url "$CARRACK_CONTROL_URL" \
  --label "$label" \
  --note "$note" \
  --expected-revision "$metadata_revision" \
  --check \
  --format json
```

After reviewing the server-normalized desired state, apply the same input:

```bash
carrackctl token annotate "$token_id" \
  --control-url "$CARRACK_CONTROL_URL" \
  --label "$label" \
  --note "$note" \
  --expected-revision "$metadata_revision" \
  --idempotency-key "$idempotency_key" \
  --format json
```

The CLI re-authenticates into a short configuration session and verifies the
committed receipt against a fresh snapshot. This command changes descriptive
metadata only; it cannot expand token actions, directory scope, driver scope,
or expiry.

Validate a driver state transition without changing state:

```bash
carrackctl driver disable "$driver_id" \
  --control-url "$CARRACK_CONTROL_URL" \
  --expected-revision "$driver_revision" \
  --check \
  --format json
```

Review the returned placement count, available-location count, expiry, and all
warnings. Apply the exact transition with a stable idempotency key:

```bash
carrackctl driver disable "$driver_id" \
  --control-url "$CARRACK_CONTROL_URL" \
  --expected-revision "$driver_revision" \
  --idempotency-key "$idempotency_key" \
  --format json
```

Use `enable` in both commands to enable a disabled driver. Enabling supports
only driver kinds whose stored redacted configuration has a strict server-side
validator. For `local-filesystem/v2`, the CLI also opens the configured root on
the agent host before requesting validation. Disabling preserves locations and
objects; they remain recorded but unavailable through that driver until it is
enabled again.

Replace one principal's direct ACL grants:

```bash
carrackctl vfs acl replace /collection \
  --control-url "$CARRACK_CONTROL_URL" \
  --principal-id "$principal_id" \
  --action directory.list,content.read \
  --expected-revision "$acl_revision" \
  --idempotency-key "$idempotency_key" \
  --format json
```

Actions are a comma-separated complete replacement. Omit `--action` to clear
that principal's direct grants.

Replace the complete placement set:

```bash
carrackctl vfs placement replace /collection \
  --control-url "$CARRACK_CONTROL_URL" \
  --placement local-main:0,archive-backup:10 \
  --expected-revision "$placement_revision" \
  --idempotency-key "$idempotency_key" \
  --format json
```

Priorities and driver IDs must each be unique. Every driver must be enabled and
registered. The token must have unscoped `driver.manage` authority.

Issue an attenuated child token:

```bash
carrackctl vfs token issue /collection \
  --control-url "$CARRACK_CONTROL_URL" \
  --action directory.list,content.read \
  --driver-id local-main \
  --expires-at "$expires_at" \
  --idempotency-key "$idempotency_key" \
  --format json
```

Move the returned bearer directly into its intended secret store, then clear
the process output. The server stores only its verifier.

Revoke it with:

```bash
carrackctl vfs token revoke "$token_id" \
  --control-url "$CARRACK_CONTROL_URL" \
  --idempotency-key "$idempotency_key" --format json
```

Garbage collection has no CLI command. It is scheduled, fenced, revalidated,
and executed by the control plane. A missing cleanup surface is intentional;
never substitute direct D1, raw provider HTTP, OpenList, or a provider CLI.

## Failure decisions

| Condition | Action |
|---|---|
| Local input rejection | Fix desired state before any request |
| HTTP 401/403 | Stop; obtain correct, narrower authority through approved secret handling |
| HTTP 409 | Re-read, decide again, validate again, and use a new idempotency key |
| Lost response | Replay the identical request and idempotency key |
| Malformed or mismatched receipt | Treat as failure and do not claim mutation success |
| Missing CLI mutation surface | Stop; do not bypass the CLI with D1 or raw HTTP |
