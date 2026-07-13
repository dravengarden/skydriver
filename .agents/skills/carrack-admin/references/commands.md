# Carrack management commands

## Authentication

| Surface | Environment variable | Authority |
|---|---|---|
| `carrack admin` | `CARRACK_OPERATOR_CREDENTIAL` | Redacted environment management |
| `carrack vfs` | `CARRACK_VFS_TOKEN` | Explicit token actions and directory scope |

Both credentials are canonical unpadded base64url values encoding 32 bytes.
Keep them out of argv and output.

## Read commands

```bash
carrack admin snapshot --control-url "$CARRACK_CONTROL_URL" --format json
carrack admin directory "$directory_id" --control-url "$CARRACK_CONTROL_URL" --format json
carrack vfs acl show "$directory_id" --control-url "$CARRACK_CONTROL_URL" --format json
carrack vfs placement list "$directory_id" --control-url "$CARRACK_CONTROL_URL" --format json
```

The admin snapshot contains only redacted driver configuration and non-secret
token metadata. It never contains provider credentials, token bearers, token
verifiers, directory keys, or plaintext file bytes.

## Existing mutation commands

Validate a token annotation without changing state:

```bash
carrack admin token annotate "$token_id" \
  --control-url "$CARRACK_CONTROL_URL" \
  --label "$label" \
  --note "$note" \
  --expected-revision "$metadata_revision" \
  --check \
  --format json
```

After reviewing the server-normalized desired state, apply the same input:

```bash
carrack admin token annotate "$token_id" \
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
carrack admin driver disable "$driver_id" \
  --control-url "$CARRACK_CONTROL_URL" \
  --expected-revision "$driver_revision" \
  --check \
  --format json
```

Review the returned placement count, available-location count, expiry, and all
warnings. Apply the exact transition with a stable idempotency key:

```bash
carrack admin driver disable "$driver_id" \
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
carrack vfs acl replace "$directory_id" "$principal_id" \
  --control-url "$CARRACK_CONTROL_URL" \
  --role viewer \
  --expected-acl-revision "$acl_revision" \
  --idempotency-key "$idempotency_key" \
  --format json
```

Use repeated `--action` instead of `--role` for explicit actions. Use `--clear`
to remove all direct grants. Exactly one mode is required.

Replace the complete placement set:

```bash
carrack vfs placement replace "$directory_id" \
  --control-url "$CARRACK_CONTROL_URL" \
  --placement local-main=0 \
  --placement archive-backup=10 \
  --expected-placement-revision "$placement_revision" \
  --idempotency-key "$idempotency_key" \
  --format json
```

Priorities and driver IDs must each be unique. Every driver must be enabled and
registered. The token must have unscoped `driver.manage` authority.

Issue an attenuated child token:

```bash
carrack vfs token issue "$root_directory_id" \
  --control-url "$CARRACK_CONTROL_URL" \
  --action directory.list \
  --action content.read \
  --driver-id local-main \
  --expires-at "$expires_at" \
  --idempotency-key "$idempotency_key" \
  --format json
```

Move the returned bearer directly into its intended secret store, then clear
the process output. The server stores only its verifier.

## Failure decisions

| Condition | Action |
|---|---|
| Local input rejection | Fix desired state before any request |
| HTTP 401/403 | Stop; obtain correct, narrower authority through approved secret handling |
| HTTP 409 | Re-read, decide again, validate again, and use a new idempotency key |
| Lost response | Replay the identical request and idempotency key |
| Malformed or mismatched receipt | Treat as failure and do not claim mutation success |
| Missing CLI mutation surface | Stop; do not bypass the CLI with D1 or raw HTTP |
