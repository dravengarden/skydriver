# Skydriver management commands

## Authentication

| Surface | Environment variable | Authority |
|---|---|---|
| `skydriverctl snapshot`, `metrics`, `analytics`, `watch`, `directory`, `driver`, `quota`, `token annotate` | `SKYDRIVER_OPERATOR_ACCOUNT`, `SKYDRIVER_OPERATOR_CREDENTIAL` | Redacted environment management |
| `skydriverctl vfs acl`, `vfs mount`, `vfs token` | `SKYDRIVER_VFS_TOKEN` | Explicit token actions and directory scope |

`SKYDRIVER_OPERATOR_ACCOUNT` is a canonical non-secret lowercase identifier.
Both credentials are canonical unpadded base64url values encoding 32 bytes;
keep them out of argv and output.

Development uses `draven@skydriver-dev`; production uses
`draven@skydriver-prod`. Operator password rotation is outside `skydriverctl` and
must use the dedicated stdin-only `just rotate-operator-dev` or
production-gated recipe. Those commands update only `SKYDRIVER_ADMIN_TOKEN`.
Never change a VFS master key, wrapped directory key, bootstrap token, or
recovery authority as part of an account or password change.

## Read commands

```bash
skydriverctl snapshot --control-url "$SKYDRIVER_CONTROL_URL" --format json
skydriverctl metrics global all --control-url "$SKYDRIVER_CONTROL_URL" --format json
skydriverctl metrics driver "$driver_id" --control-url "$SKYDRIVER_CONTROL_URL" --format json
skydriverctl metrics token "$token_id" --control-url "$SKYDRIVER_CONTROL_URL" --format json
skydriverctl metrics directory "$directory_id" --control-url "$SKYDRIVER_CONTROL_URL" --format json
skydriverctl analytics --days 30 --group-by driver \
  --control-url "$SKYDRIVER_CONTROL_URL" --format json
skydriverctl analytics --days 7 --driver "$driver_id" --token "$token_id" \
  --directory "$directory_id" --include-descendants --direction download \
  --control-url "$SKYDRIVER_CONTROL_URL" --format json
skydriverctl watch --after "$event_cursor" --limit 100 \
  --control-url "$SKYDRIVER_CONTROL_URL" --format json
skydriverctl directory "$directory_id" --control-url "$SKYDRIVER_CONTROL_URL" --format json
skydriverctl access show --control-url "$SKYDRIVER_CONTROL_URL" --format json
skydriverctl inventory --control-url "$SKYDRIVER_CONTROL_URL" --format json
skydriverctl inventory --refresh-driver "$driver_id" \
  --control-url "$SKYDRIVER_CONTROL_URL" --format json
skydriverctl vfs acl show /collection --control-url "$SKYDRIVER_CONTROL_URL" --format json
skydriverctl vfs mount show /collection --control-url "$SKYDRIVER_CONTROL_URL" --format json
```

The admin snapshot contains only redacted driver configuration and non-secret
token metadata. It never contains provider credentials, token bearers, token
verifiers, directory keys, or plaintext file bytes.

`inventory` returns aggregate bounded-scan and quarantine state. Managed R2
and Aliyun Drive run server-side; the latter uses only its sealed and
automatically renewed access authority. Local filesystem inventory remains an
agent-host capability and therefore reports `unsupported` in this control-
plane view. Never treat quarantine as deletion authorization.
`--refresh-driver` only schedules the named enabled hosted driver for the next
bounded server Cron pass; it never lists or deletes provider objects from the
agent process. Verify `next_scan_at`, then re-read later to observe completion.

`metrics` returns up to 400 days of sampled daily rollups. Use `global all` for
the environment total. Rates are estimates derived from completed transfers;
zero rows means no sampled completion, not zero provider availability. The
command is read-only and must not be used as a transfer correctness signal.

`analytics` retains driver, token, directory, and direction in the same sampled
aggregate, so its filters may be intersected. Use at most one `--group-by`
dimension per query. Hourly results are retained for 45 days and daily results
for 400 days; `--interval auto` selects the safe available grain. Directory
descendants mean the directory's current active subtree. Results remain
estimates and are never authorization, integrity, quota, or billing evidence.

`watch` returns one ascending audit page with schema
`skydriver.management.events.v1`; it is deliberately bounded and does not stay
resident. Start from a snapshot's `event_cursor`, process every event in order,
and continue with `next_after` while `has_more` is true. Persist only a cursor
whose events were handled successfully. A `409` for an ahead cursor usually
means the wrong environment was selected or metadata was restored; stop and
reconcile rather than resetting to zero automatically.

## Existing mutation commands

Create and manage principals and filesystem groups with server validation:

```bash
skydriverctl access principal create --kind service --display-name "$name" \
  --control-url "$SKYDRIVER_CONTROL_URL" --check --format json
skydriverctl access group create "$filesystem_id" --name "$name" \
  --control-url "$SKYDRIVER_CONTROL_URL" --check --format json
skydriverctl access group add-member "$group_id" "$principal_id" \
  --filesystem-id "$filesystem_id" --expected-revision "$group_revision" \
  --control-url "$SKYDRIVER_CONTROL_URL" --check --format json
```

After review, repeat the byte-identical desired state without `--check` and
with a stable idempotency key. Use `principal update --state disabled` instead
of deletion. Re-read `access show` after every apply.

Bootstrap or recover the unexpired root authority without stdout exposure:

```bash
skydriverctl authority recover --output-file "$private_new_path" \
  --control-url "$SKYDRIVER_CONTROL_URL" --format json
```

Replace one complete hard-quota policy. Omitted limits mean unlimited; first
use `--check`, then repeat with a stable idempotency key:

```bash
skydriverctl quota set directory "$directory_id" \
  --control-url "$SKYDRIVER_CONTROL_URL" \
  --max-logical-bytes 107374182400 \
  --max-file-count 100000 \
  --max-file-bytes 10737418240 \
  --expected-revision "$quota_revision" \
  --check --format json

skydriverctl quota set driver "$driver_id" \
  --control-url "$SKYDRIVER_CONTROL_URL" \
  --max-physical-bytes 107374182400 \
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
skydriverctl driver register "$driver_id" \
  --control-url "$SKYDRIVER_CONTROL_URL" \
  --kind aliyundrive-open/v2 \
  --config-file "$config_file" \
  --check --format json
```

Apply the same config with a stable idempotency key. The resulting driver is
revision 1 and disabled:

```bash
skydriverctl driver register "$driver_id" \
  --control-url "$SKYDRIVER_CONTROL_URL" \
  --kind aliyundrive-open/v2 \
  --config-file "$config_file" \
  --idempotency-key "$idempotency_key" --format json
```

Set or rotate its write-only credential before enabling it:

```bash
chmod 600 "$credential_file"
skydriverctl driver credential set "$driver_id" \
  --control-url "$SKYDRIVER_CONTROL_URL" \
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
Do not register or manually rotate that identity. During environment creation,
use `just check-r2-dev` and then `SKYDRIVER_PROVISION_R2=1 just provision-r2-dev`
with separately injected `CLOUDFLARE_TOKEN_FACTORY_API_TOKEN`,
`SKYDRIVER_OPERATOR_CREDENTIAL`, and `SKYDRIVER_VFS_TOKEN`. The provisioner reads
the committed `SKYDRIVER_OPERATOR_ACCOUNT` from the selected environment.
Production also
requires `SKYDRIVER_PROVISION_PROD=1`. The setup tool creates or rolls only the
deterministically named, exact-bucket Cloudflare token, moves its derived S3
credential through a private temporary file, calls the same `skydriverctl`
validate/apply/readback commands, and enables the driver. It adds a root
placement only when the existing complete set is empty. Never copy the factory
token into `.env`, the UI, D1, Worker secrets, argv, or logs.

If preflight reports `recover`, stop and exclude every parallel provisioner.
Only an explicitly reviewed recovery may set `SKYDRIVER_RECOVER_R2_TOKEN=1` and
pass `--recover-existing-token`; ordinary retries must never roll a provider
token merely because Skydriver currently reports no sealed credential.

For an additional R2 bucket, register this configuration first:

```json
{"endpoint":"https://ACCOUNT_ID.r2.cloudflarestorage.com","bucket":"third-party-bucket","prefix":"skydriver/","managed":false}
```

The server validates each key with a temporary object and stores it sealed;
never print or commit either file. R2 multipart journals and abandoned-object
cleanup are internal. The built-in driver's server cleanup uses the Worker
binding and does not depend on the signing key. Agents should retry the same
VFS Put idempotency key and staging directory to resume; never manually list,
complete, abort, or delete multipart uploads through provider tools.

Validate a token annotation without changing state:

```bash
skydriverctl token annotate "$token_id" \
  --control-url "$SKYDRIVER_CONTROL_URL" \
  --label "$label" \
  --note "$note" \
  --expected-revision "$metadata_revision" \
  --check \
  --format json
```

After reviewing the server-normalized desired state, apply the same input:

```bash
skydriverctl token annotate "$token_id" \
  --control-url "$SKYDRIVER_CONTROL_URL" \
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
skydriverctl driver disable "$driver_id" \
  --control-url "$SKYDRIVER_CONTROL_URL" \
  --expected-revision "$driver_revision" \
  --check \
  --format json
```

Review the returned placement count, available-location count, expiry, and all
warnings. Apply the exact transition with a stable idempotency key:

```bash
skydriverctl driver disable "$driver_id" \
  --control-url "$SKYDRIVER_CONTROL_URL" \
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
skydriverctl vfs acl replace /collection \
  --control-url "$SKYDRIVER_CONTROL_URL" \
  --principal-id "$principal_id" \
  --action directory.list,content.read \
  --expected-revision "$acl_revision" \
  --idempotency-key "$idempotency_key" \
  --format json
```

Actions are a comma-separated complete replacement. Omit `--action` to clear
that principal's direct grants.

Mount a driver at one empty directory after reading its mount revision:

```bash
skydriverctl vfs mount set /collection \
  --control-url "$SKYDRIVER_CONTROL_URL" \
  --driver local-main \
  --expected-revision "$placement_revision" \
  --idempotency-key "$idempotency_key" \
  --format json
```

Remove an explicit mount by inheriting the parent driver:

```bash
skydriverctl vfs mount inherit /collection \
  --control-url "$SKYDRIVER_CONTROL_URL" \
  --expected-revision "$placement_revision" \
  --idempotency-key "$idempotency_key" \
  --format json
```

The selected driver must be enabled and registered. The target must be empty
when its effective driver changes, nested mounts are rejected, and the token
must have unscoped `driver.manage` authority. The root uses `mount set` to
change its default and cannot use `mount inherit`.

Issue an attenuated child token:

```bash
skydriverctl vfs token issue /collection \
  --control-url "$SKYDRIVER_CONTROL_URL" \
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
skydriverctl vfs token revoke "$token_id" \
  --control-url "$SKYDRIVER_CONTROL_URL" \
  --idempotency-key "$idempotency_key" --format json
```

Garbage collection has no CLI command. It is scheduled, fenced, revalidated,
and executed by the control plane. A missing cleanup surface is intentional;
never substitute direct D1, raw provider HTTP, OpenList, or a provider CLI.

## Failure decisions

Both `skydriver` and `skydriverctl` emit one `skydriver.cli-error.v1` object on
stderr. Prefer its stable string `code`; its `exit_status` field exactly
matches the process status. Statuses are `2` invalid arguments, `3` invalid
input, `4` invalid control plane, `5` required SDK upgrade, `6` invalid server
response, `7` permission denied, `8` not found, `9` revision conflict, `10`
other rejection, `11` transport failure, `12` failed management readback,
`13` output failure, `14` missing private environment input, `15` unsupported
suite, `16` corrupt ciphertext, `17` corrupt plaintext, `18` provider
unavailable, and `19` permanent loss. Never treat an undocumented
nonzero status as success or infer that a mutation was not committed.

| Condition | Action |
|---|---|
| Local input rejection | Fix desired state before any request |
| HTTP 401/403 | Stop; obtain correct, narrower authority through approved secret handling |
| HTTP 409 | Re-read, decide again, validate again, and use a new idempotency key |
| Lost response | Replay the identical request and idempotency key |
| Malformed or mismatched receipt | Treat as failure and do not claim mutation success |
| Missing CLI mutation surface | Stop; do not bypass the CLI with D1 or raw HTTP |
