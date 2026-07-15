---
name: carrack-admin
description: Inspect Carrack drivers, virtual filesystems, collections, files, token scopes, ACLs, placements, and management state through the validated Carrack CLI. Use when an agent must audit Carrack, explain effective access or storage, prepare a configuration change, apply a supported VFS policy mutation, verify an external UI or CLI change, or recover from a revision conflict without exposing credentials.
---

# Carrack Admin

Use `carrackctl`; do not reconstruct management HTTP requests. Treat local
schema checks, server validation, compatibility fail-fast, and receipt
verification as mandatory parts of the protocol. The public `carrack` binary
is only for filesystem data operations.

## Inspect first

1. Resolve the intended control-plane environment explicitly.
2. Read the redacted management snapshot as JSON:

   ```bash
   carrackctl snapshot --control-url "$CARRACK_CONTROL_URL" --format json
   ```

3. When observing changes after that snapshot, pass its `event_cursor` into a
   bounded event read:

   ```bash
   carrackctl watch --after "$event_cursor" --limit 100 \
     --control-url "$CARRACK_CONTROL_URL" --format json
   ```

   Process events in returned order. While `has_more` is true, repeat with
   `next_after`; persist a cursor only after every event through it has been
   handled successfully. This command returns one page and never leaves an
   agent-owned watcher running.
4. Inspect each affected collection before deciding on a change:

   ```bash
   carrackctl directory "$directory_id" \
     --control-url "$CARRACK_CONTROL_URL" --format json
   ```

5. Read the exact ACL or placement revision with `carrackctl vfs acl show`
   or `carrackctl vfs placement show` before a policy mutation.
6. State the intended complete desired state and affected resource IDs.

Read [references/commands.md](references/commands.md) when selecting a command
or handling a failure.

## Keep credentials separate

- Read the non-secret canonical account from `CARRACK_OPERATOR_ACCOUNT`.
  Dev and production currently use `draven`; do not guess a different account
  from a URL, token label, or local username.
- Read `CARRACK_OPERATOR_CREDENTIAL` only from the environment or an approved
  private secret injection. Never pass it in argv, print it, persist it in a
  plan, or write it to Git.
- Use the operator credential for redacted environment management only.
- Use `CARRACK_VFS_TOKEN` for VFS content or supported VFS policy operations.
- Never assume management authority includes `content.read`.
- Treat the bootstrap all-actions VFS bearer as offline recovery authority.
  Request a short-lived attenuated token for normal work.

## Apply supported changes

For token annotation, typed driver registration, write-only driver credential,
driver state, directory or driver quota, principal/group lifecycle, group
membership, ACL, placement, child-token issue, and child-token revocation:

1. Read current state and its exact revision.
2. Build the complete desired replacement locally.
3. Validate every identifier, action, role, driver, uniqueness constraint, and
   scope before invoking the CLI.
4. Use a stable idempotency key for exactly one canonical request.
5. Submit the exact observed revision.
6. Verify the returned schema, resource identity, final revision, policy, and
   durable state.
7. Re-read effective state with the matching `carrackctl` read command.

For a token label or operator note, run `carrackctl token annotate` with
`--check` first. Review the normalized label, note, exact metadata revision,
expiry, and warnings. Then repeat the same desired state without `--check`.
The CLI enables a short configuration session, applies the signed validation,
and verifies the receipt against a fresh management snapshot.

For quota changes, use `carrackctl quota set directory|driver --check` first.
Treat omitted limits as an intentional unlimited value because quota updates
replace the complete policy. Directory limits cover the complete subtree
across placements; driver limits cover non-deleted physical objects and live
put reservations. Never lower a limit expecting Carrack to delete data.

For driver enable or disable, run `carrackctl driver enable|disable` with
`--check` first. Review the exact revision, placement and available-location
counts, and every server warning. Then repeat with the same desired state and a
stable idempotency key. Enabling a local-filesystem driver additionally probes
the configured root from the agent host before server validation. A successful
apply is not complete until the CLI re-reads the management snapshot and
matches the receipt.

Register a driver with `carrackctl driver register` and `--check` before
apply. Registration is typed, creates revision 1 in the disabled state, and
never accepts credentials in the non-secret config. The environment-owned
`r2-default` is the exception: it is materialized by the server and must not be
registered or edited. Its initial physical-byte hard quota is 100 GiB; inspect
the independent quota revision and use the normal validated quota command when
the environment needs a different limit. Its signing parent is owned by the
one-time environment provisioner; do not paste, rotate, or request it through
the UI or ordinary agent workflow. The provisioner still uses the same
validate/apply/readback CLI protocol internally. For Aliyun
Drive, then run `carrackctl driver credential set` with `--check`, using a
private regular JSON file readable only by its owner, and apply the same file
before enabling the driver. Aliyun authorization input contains only `refresh_token` and
`refresh_issuer` set to `openlist-online/v1`. Carrack verifies the refresh
authority with the provider, generates access tokens internally, encrypts the
complete internal bundle, and projects only access grants to filesystem SDKs.
Review `credential_refresh_state`, `credential_refresh_last_succeeded_at`, and
`credential_refresh_token_expires_at` in the re-read snapshot. A
`reauth_required` state requires a new OAuth refresh token through this same
validated command. Never put a provider secret in argv, stdout, a plan, or Git.

`carrackctl vfs token issue` may only attenuate the authenticated parent. It
cannot change principals or widen directory, action, driver, or expiry scope.
Capture its one-time bearer directly into the approved secret store and redact
command output from logs. Use `carrackctl vfs token revoke` for revocation.

Use `carrackctl access show` before principal or group changes. Principal
deletion is deliberately unsupported: disable a principal under its exact
revision to reject all of its tokens immediately. Group creation, rename,
membership add/remove, and deletion use the same signed validation,
configuration reauthentication, idempotent receipt, and readback protocol.
Use `carrackctl vfs acl replace --group-id` only after the group exists in the
same filesystem as the directory.

Bootstrap and recover root authority only with `carrackctl authority` and a
new path inside an owner-private directory. The CLI writes mode 0600 and emits
only a redacted receipt. Never open, print, parse into a plan, or copy that file
unless an approved VFS operation needs secret injection.

## Handle races and ambiguous outcomes

- Replay an ambiguous transport outcome only with the byte-identical desired
  state and idempotency key.
- On `409`, re-read state. Do not retry with the old revision or silently merge
  policy. Make a new decision and use a new idempotency key.
- Treat an invalid or unexpected receipt as failure even when HTTP returned 2xx.
- Garbage collection is entirely server-internal. Never enumerate candidates,
  claim cleanup work, request provider delete credentials, or delete a hosted
  provider object with either CLI. Preserve suspicious objects for control-
  plane reconciliation or operator investigation.
- `carrackctl inventory` is a redacted aggregate view of the bounded hosted
  scan. Managed R2 and Aliyun Drive are scanned by the control plane; local
  filesystems report an explicit agent-host fallback. Quarantine is evidence,
  never permission for an agent to adopt or delete provider objects.

## Finish

Return the effective resource revision, durable receipt identity when present,
and a redacted summary of the final state. Mention validation warnings and
correctness-preserving driver fallbacks. Never include bearer values,
credentials, key envelopes, signed URLs, or secret provider paths.
