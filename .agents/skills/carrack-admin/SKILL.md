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

3. Inspect each affected collection before deciding on a change:

   ```bash
   carrackctl directory "$directory_id" \
     --control-url "$CARRACK_CONTROL_URL" --format json
   ```

4. Read the exact ACL or placement revision with `carrackctl vfs acl show`
   or `carrackctl vfs placement show` before a policy mutation.
5. State the intended complete desired state and affected resource IDs.

Read [references/commands.md](references/commands.md) when selecting a command
or handling a failure.

## Keep credentials separate

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
driver state, ACL, placement, child-token issue, and child-token revocation:

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

For driver enable or disable, run `carrackctl driver enable|disable` with
`--check` first. Review the exact revision, placement and available-location
counts, and every server warning. Then repeat with the same desired state and a
stable idempotency key. Enabling a local-filesystem driver additionally probes
the configured root from the agent host before server validation. A successful
apply is not complete until the CLI re-reads the management snapshot and
matches the receipt.

Register a driver with `carrackctl driver register` and `--check` before
apply. Registration is typed, creates revision 1 in the disabled state, and
never accepts credentials in the non-secret config. For Aliyun Drive, then run
`carrackctl driver credential set` with `--check`, using a private regular
JSON file readable only by its owner, and apply the same file before enabling
the driver. The only accepted Aliyun credential is `access_token`; refresh
tokens remain unsupported until Carrack can durably CAS a rotated refresh
token back into its encrypted envelope. Review `credential_expires_at` during
validation and in the re-read snapshot. Rotate before expiry; never wait for a
filesystem operation to discover an expired credential. An interactive OAuth
broker is an out-of-band operator input, never an automatic Carrack runtime
dependency. Never put a provider secret in argv, stdout, a plan, or Git.

`carrackctl vfs token issue` may only attenuate the authenticated parent. It
cannot change principals or widen directory, action, driver, or expiry scope.
Capture its one-time bearer directly into the approved secret store and redact
command output from logs. Use `carrackctl vfs token revoke` for revocation.

Do not claim support for principal or group lifecycle or global settings until
the installed CLI exposes their validated commands. Report the missing surface
instead of editing D1, calling Wrangler D1 directly, or crafting HTTP.

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

## Finish

Return the effective resource revision, durable receipt identity when present,
and a redacted summary of the final state. Mention validation warnings and
correctness-preserving driver fallbacks. Never include bearer values,
credentials, key envelopes, signed URLs, or secret provider paths.
