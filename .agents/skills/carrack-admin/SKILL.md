---
name: carrack-admin
description: Inspect Carrack drivers, virtual filesystems, collections, files, token scopes, ACLs, placements, and management state through the validated Carrack CLI. Use when an agent must audit Carrack, explain effective access or storage, prepare a configuration change, apply a supported VFS policy mutation, verify an external UI or CLI change, or recover from a revision conflict without exposing credentials.
---

# Carrack Admin

Use `carrack admin` and `carrack vfs`; do not reconstruct management HTTP
requests. Treat CLI response validation and server validation as mandatory
parts of the protocol.

## Inspect first

1. Resolve the intended control-plane environment explicitly.
2. Read the redacted management snapshot as JSON:

   ```bash
   carrack admin snapshot --control-url "$CARRACK_CONTROL_URL" --format json
   ```

3. Inspect each affected collection before deciding on a change:

   ```bash
   carrack admin directory "$directory_id" \
     --control-url "$CARRACK_CONTROL_URL" --format json
   ```

4. Read the exact ACL or placement revision before a supported policy mutation.
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
driver state, ACL, and placement changes:

1. Read current state and its exact revision.
2. Build the complete desired replacement locally.
3. Validate every identifier, action, role, driver, uniqueness constraint, and
   scope before invoking the CLI.
4. Use a stable idempotency key for exactly one canonical request.
5. Submit the exact observed revision.
6. Verify the returned schema, resource identity, final revision, policy, and
   durable state.
7. Re-read effective state with `carrack admin` or the matching `carrack vfs`
   read command.

For a token label or operator note, run `carrack admin token annotate` with
`--check` first. Review the normalized label, note, exact metadata revision,
expiry, and warnings. Then repeat the same desired state without `--check`.
The CLI enables a short configuration session, applies the signed validation,
and verifies the receipt against a fresh management snapshot.

For driver enable or disable, run `carrack admin driver enable|disable` with
`--check` first. Review the exact revision, placement and available-location
counts, and every server warning. Then repeat with the same desired state and a
stable idempotency key. Enabling a local-filesystem driver additionally probes
the configured root from the agent host before server validation. A successful
apply is not complete until the CLI re-reads the management snapshot and
matches the receipt.

Register a driver with `carrack admin driver register` and `--check` before
apply. Registration is typed, creates revision 1 in the disabled state, and
never accepts credentials in the non-secret config. For Aliyun Drive, then run
`carrack admin driver credential set` with `--check`, using a private regular
JSON file readable only by its owner, and apply the same file before enabling
the driver. The only accepted Aliyun credential is `access_token`; refresh
tokens remain unsupported until Carrack can durably CAS a rotated refresh
token back into its encrypted envelope. Never put a provider secret in argv,
stdout, a plan, or Git.

Do not claim support for principal management, groups, token authority changes,
or global settings until the installed CLI exposes their `validate` and
`apply` commands. Report the missing surface instead of editing D1, calling
Wrangler D1 directly, or crafting HTTP.

## Handle races and ambiguous outcomes

- Replay an ambiguous transport outcome only with the byte-identical desired
  state and idempotency key.
- On `409`, re-read state. Do not retry with the old revision or silently merge
  policy. Make a new decision and use a new idempotency key.
- Treat an invalid or unexpected receipt as failure even when HTTP returned 2xx.
- Never use GC to resolve a metadata race. GC is for unreachable immutable
  provider objects after grace and reachability checks.

## Finish

Return the effective resource revision, durable receipt identity when present,
and a redacted summary of the final state. Mention validation warnings and
correctness-preserving driver fallbacks. Never include bearer values,
credentials, key envelopes, signed URLs, or secret provider paths.
