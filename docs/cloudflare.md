# Cloudflare operations

Carrack uses a scoped account API token, not an interactive Wrangler browser
session. Copy `.env.example` to the gitignored `.env`, set mode `0600`, and
provide `CLOUDFLARE_API_TOKEN` plus `CLOUDFLARE_ACCOUNT_ID`. Entering
`nix develop` exports those values.

The token needs only the account permissions required by Carrack:

- Workers Scripts: Edit
- D1: Edit
- Account Settings: Read, only when required by Wrangler identity checks

Carrack has one initial D1 database, `carrack-index`. Its public database UUID
is committed in `control-plane/wrangler.jsonc`; credentials and Worker runtime
secrets are never committed.

Carrack also uses the `carrack-manifests` R2 bucket for small portable recovery
metadata. Create the production and preview buckets once before the first
deployment:

```bash
pnpm exec wrangler r2 bucket create carrack-manifests
pnpm exec wrangler r2 bucket create carrack-manifests-preview
```

The R2 binding never carries payload extents. SDK clients upload those directly
to their selected storage drivers.

Apply migrations before deploying:

```bash
pnpm exec wrangler d1 migrations apply carrack-index \
  --remote \
  --config control-plane/wrangler.jsonc
```

Administrator usernames and Argon2id password hashes live in the
`admin_users` D1 table. Plaintext passwords never enter D1. Keep the generated
operator password in a gitignored `0600` file on the host that owns the
account.

Set the session signing key through Wrangler:

```bash
pnpm exec wrangler secret put CARRACK_SESSION_KEY \
  --config control-plane/wrangler.jsonc

pnpm exec wrangler secret put CARRACK_ROOT_KEY_V1 \
  --config control-plane/wrangler.jsonc
```

`CARRACK_SESSION_KEY` must be an independently generated high-entropy value.
`CARRACK_ROOT_KEY_V1` must be the unpadded base64url encoding of exactly 32
random bytes with a tested offline recovery copy. Add a new versioned binding
for rotation; never replace an old root while published manifests reference it.
Account provisioning is an operator action performed after the D1 migration;
do not commit password hashes as migration seed data.

Build and deploy only after the repository gate passes:

```bash
just verify
pnpm exec wrangler deploy --config control-plane/wrangler.jsonc
```

After deployment, verify `/api/health`, sign in with the preset account, and
confirm `/api/summary` can read the migrated D1 database.

## Integrity findings

The authenticated dashboard polls open integrity findings every 15 seconds. It
shows the server-projected namespace, manifest and root-key identities, provider
location, last successful verification, independently available repair sources,
raw evidence, and the required conservative operator action. `REPAIRABLE` is a
server decision: it is set only for a currently missing location with at least
one other available location for the same extent. It does not start a repair.

Operators and diagnostic clients can read the same projection directly:

```text
GET /api/integrity/findings?state=open&condition=missing&limit=50
```

The endpoint requires an administrator session. `state` defaults to `open` and
accepts `open`, `acknowledged`, `tombstoned`, or `resolved`; `condition` is
optional. The response's `next_cursor` is opaque. Pass it back as `cursor` to
load the next page and do not persist or decode it. A resolved finding remains
queryable for audit, but never reports as repairable after its location has
returned to `available`.

## D1 backup and recovery

D1 Time Travel is a short-window rollback mechanism, not Carrack's only data
recovery source. Export D1 to R2 on a schedule and mirror those exports off the
Cloudflare account. Published portable recovery manifests are also stored in
the manifest R2 bucket and as destination-driver sidecars. Root seeds have a
separate offline backup.

Never restore D1 while mutation traffic is enabled. The recovery sequence is:

1. Set the `CARRACK_MAINTENANCE` Worker secret to `1`. Confirm `/api/health`
   reports `external_maintenance: true` and `mutations_allowed: false`.
2. Record the current Time Travel bookmark or export before overwriting D1.
3. Restore D1 and apply every repository migration newer than the restored
   point.
4. Generate a new random 128-bit lowercase hexadecimal incarnation.
5. Call `POST /api/recovery/begin` with the new `incarnation` and the current
   `expected_revision`. This moves D1 to `recovering` and invalidates all old
   operations, attempts, leases, and GC epochs.
6. Verify the configured root-seed canary, scan the R2 manifest archive and
   destination sidecars, inventory providers, rebuild unindexed metadata, and
   classify every unresolved discrepancy.
7. Call `POST /api/recovery/complete` with the same incarnation and latest
   revision. This changes D1 back to `active`, but external maintenance still
   blocks mutations.
8. Remove or set `CARRACK_MAINTENANCE` to `0`, then verify health and run a
   canary restore before resuming automatic work.

The recovery endpoints require an authenticated administrator session and are
idempotent for the same incarnation. They deliberately require the external
maintenance binding because a D1 rollback can also roll back an in-database
maintenance flag. A client holding a pre-restore lease cannot commit after the
incarnation change even if its old fencing token numerically collides with a
restored counter.

Do not automatically clean up `key_unavailable`, `unsupported_suite`,
ambiguous `orphan`, or `unrecoverable` findings. Permanent cleanup requires an
operator acknowledgement, tombstone, grace period, and final fenced recheck.
