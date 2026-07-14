# Cloudflare operations

Carrack uses a scoped account API token, not an interactive Wrangler browser
session. Copy `.env.example` to the gitignored `.env`, set mode `0600`, and
provide `CLOUDFLARE_API_TOKEN` plus `CLOUDFLARE_ACCOUNT_ID`. Entering
`nix develop` exports those values.

The day-to-day token needs only the account permissions required by Carrack:

- Workers Scripts: Edit
- D1: Edit
- Workers R2 Storage: Edit
- Account Settings: Read, only when required by Wrangler identity checks

Creating or changing the committed custom domains is a separate, rare trigger
operation. It additionally requires `Workers Routes: Edit` for the
`stormbird.xyz` zone. Do not grant that zone permission to the routine deploy
token; use a short-lived setup token or the Cloudflare dashboard, then run the
environment audit.

## Environment isolation

Carrack has explicit `dev` and `prod` environments. Every remotely usable
resource is distinct:

| Environment | Worker | Custom domain | D1 | R2 |
|---|---|---|---|---|
| `dev` | `carrack-control-plane-dev` | `dev.carrack.stormbird.xyz` | `carrack-index-dev` | `carrack-manifests-dev` |
| `prod` | `carrack-control-plane-prod` | `carrack.stormbird.xyz` | `carrack-index-prod` | `carrack-manifests-prod` |

The default Wrangler configuration is local-only. It uses a non-routable D1
sentinel, disables `workers.dev`, and must never be deployed. A remote command
must always select `--env dev` or `--env prod`. `preview_bucket_name` is not an
environment boundary and is deliberately unused.

Remote environments follow Stormbird's hostname hierarchy: production uses
the product hostname and development prefixes that hostname with `dev.`. Both
`workers.dev` and version preview URLs are disabled. The committed Wrangler
configuration records the exact custom domain, DNS record, and certificate
binding, while routine version deployments deliberately leave those stable
routes unchanged. The deploy helper synchronizes only the environment's Cron
schedules through the account-scoped Worker schedules API; it does not use
Wrangler's combined trigger command, which also reads zone routes and would
unnecessarily require `Workers Routes: Edit`.

The public UUIDs and bucket names are committed in
`control-plane/wrangler.jsonc`; credentials and Worker runtime secrets are
never committed. Run the local invariant check through `just test`. After a
remote deployment, verify that no other Worker is bound to either environment:

```bash
just audit-cloudflare
```

Carrack's R2 bindings carry only small portable recovery metadata. Payload
bytes continue to flow directly between SDK clients and their selected storage
drivers.

Create all four storage resources once before the first deployment:

```bash
pnpm exec wrangler d1 create carrack-index-dev
pnpm exec wrangler d1 create carrack-index-prod
pnpm exec wrangler r2 bucket create carrack-manifests-dev
pnpm exec wrangler r2 bucket create carrack-manifests-prod
```

Apply migrations independently before deploying. Never run a remote migration
without an explicit environment:

```bash
just migrate-dev
CARRACK_MIGRATE_PROD=1 just migrate-prod
```

The recipes intentionally use Carrack's import-based migration runner instead
of `wrangler d1 migrations apply --remote`. Wrangler's statement splitter
removes the terminal semicolon from SQLite trigger definitions; D1 then rejects
the incomplete trigger. The Carrack runner imports one migration and its
`d1_migrations` receipt atomically, and verifies that receipt before advancing.

The operator console has no username or account directory. Each environment
uses one independent `CARRACK_ADMIN_TOKEN` Worker secret, following Stormbird's
operator-credential model. A successful login exchanges that credential for a
random 12-hour HttpOnly browser session. D1 stores only the session's SHA-256
verifier; logout deletes it. A 15-minute metadata-hygiene Cron Trigger also
deletes expired operator and configuration sessions, so cleanup does not depend
on a later login.

Set independent operator, archive-root, and VFS-master secrets for each environment:

```bash
pnpm exec wrangler secret put CARRACK_ADMIN_TOKEN \
  --env dev \
  --config control-plane/wrangler.jsonc
pnpm exec wrangler secret put CARRACK_ROOT_KEY_V1 \
  --env dev \
  --config control-plane/wrangler.jsonc
pnpm exec wrangler secret put CARRACK_VFS_MASTER_KEY_V1 \
  --env dev \
  --config control-plane/wrangler.jsonc

pnpm exec wrangler secret put CARRACK_ADMIN_TOKEN \
  --env prod \
  --config control-plane/wrangler.jsonc
pnpm exec wrangler secret put CARRACK_ROOT_KEY_V1 \
  --env prod \
  --config control-plane/wrangler.jsonc
pnpm exec wrangler secret put CARRACK_VFS_MASTER_KEY_V1 \
  --env prod \
  --config control-plane/wrangler.jsonc
```

`CARRACK_ADMIN_TOKEN` must be the unpadded base64url encoding of exactly 32
random bytes. It is an operator credential, not a VFS principal or capability
token, and development and production must never share it.
`CARRACK_ROOT_KEY_V1` must be the unpadded base64url encoding of exactly 32
random bytes with a tested offline recovery copy. Add a new versioned binding
for rotation; never replace an old root while published manifests reference it.
`CARRACK_VFS_MASTER_KEY_V1` is also an unpadded base64url encoding of exactly
32 random bytes, generated independently from both legacy secrets. It seals V2
directory keys and derives the recoverable one-shot bootstrap token. Preserve
the version while either V2 envelopes or the bootstrap receipt depend on it;
see `vfs-bootstrap-v1.md`.

Build and deploy only through the environment-specific recipes. Production
requires an additional explicit acknowledgement:

```bash
just deploy-dev
CARRACK_DEPLOY_PROD=1 just deploy-prod
```

The verification gate also compiles `carrack-sdk-core` for
`wasm32-unknown-unknown`. The deployed Worker exposes the credential-free
`GET /api/acceptance/wasm-sdk` proof: it computes the canonical file Merkle
root, encrypts a deterministic payload into authenticated frames, decrypts it,
and reports both encoded and decoded SHA-256 identities. Deployment acceptance
must call this endpoint and require `round_trip_verified: true`; a native-only
SDK test is insufficient.

Real Aliyun Drive acceptance is intentionally separate from the hermetic gate.
It requires an explicitly scoped dev VFS token and driver ID, writes one random
encrypted object, verifies concurrent exact-range download and interrupted
resume, then logically removes the test file:

```bash
export CARRACK_CONTROL_URL=https://dev.carrack.stormbird.xyz
export CARRACK_VFS_TOKEN='<short-lived dev acceptance token>'
export CARRACK_ALIYUN_DRIVER_ID='<enabled dev Aliyun driver>'
CARRACK_ALIYUN_LIVE_TEST=1 tests/aliyun-live.sh
```

The script never prints credentials, provider locators, or signed URLs. Its
remove verifies namespace deletion; physical deletion remains subject to the
normal server grace and scheduled GC rather than weakening production safety
for a test.

Each recipe uploads a tagged Worker version and then moves 100% of that
environment's traffic to it. It does not rewrite the already-audited custom
domain, so the routine account token does not need zone-wide route mutation
permission. Reconcile an intentional route change separately with a suitably
scoped setup credential.

The stable UI endpoints are:

- `https://dev.carrack.stormbird.xyz`
- `https://carrack.stormbird.xyz`

The workers.dev subdomain and version preview URLs are disabled for both
environments. After deployment, verify that `/api/health` reports the expected
`environment`, sign in with the environment's operator credential, and confirm
`/api/summary` can read only that environment's D1 database.

Deployment and VFS bootstrap are separate operations. Keep a new environment
unbootstrapped until its initial payload-driver topology is decided: bootstrap
is intentionally one-shot. The currently implemented bootstrap creates a
`local-filesystem/v2` driver and placement, while the compiled Aliyun Drive
provider still belongs to the archive-oriented V1 path. Before an Aliyun Drive
V2 canary, implement the complete-object V2 driver plus its registration or a
driver-neutral bootstrap path, then bootstrap `dev` only. Never use `prod` for
provider credential or compatibility experiments.

## Garbage collection

The Worker Cron Trigger performs bounded metadata hygiene and schedules
server-internal lifecycle work. Each run deletes at
most 500 expired rows from each ephemeral session table and moves at most 250
expired V2 Put intents from `prepared` to the durable `expired` state. The
bounds keep one
maintenance invocation from monopolizing D1; later invocations drain any
backlog. When an expired intent has immutable upload evidence, the same
transaction idempotently plans a fenced delete task with an additional one-day
grace. Provider `Stat` and deletion are server-internal and run only through a
typed hosted-driver adapter after final reachability and fence validation.
There is no client or operator GC command. A driver without stable identity,
exact Stat, and idempotent Delete retains its candidates for later retry;
capability and identity errors require investigation, not manual deletion.

Namespace `retention_policy_json` accepts `move_grace_seconds`,
`gc_minimum_age_seconds`, `gc_grace_seconds`, and
`inventory_quarantine_seconds`. GC age defaults to seven days; Move, GC, and
inventory quarantine grace default to one day. Every value must be between 60
seconds and 365 days. An existing operation pins its cutoff and grace, so
changing the namespace cannot change in-flight work.

Run `carrack gc mark` with an `administrator` token. The Worker atomically
selects only complete unreachable provider objects, tombstones their indexed
ranges, records object-grouped delete tasks, and releases the short mark lease.
It does not contact a provider. If no object is eligible, the operation succeeds
with zero candidates.

After grace, run `carrack gc sweep <operation-id>` with a `janitor` or
`administrator` token and the exact local driver configuration. Each task is
claimed and then revalidated immediately before provider deletion. A new active
lease, a newly published reference, a stale incarnation, a changed location
revision, or any non-candidate range sharing the provider object blocks the
task. Provider failure is retained for retry.

Do not schedule these commands automatically yet. The explicit GC protocol is
implemented and tested, but production Cron activation remains subject to the
fault-injection and disaster-recovery gate in `docs/requirements.md`.

## D1 cost and index maintenance

Schema migrations include only indexes tied to production query shapes,
including reverse foreign-key traversal, active directory and file scans,
location lookup, token audit lookup, outbox claiming, snapshot expiry, and
session expiry. `control-plane/tests/vfs-v2-protocol.sh` fails if a required
index disappears. Use `EXPLAIN QUERY PLAN` when adding or changing a query;
avoid an index that has no concrete read or maintenance path because every
index also adds storage and write work.

VFS snapshot reachability adds two bounded reverse indexes: version-to-snapshot
for candidate subtraction, and snapshot-to-token-expiry for protective token
checks. A retained, channel-addressed, or unexpired-token snapshot without a
valid local reachability seal blocks GC for its filesystem. D1 therefore never
fetches snapshot manifests from R2 inside a mark or delete fence and never
treats missing materialization as an empty snapshot.

After applying an index-changing migration to one environment, run
`PRAGMA optimize;` against that same environment so SQLite can refresh planner
statistics. Never run the command against the other environment by accident.
Inspect D1 analytics after representative traffic and remove demonstrably
unused indexes only through a new append-only migration.

## Provider inventory

Run `carrack reconcile inventory` with an `administrator` token, the exact
registered local driver ID and root, and a dedicated Carrack-owned prefix. The
SDK lists only regular files under that prefix in bounded pages and maintains a
renewable operation fence through final report commit. Unknown objects are
retained in quarantine for the pinned `inventory_quarantine_seconds`; absent
indexed objects produce findings for a later Verify or Repair decision.
Provider adapters normalize pagination to strictly increasing storage keys;
duplicate or regressed pages are rejected, while a stale omission remains only
conservative evidence and can converge on the next full scan.

Inventory is deliberately read-only. It does not adopt provider objects,
change manifest or location state, or invoke provider deletion. Do not overlap
owned prefixes across namespaces: an unknown object already quarantined for a
different namespace rejects completion instead of guessing ownership. Cron
scheduling and adoption remain disabled pending their own fenced protocols and
production fault-injection gates.

After the integrity console's `quarantine_until`, use `carrack quarantine
acknowledge` with the displayed quarantine revision and a durable review reason.
Then use `carrack quarantine tombstone` with the newly acknowledged revision to
start a second `inventory_quarantine_seconds` grace. Both commands require an
`administrator` client token and reject stale object, driver, provider-version,
ETag, size, revision, incarnation, or lease identities. Their audit records and
integrity findings remain in D1.

A D1 write that makes a matching location non-deleted or recovery sidecar
non-missing immediately resolves the quarantine finding, supersedes any pending,
claimed, or failed delete task, and records the reference in the audit log. An
older janitor fence then fails revalidation without provider I/O; this safeguard
does not depend on waiting for another inventory pass.

These review commands do not delete provider bytes. Tombstoning creates a task
that remains ineligible until `delete_after`. Run the explicit local-filesystem
janitor only after that deadline:

```bash
export CARRACK_CONTROL_TOKEN="$(read-janitor-token)"

carrack quarantine sweep <tombstone-operation-id> \
  --control-url https://carrack.example.com \
  --local-driver-id local-archive \
  --local-root /srv/carrack/archive
```

The token needs the `janitor` or `administrator` role. The SDK requires exact
provider `Stat` identity before asking D1 to rotate the fence and repeat grace,
driver-revision, reference, recovery-sidecar, incarnation, and role checks. It
then invokes the idempotent driver delete and records either `deleted` or
`already_absent`. A changed provider identity fails the task without deletion.
Do not schedule this command automatically yet; the explicit protocol is
implemented, but the production fault-injection gate remains outstanding.

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
