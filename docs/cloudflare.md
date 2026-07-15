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

It deliberately does not have `Account API Tokens: Write`. Default R2 setup uses
a separate, short-lived account-owned `CLOUDFLARE_TOKEN_FACTORY_API_TOKEN`.
Create it under **Manage account > Account API tokens** with only **Entire
Account > Account API Tokens: Write** and a short TTL. A user-owned **Create
additional tokens** credential is not the same authority and cannot inspect or
create the account-owned bucket tokens used here. Do not put the factory token
in `.env`, a Worker secret, the UI, or D1. Supply it only to the one-time
environment provision command, then revoke it and remove it from the process
environment. Cloudflare documents both this required bootstrap authority and
the recommendation to keep it free of unrelated permissions:
<https://developers.cloudflare.com/fundamentals/api/how-to/create-via-api/>.

Creating or changing the committed custom domains is a separate, rare trigger
operation. It additionally requires `Workers Routes: Edit` for the
`stormbird.xyz` zone. Do not grant that zone permission to the routine deploy
token; use a short-lived setup token or the Cloudflare dashboard, then run the
environment audit.

## Environment isolation

Carrack has explicit `dev` and `prod` environments. Every remotely usable
resource is distinct:

| Environment | Worker | Custom domain | D1 | Metadata R2 | Default payload R2 |
|---|---|---|---|---|---|
| `dev` | `carrack-control-plane-dev` | `dev.carrack.stormbird.xyz` | `carrack-index-dev` | `carrack-manifests-dev` | `carrack-payload-dev` |
| `prod` | `carrack-control-plane-prod` | `carrack.stormbird.xyz` | `carrack-index-prod` | `carrack-manifests-prod` | `carrack-payload-prod` |

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
never committed. Run the local invariant check through `just test`. After
migration, deployment, and the one-time default R2 provisioning described
below, verify both resource isolation and the enabled `r2-default` profile with
its current operator-configurable hard quota in D1:

```bash
just audit-cloudflare
```

`CARRACK_MANIFESTS` carries only immutable control metadata: verification-block
manifests plus full and delta catalog artifacts. It never stores user payload
bytes.
`CARRACK_PAYLOAD` gives server-side lifecycle and reconciliation code access to
the environment's built-in payload bucket. Payload bytes still flow directly
between SDK clients and storage; the Worker never relays file bodies.

Create all six isolated storage resources once before the first deployment:

```bash
pnpm exec wrangler d1 create carrack-index-dev
pnpm exec wrangler d1 create carrack-index-prod
pnpm exec wrangler r2 bucket create carrack-manifests-dev
pnpm exec wrangler r2 bucket create carrack-manifests-prod
pnpm exec wrangler r2 bucket create carrack-payload-dev
pnpm exec wrangler r2 bucket create carrack-payload-prod
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

The operator console requires the committed canonical account
`CARRACK_OPERATOR_ACCOUNT=draven` plus one independent
`CARRACK_ADMIN_TOKEN` Worker secret per environment. The account is a
non-secret login identity, not an additional authentication factor or account
directory. A successful login exchanges the exact account and credential for a
random 12-hour HttpOnly browser session. D1 stores only the session's SHA-256
verifier; logout deletes it. A 15-minute metadata-hygiene Cron Trigger also
deletes expired operator and configuration sessions, so cleanup does not depend
on a later login.

Set independent operator and VFS-master secrets for each environment:

```bash
pnpm exec wrangler secret put CARRACK_ADMIN_TOKEN \
  --env dev \
  --config control-plane/wrangler.jsonc
pnpm exec wrangler secret put CARRACK_VFS_MASTER_KEY_V1 \
  --env dev \
  --config control-plane/wrangler.jsonc

pnpm exec wrangler secret put CARRACK_ADMIN_TOKEN \
  --env prod \
  --config control-plane/wrangler.jsonc
pnpm exec wrangler secret put CARRACK_VFS_MASTER_KEY_V1 \
  --env prod \
  --config control-plane/wrangler.jsonc
```

`CARRACK_ADMIN_TOKEN` must be the unpadded base64url encoding of exactly 32
random bytes. It is an operator credential, not a VFS principal or capability
token, and development and production must never share it.
`CARRACK_VFS_MASTER_KEY_V1` is also an unpadded base64url encoding of exactly
32 random bytes, generated independently from the operator credential. It seals V2
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

The managed R2 acceptance uses the same safety boundary but defaults to a
128 MiB random payload and eight concurrent 8 MiB parts so the real multipart,
range, resume, hash, and logical-removal paths are exercised:

```bash
export CARRACK_CONTROL_URL=https://dev.carrack.stormbird.xyz
export CARRACK_VFS_TOKEN='<short-lived dev acceptance token>'
CARRACK_R2_LIVE_TEST=1 tests/r2-live.sh
```

This live test is opt-in and is not part of `just verify`; the hermetic gate
checks its shell contract only.

Each recipe uploads a tagged Worker version and then moves 100% of that
environment's traffic to it. It does not rewrite the already-audited custom
domain, so the routine account token does not need zone-wide route mutation
permission. After the traffic move, the recipe polls the custom domain with a
deployment-tagged cache buster and succeeds only when health reports the exact
environment, the Worker WASM SDK round trip verifies, and the served UI asset
has the same SHA-256 as the locally verified build. This bounded retry absorbs
ordinary edge propagation while failing closed on a stale Worker, wrong route,
or partial asset rollout. Reconcile an intentional route change separately
with a suitably scoped setup credential.

The stable UI endpoints are:

- `https://dev.carrack.stormbird.xyz`
- `https://carrack.stormbird.xyz`

The workers.dev subdomain and version preview URLs are disabled for both
environments. After deployment, verify that `/api/health` reports the expected
`environment`, sign in as `draven` with the environment's operator credential, and confirm
`/api/admin/snapshot` and `/api/admin/activity` read only that environment's D1
database.

Deployment and VFS bootstrap are separate operations. Bootstrap is
intentionally one-shot. Every dev or production Worker materializes one
disabled, immutable `r2-default` identity from its `CARRACK_PAYLOAD` binding,
account S3 endpoint, and environment-specific `carrack-payload-<environment>`
bucket. Driver creation atomically initializes a 100 GiB physical-byte hard
quota from `CARRACK_DEFAULT_R2_MAX_PHYSICAL_BYTES`; later UI or `carrackctl`
quota changes advance the independent quota revision and are never overwritten
by environment reconciliation.

After VFS bootstrap, provision the environment-owned driver outside the normal
deployment credential boundary:

```bash
export CLOUDFLARE_TOKEN_FACTORY_API_TOKEN='<short-lived Account API Tokens Write credential>'
export CARRACK_OPERATOR_CREDENTIAL='<environment operator credential>'
export CARRACK_OPERATOR_ACCOUNT=draven
# Required only when this environment already has a bootstrapped VFS.
export CARRACK_VFS_TOKEN='<environment root or scoped driver.manage token>'

just check-r2-dev
CARRACK_PROVISION_R2=1 just provision-r2-dev
unset CLOUDFLARE_TOKEN_FACTORY_API_TOKEN CARRACK_OPERATOR_ACCOUNT \
  CARRACK_OPERATOR_CREDENTIAL CARRACK_VFS_TOKEN
```

Production additionally requires `CARRACK_PROVISION_PROD=1`. The preflight and
apply commands first inspect the exact Carrack driver and root placement
revisions. Before VFS bootstrap there is no placement policy, so production can
initialize and enable `r2-default` without a VFS bearer; a later bootstrap still
starts with an empty placement as an explicit authority boundary. If no signing credential exists, they find or create the deterministic
account-owned token `carrack-r2-default-<environment>`, require the exact
`Workers R2 Storage Bucket Item Write` permission and the single bucket resource,
derive the S3 secret as SHA-256 of the one-time token value, and write it only to
a mode-0600 temporary file. They then invoke `carrackctl --check`, apply with an
idempotency key, and re-read the effective state. Cloudflare documents the exact
bucket resource and S3 conversion here:
<https://developers.cloudflare.com/r2/api/tokens/>.

Creation is fail-closed under races: the tool re-lists the deterministic name
before touching Carrack and removes its own newly created token if another
provisioner won. If that token already exists while D1 reports no credential,
normal apply stops rather than rotating authority behind a concurrent writer.
After confirming no other provisioner is active, recover the interrupted setup
explicitly:

```bash
CARRACK_PROVISION_R2=1 CARRACK_RECOVER_R2_TOKEN=1 \
  node control-plane/scripts/provision-default-r2.mjs \
  dev --recover-existing-token
```

The provisioner enables the driver and adds `r2-default:0` only when the root
placement set is empty. If an existing root policy omits R2, it is preserved and
the command warns. After reviewing that complete policy, explicitly opt into an
append with:

```bash
CARRACK_PROVISION_R2=1 node control-plane/scripts/provision-default-r2.mjs \
  dev --append-root-placement
```

The console never asks for the environment-owned access key; it shows only
readiness and permits normal state and quota controls. Additional R2 buckets
remain operator-registered with `managed:false` and retain the write-only
credential dialog and `carrackctl driver credential set` flow. The native
`aliyundrive-open/v2` adapter has completed this dev canary with encrypted
complete-object upload, concurrent exact-range download, interrupted resume,
hash verification, and logical removal.

Development and production may use one Aliyun Drive account only with distinct
dedicated provider folders and distinct `root_folder_id` configurations. This
is namespace isolation, not provider-account isolation: the OAuth grant can
still authorize the wider drive. Store each environment's encrypted credential
in its own D1 database, use only the dev root for provider experiments, and do
not register or enable the production root until its own acceptance gate.

An out-of-band OAuth helper may bootstrap an Aliyun refresh token. Carrack
never links to, launches, or routes payloads through OpenList, but the control
plane may use the typed `openlist-online/v1` issuer to exchange and renew that
authority. The control plane derives access tokens internally; both tokens then
remain in the authenticated encrypted D1 envelope, while filesystem grants
project only the access token. Cron renews before expiry with a D1 lease and
fencing token. A permanent rejection becomes `reauth_required`; repeat
interactive authorization and replace the write-only refresh token through
`carrackctl`. Never put recovery material in Git.

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
typed hosted-driver adapter after final reachability and fence validation. For
`r2-default`, object deletion and multipart abort use the `CARRACK_PAYLOAD`
Worker binding, so physical cleanup remains available after the client signing
key is rotated. Third-party R2 uses its sealed credential.
There is no client or operator GC command. A driver without stable identity,
exact Stat, and idempotent Delete retains its candidates for later retry;
capability and identity errors require investigation, not manual deletion.

GC is an internal control-plane lifecycle and is intentionally absent from the
Rust SDK and both CLIs. Every Cron invocation performs a bounded pass: it marks
old locations selected by `safe_unreachable_vfs_locations`, creates immutable
delete tasks, and processes at most one hosted-location task plus one abandoned
Put task. Before provider I/O it rechecks the location revision, driver
revision, reachability, grace deadline, lease fence, and active direct-read
leases. A concurrent publication or read therefore blocks deletion.

Locations must be unreachable for 30 days before tombstoning and then remain
under a seven-day delete grace. Aliyun deletion is server-owned and idempotent;
provider failure remains retryable. A local filesystem is deliberately
server-blocked because a Cloudflare Worker cannot safely reach an agent-local
path. Operators inspect lifecycle state and alerts but never claim or execute
GC tasks.

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

The current Rust V2 product does not expose provider-wide inventory, adoption,
or quarantine in either filesystem CLI. Physical object deletion is internal,
server-owned lifecycle work. The former archive commands, Worker routes, Rust
modules, and D1 tables have been removed; no agent may reconstruct their old
HTTP protocol.

A future hosted inventory pass must remain read-only, bounded, fenced, and
conservative: an unknown object is quarantined rather than adopted or deleted,
and a missing listing result is evidence rather than proof of absence. Its
review and physical deletion stages belong to the control plane, require the
same final reachability and identity fences as normal lifecycle GC, and must
pass production fault-injection before Cron enables them.

## Activity and lifecycle health

The authenticated dashboard polls `GET /api/admin/activity`. Its bounded V2
projection contains current upload intents, read leases, server-owned delete
and cleanup work, credential renewal failures, and the newest immutable
`vfs_audit_events`. Retry, blocked, and reauthorization states are explicitly
marked as needing attention.

Direct transfers do not proxy bytes through the Worker, so byte progress is
intentionally absent from this endpoint. The client that owns a transfer may
show local progress, while the dashboard reports only durable checkpoints and
server-side lifecycle state. The response is `Cache-Control: no-store`, returns
at most 100 active items and 100 newest events, and requires an operator
session.

Agents consume the same immutable audit stream through
`GET /api/admin/events?after=<cursor>&limit=<1..250>`. The Worker reads the
current high-water mark first, then performs an ascending bounded primary-key
range query no later than that mark. The response returns `next_after` and
`has_more`, redacts secret-shaped detail fields exactly like Activity, and
fails with `409` when a cursor is ahead of the selected environment. The Rust
`carrackctl watch` command validates ordering and continuation before emitting
the page as JSON.

## D1 backup and recovery

D1 Time Travel is a short-window rollback mechanism, not a complete provider
reconciliation system. Export D1 on a schedule, keep the export outside the
Cloudflare account, and preserve offline copies of every active VFS master-key
version. Immutable catalog checkpoints in `CARRACK_MANIFESTS` provide an
additional content-hashed recovery input.

Never restore D1 while mutation traffic is enabled. Set the external
`CARRACK_MAINTENANCE` secret first and confirm health reports
`mutations_allowed: false`. Carrack deliberately exposes no generic browser,
filesystem CLI, or public HTTP "recovery complete" switch: a rollback may
resurrect revoked tokens or metadata for provider objects deleted after the
bookmark. Keep the environment fail-closed until a release-specific recovery
runbook has reapplied migrations, rotated affected credentials, invalidated
stale capabilities and intents, reconciled every referenced provider object,
verified catalog and file roots, and passed a read-only canary. Only then may
the operator remove external maintenance mode.
