# Cloudflare operations

Skydriver uses a scoped account API token, not an interactive Wrangler browser
session. Copy `.env.example` to the gitignored `.env`, set mode `0600`, and
provide `CLOUDFLARE_API_TOKEN` plus `CLOUDFLARE_ACCOUNT_ID`. Entering
`nix develop` exports those values.

Keep Skydriver's routine deployment credential in this repository's `.env`.
Do not source or copy a complete `.env` from another project: such files can
contain unrelated R2, SSH, or product credentials and can give a deployment
broader authority than intended. When recovering an existing credential, copy
only the two variables above, preserve the source project, and verify the local
file without printing either value:

```bash
chmod 600 .env
git check-ignore .env
nix develop -c bash -c \
  'test -n "$CLOUDFLARE_API_TOKEN" && test -n "$CLOUDFLARE_ACCOUNT_ID"'
```

The day-to-day token needs only the account permissions required by Skydriver:

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

Skydriver has explicit `dev` and `prod` environments. Every remotely usable
resource is distinct:

| Environment | Worker | Custom domain | D1 | Metadata R2 | Default payload R2 |
|---|---|---|---|---|---|
| `dev` | `skydriver-control-plane-dev` | `dev.skydriver.stormbird.xyz` | `skydriver-index-dev` | `skydriver-manifests-dev` | `skydriver-payload-dev` |
| `prod` | `skydriver-control-plane-prod` | `skydriver.stormbird.xyz` | `skydriver-index-prod` | `skydriver-manifests-prod` | `skydriver-payload-prod` |

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

`SKYDRIVER_MANIFESTS` carries only immutable control metadata: verification-block
manifests plus full and delta catalog artifacts. It never stores user payload
bytes.
`SKYDRIVER_PAYLOAD` gives server-side lifecycle and reconciliation code access to
the environment's built-in payload bucket. Payload bytes still flow directly
between SDK clients and storage; the Worker never relays file bodies.

Create all six isolated storage resources once before the first deployment:

```bash
pnpm exec wrangler d1 create skydriver-index-dev
pnpm exec wrangler d1 create skydriver-index-prod
pnpm exec wrangler r2 bucket create skydriver-manifests-dev
pnpm exec wrangler r2 bucket create skydriver-manifests-prod
pnpm exec wrangler r2 bucket create skydriver-payload-dev
pnpm exec wrangler r2 bucket create skydriver-payload-prod
```

Apply migrations independently before deploying. Never run a remote migration
without an explicit environment:

```bash
just migrate-dev
SKYDRIVER_MIGRATE_PROD=1 just migrate-prod
```

The recipes intentionally use Skydriver's import-based migration runner instead
of `wrangler d1 migrations apply --remote`. Wrangler's statement splitter
removes the terminal semicolon from SQLite trigger definitions; D1 then rejects
the incomplete trigger. The Skydriver runner imports one migration and its
`d1_migrations` receipt atomically, and verifies that receipt before advancing.

The development operator console uses the single Cardea issuer at
`https://cardea.stormbird.xyz`. Its `skydriver-dev` OIDC client uses
Authorization Code Flow with PKCE and private-key client authentication. After
strictly validating the audience-bound ID token, Skydriver exchanges that
identity proof for its own random 12-hour HttpOnly browser session. Cardea does
not own Skydriver authorization, sessions, VFS tokens, or configuration access.

Production and local development retain the exact environment-scoped canonical
account and operator-credential login. Every environment still has an
independent `SKYDRIVER_ADMIN_TOKEN`: it is the CLI and break-glass credential,
and the development browser must re-enter it to obtain the separate 15-minute
configuration session. D1 stores only keyed or SHA-256 session verifiers;
logout deletes the browser session. A 15-minute metadata-hygiene Cron Trigger
also deletes expired operator and configuration sessions, so cleanup does not
depend on a later login.

The unauthenticated health response exposes the non-secret account so the UI
and password manager use the exact same environment-scoped identity. The
Worker accepts only that configured identity; there is no display-only alias
or cross-environment fallback.
The login endpoint also accepts only the exact legacy alias for its own
environment so an older cached UI cannot lock the operator out; a dev alias is
always rejected by production and vice versa.

Authentication failures are throttled in D1 by a keyed source-IP digest and,
for the known operator, a higher-threshold account digest. Raw IP addresses and
submitted account names are never retained in throttle state. The same
source-IP protection covers the credential recheck that enables a configuration
session. Login and configuration source-IP scopes allow 20 failures per
15-minute window and block for 15 minutes; the distributed account scope allows
200 failures and blocks for 30 minutes. Limits fail closed with `429` and
`Retry-After`; bounded Cron cleanup retires inactive throttle rows after one
day.

Set independent operator and VFS-master secrets for each environment:

```bash
pnpm exec wrangler secret put SKYDRIVER_ADMIN_TOKEN \
  --env dev \
  --config control-plane/wrangler.jsonc
pnpm exec wrangler secret put SKYDRIVER_VFS_MASTER_KEY_V1 \
  --env dev \
  --config control-plane/wrangler.jsonc

pnpm exec wrangler secret put SKYDRIVER_ADMIN_TOKEN \
  --env prod \
  --config control-plane/wrangler.jsonc
pnpm exec wrangler secret put SKYDRIVER_VFS_MASTER_KEY_V1 \
  --env prod \
  --config control-plane/wrangler.jsonc
```

Provision the development-only Cardea client seed and a separate random
32-byte state-cookie authentication key through stdin. Both values are
unpadded base64url encodings of exactly 32 bytes:

```bash
pnpm exec wrangler secret put CARDEA_CLIENT_PRIVATE_KEY \
  --env dev \
  --config control-plane/wrangler.jsonc
pnpm exec wrangler secret put CARDEA_STATE_KEY \
  --env dev \
  --config control-plane/wrangler.jsonc
```

`SKYDRIVER_ADMIN_TOKEN` must be the unpadded base64url encoding of exactly 32
random bytes. It is an operator credential, not a VFS principal or capability
token, and development and production must never share it.
`SKYDRIVER_VFS_MASTER_KEY_V1` is also an unpadded base64url encoding of exactly
32 random bytes, generated independently from the operator credential. It seals V2
directory keys and derives the recoverable one-shot bootstrap token. Preserve
the version while either V2 envelopes or the bootstrap receipt depend on it;
see `vfs-bootstrap-v1.md`.

After initial provisioning, rotate only the operator credential through the
non-generic stdin-only recipe:

```bash
just rotate-operator-dev < "$owner_private_operator_credential_file"
SKYDRIVER_ROTATE_OPERATOR_PROD=1 just rotate-operator-prod \
  < "$owner_private_operator_credential_file"
```

These recipes are hard-coded to `SKYDRIVER_ADMIN_TOKEN`. An operator account or
password change must never put, delete, regenerate, or otherwise mutate
`SKYDRIVER_VFS_MASTER_KEY_V1`, any wrapped directory key, or bootstrap recovery
authority. Without a separately designed envelope-rewrapping migration,
changing that master key makes existing encrypted data unrecoverable.

Build and deploy only through the environment-specific recipes. Production
requires an additional explicit acknowledgement:

```bash
just deploy-dev
SKYDRIVER_DEPLOY_PROD=1 just deploy-prod
```

Durable Object class creation, rename, transfer, and deletion are atomic state
migrations and cannot be uploaded as an inactive Worker version. Skydriver keeps
that immediate, 100%-traffic operation out of routine deployment. After a
reviewed change to `migrations`, apply it exactly once per environment with the
explicit migration recipe:

```bash
just deploy-do-migrations-dev
SKYDRIVER_DEPLOY_PROD=1 SKYDRIVER_APPLY_DO_MIGRATIONS_PROD=1 \
  just deploy-do-migrations-prod
```

The recipe runs the same full verification and post-deploy acceptance as a
routine deployment, but uses the non-versioned Cloudflare deployment operation
required to apply the migration atomically. Its private generated Wrangler
configuration omits routes and Cron triggers so this one-time operation cannot
rewrite those independently managed resources; the script synchronizes and
verifies Cron only after the Worker passes deployment. New Skydriver Durable
Object namespaces use SQLite storage. After the migration is applied, return to
`deploy-dev` or `deploy-prod`; never set `SKYDRIVER_APPLY_DO_MIGRATIONS` in a
routine deployment environment.

The verification gate also compiles `skydriver-sdk-core` for
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
export SKYDRIVER_CONTROL_URL=https://dev.skydriver.stormbird.xyz
export SKYDRIVER_VFS_TOKEN='<short-lived dev acceptance token>'
export SKYDRIVER_ALIYUN_DRIVER_ID='<enabled dev Aliyun driver>'
SKYDRIVER_ALIYUN_LIVE_TEST=1 tests/aliyun-live.sh
```

The attenuated token must grant `directory.list`, `content.read`,
`content.write`, `driver.use`, and `entry.delete` on only the test directory,
and its driver scope must include the selected Aliyun driver. `content.write`
alone is deliberately insufficient: choosing or entering a storage driver also
requires `driver.use`. Keep the one-time bearer in an owner-private secret file
or secret injection and revoke it after the acceptance run.

The script never prints credentials, provider locators, or signed URLs. Its
remove verifies namespace deletion; physical deletion remains subject to the
normal server grace and scheduled GC rather than weakening production safety
for a test. The JSON result also reports end-to-end upload, verified download,
and interrupted-resume elapsed milliseconds and effective plaintext bytes per
second. These wall-clock observations include control-plane, cryptography,
provider, verification, and local publication work; they are practical client
throughput rather than provider-only or billing metrics. Successful v2 results
also carry one random 64-bit `run_id`, the run's UTC bounds, and UTC bounds for
each measured transfer stage. The identifier is correlation metadata only; it
is not an authorization, idempotency, integrity, or provider identity.

The managed R2 acceptance uses the same safety boundary but defaults to a
128 MiB random payload and eight concurrent 8 MiB parts so the real multipart,
range, resume, hash, and logical-removal paths are exercised:

```bash
export SKYDRIVER_CONTROL_URL=https://dev.skydriver.stormbird.xyz
export SKYDRIVER_VFS_TOKEN='<short-lived dev acceptance token>'
SKYDRIVER_R2_LIVE_TEST=1 tests/r2-live.sh
```

The R2 token needs the same five actions and must be scoped to `r2-default`.
It may share a test-directory token with the Aliyun acceptance only when both
driver IDs are explicitly present; neither test needs `driver.manage`,
`acl.manage`, operator authority, or root filesystem scope.

This live test is opt-in and is not part of `just verify`; the hermetic gate
checks its shell contract and metric arithmetic only. Set
`SKYDRIVER_R2_TEST_PART_BYTES` and `SKYDRIVER_R2_TEST_CONCURRENCY` to compare
bounded R2 pipeline configurations. The R2 acceptance requires at least 100
MiB, two parts, and concurrency two so its multipart and concurrent-range
claims remain true. Set `SKYDRIVER_ALIYUN_TEST_BYTES` to the same payload size
when a cross-driver comparison is worth the slower sequential upload, up to
the scripts' 1 GiB safety bound. When using a token already scoped to a test
directory, leave the test directory as `/`: paths are relative to the
authenticated token root. Run multiple samples before comparing drivers
because the low-cost telemetry deliberately does not claim benchmark-grade
precision.

Append real results and failed tuning samples to
[transfer-performance-observations.md](transfer-performance-observations.md),
including the exact environment, payload, pipeline, timeout, cleanup outcome,
and whether a number came from end-to-end timing or sampled telemetry. Never
replace a failed acceptance with the successful stages that preceded it.
Timeout and CLI failures also emit a compact
`skydriver.*.live-acceptance-failure.v2` JSON object on stderr with the same
opaque run ID plus the stage, UTC bounds, elapsed milliseconds, exit status,
safety timeout, payload size, and requested pipeline. It contains no bearer,
signed URL, provider locator, or local path and remains a failed nonzero
process result. Use the run ID and exact bounds to correlate host or egress
telemetry; do not infer a provider cause merely from a timeout.

For an explicit many-small-file sync measurement, use the separate dev-only
acceptance. It creates a uniquely named directory, uploads 64 independent
1 MiB encrypted versions by default, performs one cold and one warm sync,
verifies every plaintext SHA-256, and logically removes every test entry on
exit. One synchronous Put must pass before the remaining uploads are started,
so a missing `driver.use` grant or inactive placement fails without a burst of
unauthorized requests:

```bash
export SKYDRIVER_CONTROL_URL=https://dev.skydriver.stormbird.xyz
export SKYDRIVER_VFS_TOKEN='<dev test-directory token>'
SKYDRIVER_R2_SMALL_SYNC_LIVE_TEST=1 tests/r2-small-sync-live.sh
```

`SKYDRIVER_R2_SMALL_SYNC_FILES`, `SKYDRIVER_R2_SMALL_SYNC_BYTES`, upload
concurrency, and sync concurrency are bounded inputs. The output includes exact
UTC windows so the run can be correlated with the sampled driver/directory
analytics. The script is never part of `just verify`: it performs real provider
writes and intentionally leaves physical deletion to server-owned GC after
logical cleanup.

Routine deployment uploads a tagged Worker version and then moves 100% of that
environment's traffic to it. An explicit Durable Object migration deployment
creates a tagged version and immediately moves 100% of traffic because
Cloudflare applies the migration atomically with that deployment. Neither path
intentionally rewrites the already-audited custom
domain, so the routine account token does not need zone-wide route mutation
permission. After the traffic move, the recipe polls the custom domain with a
deployment-tagged cache buster and succeeds only when health reports the exact
environment, the Worker WASM SDK round trip verifies, and the served UI asset
has the same SHA-256 as the locally verified build. This bounded retry absorbs
ordinary edge propagation while failing closed on a stale Worker, wrong route,
or partial asset rollout. Reconcile an intentional route change separately
with a suitably scoped setup credential.

The stable UI endpoints are:

- `https://dev.skydriver.stormbird.xyz`
- `https://skydriver.stormbird.xyz`

The workers.dev subdomain and version preview URLs are disabled for both
environments. After deployment, verify that `/api/health` reports the expected
`environment`, sign in with that environment's exact configured operator account and credential, and confirm
`/api/admin/snapshot` and `/api/admin/activity` read only that environment's D1
database.

Deployment and VFS bootstrap are separate operations. Bootstrap is
intentionally one-shot. Every dev or production Worker materializes one
disabled, immutable `r2-default` identity from its `SKYDRIVER_PAYLOAD` binding,
account S3 endpoint, and environment-specific `skydriver-payload-<environment>`
bucket. Driver creation atomically initializes a 100 GiB physical-byte hard
quota from `SKYDRIVER_DEFAULT_R2_MAX_PHYSICAL_BYTES`; later UI or `skydriverctl`
quota changes advance the independent quota revision and are never overwritten
by environment reconciliation.

After VFS bootstrap, provision the environment-owned driver outside the normal
deployment credential boundary:

```bash
export CLOUDFLARE_TOKEN_FACTORY_API_TOKEN='<short-lived Account API Tokens Write credential>'
export SKYDRIVER_OPERATOR_CREDENTIAL='<environment operator credential>'
export SKYDRIVER_OPERATOR_ACCOUNT=draven@skydriver-dev
# Required only when this environment already has a bootstrapped VFS.
export SKYDRIVER_VFS_TOKEN='<environment root or scoped driver.manage token>'

just check-r2-dev
SKYDRIVER_PROVISION_R2=1 just provision-r2-dev
unset CLOUDFLARE_TOKEN_FACTORY_API_TOKEN SKYDRIVER_OPERATOR_ACCOUNT \
  SKYDRIVER_OPERATOR_CREDENTIAL SKYDRIVER_VFS_TOKEN
```

Production additionally requires `SKYDRIVER_PROVISION_PROD=1`. The preflight and
apply commands first inspect the exact Skydriver driver and root mount revision.
Before VFS bootstrap there is no mount policy, so production can initialize and
enable `r2-default` without a VFS bearer; a later bootstrap installs it as the
root default. If no signing credential exists, they find or create the deterministic
account-owned token `skydriver-r2-default-<environment>`, require the exact
`Workers R2 Storage Bucket Item Write` permission and the single bucket resource,
derive the S3 secret as SHA-256 of the one-time token value, and write it only to
a mode-0600 temporary file. They then invoke `skydriverctl --check`, apply with an
idempotency key, and re-read the effective state. Cloudflare documents the exact
bucket resource and S3 conversion here:
<https://developers.cloudflare.com/r2/api/tokens/>.

Creation is fail-closed under races: the tool re-lists the deterministic name
before touching Skydriver and removes its own newly created token if another
provisioner won. If that token already exists while D1 reports no credential,
normal apply stops rather than rotating authority behind a concurrent writer.
After confirming no other provisioner is active, recover the interrupted setup
explicitly:

```bash
SKYDRIVER_PROVISION_R2=1 SKYDRIVER_RECOVER_R2_TOKEN=1 \
  node control-plane/scripts/provision-default-r2.mjs \
  dev --recover-existing-token
```

The provisioner enables the driver and repairs only a legacy root with no
effective driver. If an existing root uses another default, it is preserved and
the command warns; Linux-like VFS semantics never append a second root driver.

The console never asks for the environment-owned access key; it shows only
readiness and permits normal state and quota controls. Additional R2 buckets
remain operator-registered with `managed:false` and retain the write-only
credential dialog and `skydriverctl driver credential set` flow. The native
`aliyundrive-open/v2` adapter has completed this dev canary with encrypted
complete-object upload, concurrent exact-range download, interrupted resume,
hash verification, and logical removal.

Development and production may use one Aliyun Drive account only with distinct
dedicated provider folders and distinct `root_folder_id` configurations. This
is namespace isolation, not provider-account isolation: the OAuth grant can
still authorize the wider drive. Store each environment's encrypted credential
in its own D1 database, use only the dev root for provider experiments, and do
not register or enable the production root until its own acceptance gate.

An out-of-band OAuth helper may bootstrap an Aliyun refresh token. Skydriver
never links to, launches, or routes payloads through OpenList, but the control
plane may use the typed `openlist-online/v1` issuer to exchange and renew that
authority. The control plane derives access tokens internally; both tokens then
remain in the authenticated encrypted D1 envelope, while filesystem grants
project only the access token. Cron renews before expiry with a D1 lease and
fencing token. A permanent rejection becomes `reauth_required`; repeat
interactive authorization and replace the write-only refresh token through
`skydriverctl`. Never put recovery material in Git.

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
`r2-default`, object deletion and multipart abort use the `SKYDRIVER_PAYLOAD`
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
provider failure remains retryable under bounded exponential backoff with
deterministic jitter and a six-hour ceiling. A local filesystem is deliberately
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

The control plane runs one bounded server-owned inventory page for an enabled
hosted driver and exposes only aggregate status through the management UI and
`skydriverctl inventory`. The environment-owned R2 binding and Aliyun Drive Open
API adapter are supported. Agent-local filesystems remain explicitly
unsupported because a Worker cannot safely enumerate their host. Physical
object deletion is internal, server-owned lifecycle work. The former archive
commands, Worker routes, Rust modules, and D1 tables have been removed; no
agent may reconstruct their old HTTP protocol.

The hosted inventory pass is read-only, bounded, fenced, and conservative. It
uses the R2 binding or the sealed, automatically renewed Aliyun access grant;
refresh authority never leaves the control plane. An unknown object is
quarantined rather than adopted or deleted,
and a missing listing result is evidence rather than proof of absence. Its
review and physical deletion stages belong to the control plane, require the
same final reachability and identity fences as normal lifecycle GC, and must
pass production fault-injection before Cron enables them.

A completed inventory is scheduled again after 24 hours. Multi-page scans
continue one bounded page per Cron pass, while provider failures use durable
exponential retry capped at roughly six hours. The dashboard and
`skydriverctl inventory` expose the next scan time and failure-attempt count;
clients never schedule or perform inventory work.
An inventory provider failure is isolated to that driver's scan: after storing
its error and retry deadline, the same Cron invocation continues metadata
hygiene, credential renewal, physical lifecycle work, and catalog
materialization.

## Activity and lifecycle health

The authenticated dashboard polls `GET /api/admin/activity` independently for
normal and attention-required work. Its bounded V2 projection contains current
upload intents, read leases, server-owned delete and cleanup work, and
credential renewal failures. Retry, blocked, and reauthorization states are
explicitly marked as needing attention. `offset` and `limit` are validated and
the Worker reads only enough live rows to return the requested page plus a
`has_more` proof; partial indexes exclude retained terminal history.

Direct transfers do not proxy bytes through the Worker, so byte progress is
intentionally absent from this endpoint. The client that owns a transfer may
show local progress, while the dashboard reports only durable checkpoints and
server-side lifecycle state. Responses are `Cache-Control: no-store`, page size
is bounded to 100, and an operator session is required.

The browser reads newest audit history through
`GET /api/admin/events/recent?before=<cursor>&limit=<1..250>`. The first page
uses `before=0`; later pages use the returned `next_before`. Pages are ordered
by descending immutable event ID, so new events do not extend or reshuffle an
older page.

Agents consume the same immutable audit stream through
`GET /api/admin/events?after=<cursor>&limit=<1..250>`. The Worker reads the
current high-water mark first, then performs an ascending bounded primary-key
range query no later than that mark. The response returns `next_after` and
`has_more`, redacts secret-shaped detail fields exactly like Activity, and
fails with `409` when a cursor is ahead of the selected environment. The Rust
`skydriverctl watch` command validates ordering and continuation before emitting
the page as JSON.

## D1 backup and recovery

D1 Time Travel is a short-window rollback mechanism, not a complete provider
reconciliation system. Export D1 on a schedule, keep the export outside the
Cloudflare account, and preserve offline copies of every active VFS master-key
version. Immutable catalog checkpoints in `SKYDRIVER_MANIFESTS` provide an
additional content-hashed recovery input.

Never restore D1 while mutation traffic is enabled. Set the external
`SKYDRIVER_MAINTENANCE` secret first and confirm health reports
`mutations_allowed: false`. Skydriver deliberately exposes no generic browser,
filesystem CLI, or public HTTP "recovery complete" switch: a rollback may
resurrect revoked tokens or metadata for provider objects deleted after the
bookmark. Keep the environment fail-closed until a release-specific recovery
runbook has reapplied migrations, rotated affected credentials, invalidated
stale capabilities and intents, reconciled every referenced provider object,
verified catalog and file roots, and passed a read-only canary. Only then may
the operator remove external maintenance mode.
