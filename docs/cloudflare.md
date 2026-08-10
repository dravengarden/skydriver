# Cloudflare deployment

Skydriver's control plane is a Cloudflare Worker backed by D1, R2, and a
SQLite Durable Object. The repository contains a local profile and development
and production examples. The remote examples intentionally use reserved
`.example` hostnames, placeholder UUIDs, and a placeholder R2 account; replace
those values in a deployment-owned copy before deploying.

## Prerequisites

- a Cloudflare account with Workers, D1, R2, and Durable Objects enabled;
- a custom domain controlled by the deployment owner;
- the pinned Nix development shell; and
- a least-privilege API token and account ID kept outside Git.

Create a private environment file from the repository example when using the
Cloudflare scripts:

```bash
cp .env.example .env
chmod 600 .env
```

The file is ignored by Git. It may contain only routine deployment values such
as `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID`; Worker secrets belong in
Cloudflare's secret store and must not be copied into this file.

## Resource configuration

Edit a private deployment copy of `control-plane/wrangler.jsonc` and replace:

- the `dev` and `prod` custom-domain patterns;
- the D1 database IDs;
- the D1 database names and R2 bucket names, if your naming policy requires it;
- the account-specific `SKYDRIVER_R2_ENDPOINT`; and
- the environment-scoped `SKYDRIVER_OPERATOR_ACCOUNT` values.

Keep the following invariants:

- local, development, and production use distinct D1 and R2 resources;
- `workers_dev` and `preview_urls` remain disabled for remote environments;
- development and production have separate Worker names and secrets;
- the `SKYDRIVER_INDEX`, `SKYDRIVER_MANIFESTS`, and `SKYDRIVER_PAYLOAD`
  bindings remain present exactly once; and
- the `CatalogWatchHub` Durable Object migration remains in the configuration.

Do not commit the deployment copy if it contains real resource identifiers.
The checked-in configuration is safe for local builds and documentation
examples, not a production configuration.

## Worker secrets

Set the required secrets independently for each environment. Generate values
locally and paste them into Wrangler's stdin prompt or use a password manager:

```bash
pnpm exec wrangler secret put SKYDRIVER_ADMIN_TOKEN --env dev
pnpm exec wrangler secret put SKYDRIVER_VFS_MASTER_KEY_V1 --env dev

pnpm exec wrangler secret put SKYDRIVER_ADMIN_TOKEN --env prod
pnpm exec wrangler secret put SKYDRIVER_VFS_MASTER_KEY_V1 --env prod
```

`SKYDRIVER_ADMIN_TOKEN` is the break-glass operator credential and
`SKYDRIVER_VFS_MASTER_KEY_V1` protects VFS directory-key material. Both must be
random, environment-specific, and backed up through the deployment owner's
approved offline recovery process. Never place either value in Git, a command
argument, a log, a browser bundle, or a persistent shell history.

The operator account is an ordinary non-secret Worker variable. It is not a
replacement for the credential and must not be used as a password.

## Database migrations

Apply migrations to a non-production environment first:

```bash
nix develop -c just migrate-dev
```

Production migration is intentionally guarded:

```bash
SKYDRIVER_MIGRATE_PROD=1 nix develop -c just migrate-prod
```

Review the pending migration set and take the deployment owner's normal D1
backup or recovery step before applying production changes.

## Build and deploy

Run the complete local gate before any remote action:

```bash
nix develop -c just verify
```

Deploy a verified development Worker with the repository recipe:

```bash
nix develop -c just deploy-dev
```

Production requires an explicit second confirmation variable:

```bash
SKYDRIVER_DEPLOY_PROD=1 nix develop -c just deploy-prod
```

Durable Object migrations use a separate guarded recipe because Cloudflare
requires a deployment carrying the migration metadata:

```bash
nix develop -c just deploy-do-migrations-dev
SKYDRIVER_DEPLOY_PROD=1 SKYDRIVER_APPLY_DO_MIGRATIONS_PROD=1 \
  nix develop -c just deploy-do-migrations-prod
```

The deploy script uploads and promotes a version, then synchronizes the Cron
schedule through the account-scoped API. It does not grant or require a
zone-wide route mutation for routine deployments.

## Default R2 driver

The `dev` and `prod` profiles can materialize an environment-owned
`r2-default` driver from the `SKYDRIVER_PAYLOAD` binding. Provisioning is
explicit and requires both the operator credential and a narrowly scoped
Cloudflare token for the selected bucket:

```bash
SKYDRIVER_PROVISION_R2=1 nix develop -c just provision-r2-dev
SKYDRIVER_PROVISION_R2=1 SKYDRIVER_PROVISION_PROD=1 \
  nix develop -c just provision-r2-prod
```

Use `just check-r2-dev` or `just check-r2-prod` for a read-only preflight. The
provisioner must never receive a token with account-wide resource authority
when a bucket-scoped token is sufficient.

## Live acceptance

Live provider tests are opt-in and require explicit environment variables. They
never contain a default deployment URL and should use a disposable test
directory and short-lived, least-privilege VFS token:

```bash
export SKYDRIVER_CONTROL_URL='https://dev.skydriver.example'
export SKYDRIVER_VFS_TOKEN='<short-lived test token>'
SKYDRIVER_R2_LIVE_TEST=1 nix develop -c tests/r2-live.sh
```

The Aliyun and small-sync tests follow the same pattern. The normal `just test`
run skips live provider writes unless the corresponding opt-in variable is set.
Always verify cleanup and revoke the test token after an acceptance run.

## Health and audit

Use the repository scripts to inspect the selected Cloudflare account and
configuration:

```bash
nix develop -c just audit-cloudflare
```

Before promotion, verify the Worker version, schedules, D1 migration state,
R2 bindings, secret names, and public custom-domain routing. Health responses
are operational evidence only; they do not replace provider readback,
cryptographic verification, or the deployment owner's recovery checks.
