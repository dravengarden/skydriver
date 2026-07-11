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

Apply migrations before deploying:

```bash
pnpm exec wrangler d1 migrations apply carrack-index \
  --remote \
  --config control-plane/wrangler.jsonc
```

Set runtime secrets through Wrangler:

```bash
pnpm exec wrangler secret put CARRACK_ADMIN_USERNAME \
  --config control-plane/wrangler.jsonc
pnpm exec wrangler secret put CARRACK_ADMIN_PASSWORD_HASH \
  --config control-plane/wrangler.jsonc
pnpm exec wrangler secret put CARRACK_SESSION_KEY \
  --config control-plane/wrangler.jsonc
```

`CARRACK_ADMIN_PASSWORD_HASH` is an Argon2id PHC string. The Worker never
stores the plaintext password. `CARRACK_SESSION_KEY` must be an independently
generated high-entropy value.

Build and deploy only after the repository gate passes:

```bash
just verify
pnpm exec wrangler deploy --config control-plane/wrangler.jsonc
```

After deployment, verify `/api/health`, sign in with the preset account, and
confirm `/api/summary` can read the migrated D1 database.
