# Skydriver VFS Bootstrap V1

## Purpose

`POST /api/v2/bootstrap` creates the first VFS authority in an empty migrated
D1 database. It is an operator-only, one-shot control-plane operation, not a
payload API. In one D1 batch it creates:

- the filesystem and empty root directory;
- the first user principal and root ACL grants;
- a sealed root-directory key epoch, or an explicit plaintext epoch;
- the environment-owned `r2-default` identity as the root's default mount;
- an all-actions root administration token; and
- an immutable bootstrap receipt and audit record.

The default R2 identity is derived from the Worker environment and begins with
the environment profile's 100 GiB physical-byte hard quota. The one-time
environment provisioner creates its exact-bucket Cloudflare authority,
validates and seals the derived S3 signing key and enables the driver. The
disabled default mount exists before credentials so the virtual hierarchy has
one stable backing identity, while namespace and payload mutations remain
unavailable until the driver is enabled. Operators may later replace the quota through
the same validated UI or `skydriverctl` policy flow; environment reconciliation
never resets an operator revision. The Cloudflare Worker stores only the token
verifier and authenticated key envelope. It never stores a VFS bearer token or
plaintext directory key in D1 and never opens the configured local filesystem
path.

## Prerequisites

Apply all D1 migrations, configure an operator account, and set the independent
VFS master secret before calling the endpoint:

```bash
pnpm exec wrangler secret put SKYDRIVER_VFS_MASTER_KEY_V1 \
  --env <dev-or-prod> \
  --config control-plane/wrangler.jsonc
```

The value is the unpadded base64url encoding of exactly 32 random bytes. Keep a
tested offline recovery copy. It must be generated independently from
`SKYDRIVER_ADMIN_TOKEN`. No archive-root compatibility secret participates in VFS bootstrap.

The caller first authenticates through `POST /api/auth/login` with the
environment's operator account and credential and sends the resulting revocable session
cookie. External maintenance mode rejects the mutation. A VFS bearer token
cannot invoke bootstrap.

## Request

The JSON request is strict and rejects unknown fields:

```json
{
  "filesystem_name": "Skydriver VFS",
  "principal_display_name": "VFS operator",
  "crypto_suite": "carrack-vfs-aes256gcm-hkdfsha256-v1",
  "token_lifetime_seconds": 2592000,
  "idempotency_key": "production-bootstrap-v1"
}
```

`crypto_suite` defaults to
`carrack-vfs-aes256gcm-hkdfsha256-v1`; the only alternative is the explicit
`plaintext/v1` suite. `token_lifetime_seconds` defaults to 30 days and must be
between one hour and 365 days. Dev and production select `r2-default`. The
response identifies that initially disabled driver as the root default mount.
Run the environment provisioner after bootstrap; credential and enablement
remain separately validated operations even though the provisioner
orchestrates them as one fail-fast setup workflow.

Local conformance environments may explicitly provide both `local_driver_id`
and `local_root`. That compatibility path preserves the original V1 request
digest and creates a `local-filesystem/v2` placement. Providing only one field
is invalid. Hosted environments should omit both fields.

## Response and replay

The successful response uses schema `carrack.vfs.bootstrap-receipt.v1`:

```json
{
  "schema": "carrack.vfs.bootstrap-receipt.v1",
  "filesystem_id": "32 lowercase hex",
  "principal_id": "32 lowercase hex",
  "root_directory_id": "32 lowercase hex",
  "token_id": "32 lowercase hex",
  "driver_id": "r2-default",
  "crypto_suite": "carrack-vfs-aes256gcm-hkdfsha256-v1",
  "key_epoch": 1,
  "token_expires_at": 0,
  "token": "43-character base64url bearer"
}
```

The real `token_expires_at` is an absolute Unix timestamp. The response is
marked `Cache-Control: no-store` and must be captured into an appropriately
protected secret store. Use the returned `root_directory_id` as the destination
for the first Put.

D1 accepts exactly one immutable bootstrap receipt. Repeating the exact request
under the same operator subject and idempotency key returns the identical IDs
and bearer token. The Worker deterministically re-derives that token from the
versioned VFS master key and request identity, so no bearer value is stored in
D1. Any changed request, subject, or idempotency identity after bootstrap
returns `409` and cannot create a second root.

Retain `SKYDRIVER_VFS_MASTER_KEY_V1` while the key envelopes or bootstrap receipt
depend on it. Rotation requires adding a new versioned binding and rewrapping
directory epochs; replacing the old value in place would make encrypted data
and exact bootstrap replay unrecoverable.

`skydriverctl authority bootstrap --output-file PATH` is the supported operator
bootstrap surface. `skydriverctl authority recover --output-file PATH` re-derives
the same unexpired bearer from the immutable receipt after a separate
configuration reauthentication. Both commands create a new owner-only file;
they print only a redacted file receipt and never print the bearer. Recovery
fails closed when the receipt expired, the master key changed, or the stored
verifier does not match.
