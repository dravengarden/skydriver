# Skydriver v1 identity reset

Skydriver is the product, repository, CLI, SDK, Worker, UI, protocol, and
physical Cloudflare resource name. The earlier visual identity has been
archived by Data Provider and is not a Skydriver product surface.

Skydriver v1 is an intentional clean epoch. The pre-production D1 and
R2 contents were test data and are not migrated. Every persisted identity is
therefore reset together:

- `skydriver.*` JSON schemas and content types;
- Merkle, HKDF, AEAD, token, receipt, and idempotency domain separators;
- encrypted local metadata-cache and resumable-journal formats;
- D1 migration bytes and stored schema values; and
- environment D1 database and R2 bucket names.

Old clients, ciphertext, receipts, catalogs, caches, journals, and D1 rows are
incompatible by design and must fail closed. There is no dual-read fallback.
After this reset, these Skydriver v1 identities are immutable; any future reset
requires a new versioned format and a reviewed migration that proves every
retained object and recovery path remains readable.

The control plane accepts only canonical `Skydriver-Protocol-Epoch` and
`Skydriver-SDK-Version` headers. CLI state is stored only under `skydriver`.
Pre-v1 local state is an untrusted stale cache and is never imported.

Operator credential rotation is unrelated to VFS encryption. It must never
rotate or replace the VFS master key or wrapped directory keys.
