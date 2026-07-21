# Carrack compatibility identities

Skydriver is the product, repository, CLI, SDK, Worker, UI, and documentation
name. The earlier Carrack visual identity has been archived by Data Provider and
is not a Skydriver product surface.

The rename deliberately does not rewrite persisted identities whose bytes are
part of a correctness proof:

- `carrack.*` JSON schemas and content types;
- Merkle, HKDF, AEAD, token, receipt, and idempotency domain separators;
- encrypted local metadata-cache and resumable-journal formats;
- applied D1 migration bytes; and
- the existing D1 database and R2 bucket names bound to each environment.

These strings are legacy protocol and physical-storage identifiers, not current
branding. Rewriting them in place would invalidate ciphertext derivation,
receipts, catalog hashes, cache authentication, migration checksums, or access
to existing objects. A future removal requires a new versioned format plus an
explicit migration that proves every old object and recovery path remains
readable.

The epoch-2 control plane accepts both the canonical `Skydriver-Protocol-Epoch`
and `Skydriver-SDK-Version` headers and their legacy Carrack spellings. When
both spellings are present they must agree. New clients send only Skydriver
headers. New CLI state is stored under `skydriver`; an existing owner-local
`skydriver` state directory is reused so resumable work is not abandoned.

Operator credential rotation is unrelated to VFS encryption. It must never
rotate or replace the VFS master key or wrapped directory keys.
