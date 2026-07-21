# AWS S3 driver v1

This document fixes the correctness envelope for the compiled `aws-s3/v1`
driver. [requirements.md](requirements.md) remains normative. The adapter is
exposed through the shared registry, management API, CLI, and UI only as one
official-AWS implementation; generic S3-compatible services remain separate
versioned drivers.

## Scope

`aws-s3/v1` targets AWS S3 general-purpose buckets in the standard AWS and
GovCloud partitions through official regional endpoints. China and isolated
partitions need an explicit endpoint-partition model in a later adapter
version. It is not a generic S3-compatible adapter. A provider may use
the S3 protocol while differing on conditional writes, conditional deletes,
range responses, multipart completion, identity, or listing consistency; such
a provider needs its own versioned adapter and conformance evidence.

The initial configuration is deliberately small:

```json
{
  "region": "us-east-1",
  "bucket": "carrack-payload-example",
  "expected_bucket_owner": "123456789012",
  "prefix": "objects/"
}
```

- Skydriver derives the HTTPS virtual-hosted regional endpoint. It does not
  accept an operator-supplied origin, redirect target, or addressing style.
- The first version accepts DNS-label bucket names without dots. This avoids
  TLS and endpoint ambiguity; a later version may safely widen the grammar.
- `expected_bucket_owner` is required and signed into every provider request.
  Deleting and later recreating a bucket under another account therefore
  cannot silently rebind an existing Skydriver driver.
- `prefix` is empty or a bounded relative key prefix ending in `/`. Skydriver
  continues to generate opaque, provider-neutral storage keys beneath it.

Only long-lived IAM access-key ID and secret-access-key pairs are accepted in
v1. Session credentials and role assumption require a separate renewal design
that keeps parent authority in the control plane and projects only short-lived
object grants.

## Bucket prerequisites

Credential authorization must contact AWS and prove all prerequisites before
the encrypted credential can commit or the driver can be enabled:

1. `GetBucketLocation` agrees with the configured region and the signed
   expected owner.
2. `GetBucketVersioning` reports no enabled or suspended versioning state.
3. A Skydriver-owned random canary key can be created with `If-None-Match: *`,
   read back with exact length and range semantics, and removed with
   `If-Match: <etag>`.
4. Multipart initiate, part upload, conditional completion, readback, and
   abort probes succeed when multipart is advertised.
5. A bounded `ListObjectsV2` request can enumerate only the configured prefix.

Versioned and versioning-suspended buckets are rejected by v1. Supporting
them correctly requires carrying the exact `versionId` through publication,
download grants, inventory, conditional deletion, and orphan cleanup. Merely
deleting the current key would leave unreachable historical bytes and would
not satisfy Skydriver's server-owned lifecycle contract.

Skydriver rechecks the unversioned-bucket authority before issuing payload
grants, inventory pages, and physical object deletion. Changing bucket
versioning or replacing IAM/bucket policy outside Skydriver is an uncoordinated
administrative mutation: subsequent operations fail closed until the original
v1 prerequisites are restored. An administrator can still race a short-lived
grant after issuance; deployments requiring a closed administrative boundary
must restrict bucket-policy and versioning changes to a separately controlled
AWS role.

The recommended bucket or IAM policy also rejects `PutObject` and
`CompleteMultipartUpload` without `If-None-Match`, and rejects `DeleteObject`
without `If-Match`. Skydriver still signs and checks these conditions itself;
the policy protects against an accidentally over-broad credential used by
another tool.

## Publication and identity

Every single PUT and multipart completion signs `If-None-Match: *`. A 412 is a
key collision and may be adopted only after independent complete readback
proves exact encoded length and SHA-256. A 409 is retryable from a fresh
multipart upload and is never reported as publication success.

S3 ETags are opaque provider evidence, not content hashes. Skydriver returns
success only after reading the complete object through the issued GET grant and
verifying encoded length and SHA-256. The committed location stores the exact
key, size, ETag, driver ID, and driver revision.

Delayed physical deletion first revalidates all Skydriver reachability and lease
fences, then sends one conditional `DeleteObject` with the committed ETag in
`If-Match`. A 412 or 409 is an identity race and must not delete a replacement;
the lifecycle task is retried or blocked for reconciliation. HEAD followed by
an unconditional DELETE is forbidden.

## Direct grants

Payload bytes continue to bypass the Worker. The control plane issues SigV4
URLs lasting at most 15 minutes and returns the exact signed request headers:

- `x-amz-expected-bucket-owner` on every operation;
- `If-None-Match: *` on single PUT and multipart completion; and
- `If-Match: <committed-etag>` only to the server lifecycle executor, never as
  broad client delete authority.

The client rejects a grant if the method, host, signed-header set, expiry, or
conditional header differs from the typed grant. Download range validation,
complete encoded SHA-256, AEAD, plaintext length, and plaintext Merkle checks
remain the provider-independent chain described by [vfs-v2.md](vfs-v2.md).

## Inventory and recovery

The hosted inventory adapter performs bounded `ListObjectsV2` pages with an
opaque continuation token and the exact configured prefix. The continuation
token is a server-side cursor only; clients never receive inventory authority.
Unknown objects enter quarantine and are never adopted or deleted from one
listing observation.

Incomplete multipart uploads use the existing fenced server cleanup protocol.
The durable task pins the driver revision, storage key, and upload ID. The
control plane aborts only that upload after re-opening the current encrypted
credential and rechecking the task fence.

## Integration and acceptance gate

The compiled driver is selectable only because the following components land
in one verified release:

- strict shared contract kind, configuration, and capability posture;
- pure server normalization and authority-continuity checks;
- provider authorization probes and encrypted credential lifecycle;
- object and multipart grant projection with signed-header validation;
- native Rust upload/download dispatch using the common signed-object
  pipeline;
- bounded inventory, conditional Stat/Delete, and multipart cleanup adapters;
- management UI and `skydriverctl` validation/apply flows;
- malformed range, short/long body, collision adoption, conditional-delete
  race, owner mismatch, versioning rejection, credential rotation, inventory
  cursor, interruption, and complete-readback tests; and
- the full repository verification gate.

Unknown driver kinds continue to fail closed. Release verification proves the
local contract and deterministic protocol paths; an environment must still
complete credential authorization against its real AWS bucket before enabling
the driver.
