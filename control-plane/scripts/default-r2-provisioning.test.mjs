import assert from "node:assert/strict";
import test from "node:test";

import {
    assertManagedDriver,
    assertTokenPolicy,
    bucketResource,
    credentialFromToken,
    desiredRootPlacements,
    desiredTokenPolicy,
    environmentProfile,
    hasBootstrappedVfs,
    selectExactNamedToken,
    stableKey,
} from "./default-r2-provisioning.mjs";

const accountId = "0123456789abcdef0123456789abcdef";
const bucket = "carrack-payload-dev";

test("derives an exact environment profile and bucket-only policy", () => {
    const profile = environmentProfile(
        {
            env: {
                dev: {
                    routes: [{ pattern: "dev.carrack.example" }],
                    vars: {
                        CARRACK_R2_ENDPOINT: `https://${accountId}.r2.cloudflarestorage.com`,
                        CARRACK_OPERATOR_ACCOUNT: "draven@carrack-dev",
                    },
                    r2_buckets: [{ binding: "CARRACK_PAYLOAD", bucket_name: bucket }],
                },
            },
        },
        "dev",
        accountId,
    );
    assert.deepEqual(profile, {
        environment: "dev",
        controlUrl: "https://dev.carrack.example",
        endpoint: `https://${accountId}.r2.cloudflarestorage.com`,
        operatorAccount: "draven@carrack-dev",
        bucket,
        tokenName: "carrack-r2-default-dev",
    });
    assert.equal(
        bucketResource(accountId, bucket),
        `com.cloudflare.edge.r2.bucket.${accountId}_default_${bucket}`,
    );
    assert.deepEqual(desiredTokenPolicy(accountId, bucket, accountId), {
        effect: "allow",
        resources: {
            [`com.cloudflare.edge.r2.bucket.${accountId}_default_${bucket}`]: "*",
        },
        permission_groups: [{ id: accountId }],
    });
});

test("rejects ambiguous tokens and policies broader than one bucket", () => {
    assert.throws(
        () =>
            selectExactNamedToken(
                [{ name: "carrack-r2-default-dev" }, { name: "carrack-r2-default-dev" }],
                "carrack-r2-default-dev",
            ),
        /multiple Cloudflare tokens/,
    );
    const desired = desiredTokenPolicy(accountId, bucket, accountId);
    assert.doesNotThrow(() =>
        assertTokenPolicy(
            {
                status: "active",
                policies: [{ ...desired, id: "ignored" }],
            },
            desired,
        ),
    );
    assert.throws(
        () =>
            assertTokenPolicy(
                {
                    status: "active",
                    policies: [
                        {
                            ...desired,
                            resources: { "com.cloudflare.api.account.*": "*" },
                        },
                    ],
                },
                desired,
            ),
        /not bucket scoped/,
    );
    assert.throws(
        () =>
            assertTokenPolicy(
                {
                    status: "active",
                    expires_on: "2026-08-01T00:00:00Z",
                    policies: [desired],
                },
                desired,
            ),
        /unsupported restrictions/,
    );
});

test("derives the documented S3 credential without exposing token value", () => {
    assert.deepEqual(credentialFromToken(accountId, "x".repeat(40)), {
        access_key_id: accountId,
        secret_access_key: "bd913ff68243d41b9611b2690dfbf2b0f6e42ea14536a98232af60e9f64ffdaa",
    });
});

test("validates environment-owned driver identity", () => {
    const profile = {
        endpoint: `https://${accountId}.r2.cloudflarestorage.com`,
        bucket,
    };
    assert.doesNotThrow(() =>
        assertManagedDriver(
            {
                id: "r2-default",
                kind: "r2/v1",
                lifecycle_owner: "environment",
                config: { endpoint: profile.endpoint, bucket, prefix: "", managed: true },
            },
            profile,
        ),
    );
    assert.throws(
        () =>
            assertManagedDriver(
                {
                    id: "r2-default",
                    kind: "r2/v1",
                    lifecycle_owner: "operator",
                    config: { endpoint: profile.endpoint, bucket, prefix: "", managed: true },
                },
                profile,
            ),
        /committed environment profile/,
    );
});

test("sets only an empty legacy root and preserves another default", () => {
    assert.deepEqual(desiredRootPlacements({ placement_revision: 1, placements: [] }), {
        action: "add-to-empty-root",
        placements: [{ driverId: "r2-default", priority: 0 }],
    });
    const existing = {
        placement_revision: 4,
        placements: [{ driver_id: "aliyun-dev", write_priority: 0 }],
    };
    assert.equal(desiredRootPlacements(existing).action, "preserve-other-default");
    assert.throws(
        () =>
            desiredRootPlacements({
                placement_revision: 5,
                placements: [
                    { driver_id: "aliyun-dev", write_priority: 0 },
                    { driver_id: "r2-default", write_priority: 10 },
                ],
            }),
        /invalid root placement|at most one/,
    );
});

test("requires VFS authority only after bootstrap", () => {
    assert.equal(hasBootstrappedVfs([]), false);
    assert.equal(hasBootstrappedVfs([{ id: "vfs" }]), true);
    assert.throws(() => hasBootstrappedVfs(undefined), /omitted filesystems/);
});

test("stable mutation keys contain no provider credential", () => {
    assert.equal(stableKey("r2-dev", "secret"), stableKey("r2-dev", "secret"));
    assert.doesNotMatch(stableKey("r2-dev", "secret"), /secret/);
});
