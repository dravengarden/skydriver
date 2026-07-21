import { createHash } from "node:crypto";

export const DEFAULT_R2_DRIVER_ID = "r2-default";
export const R2_BUCKET_WRITE_PERMISSION = "Workers R2 Storage Bucket Item Write";

function canonicalOperatorAccount(account) {
    if (typeof account !== "string" || account.length === 0 || account.length > 64) {
        return false;
    }
    const parts = account.split("@");
    return (
        parts.length <= 2 &&
        parts.every((part) => /^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$/.test(part))
    );
}

export function environmentProfile(config, environmentName, accountId) {
    if (environmentName !== "dev" && environmentName !== "prod") {
        throw new Error("environment must be dev or prod");
    }
    if (!/^[0-9a-f]{32}$/.test(accountId)) {
        throw new Error("CLOUDFLARE_ACCOUNT_ID must be a lowercase 32-character identifier");
    }
    const environment = config.env?.[environmentName];
    const endpoint = environment?.vars?.SKYDRIVER_R2_ENDPOINT;
    const operatorAccount = environment?.vars?.SKYDRIVER_OPERATOR_ACCOUNT;
    const payloadBindings = environment?.r2_buckets?.filter(
        ({ binding }) => binding === "SKYDRIVER_PAYLOAD",
    );
    const hostname = environment?.routes?.[0]?.pattern;
    if (
        typeof endpoint !== "string" ||
        !canonicalOperatorAccount(operatorAccount) ||
        payloadBindings?.length !== 1 ||
        typeof payloadBindings[0].bucket_name !== "string" ||
        typeof hostname !== "string"
    ) {
        throw new Error(`${environmentName} has an invalid default R2 environment profile`);
    }
    const expectedEndpoint = `https://${accountId}.r2.cloudflarestorage.com`;
    if (endpoint !== expectedEndpoint) {
        throw new Error(`${environmentName} R2 endpoint does not match CLOUDFLARE_ACCOUNT_ID`);
    }
    return {
        environment: environmentName,
        controlUrl: `https://${hostname}`,
        endpoint,
        operatorAccount,
        bucket: payloadBindings[0].bucket_name,
        tokenName: `carrack-${DEFAULT_R2_DRIVER_ID}-${environmentName}`,
    };
}

export function bucketResource(accountId, bucket) {
    if (!/^[0-9a-f]{32}$/.test(accountId) || !/^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/.test(bucket)) {
        throw new Error("invalid account or R2 bucket identity");
    }
    return `com.cloudflare.edge.r2.bucket.${accountId}_default_${bucket}`;
}

export function desiredTokenPolicy(accountId, bucket, permissionGroupId) {
    if (!/^[0-9a-f]{32}$/.test(permissionGroupId)) {
        throw new Error("invalid R2 bucket permission-group identity");
    }
    return {
        effect: "allow",
        resources: { [bucketResource(accountId, bucket)]: "*" },
        permission_groups: [{ id: permissionGroupId }],
    };
}

export function selectExactNamedToken(tokens, tokenName) {
    const matches = tokens.filter(({ name }) => name === tokenName);
    if (matches.length > 1) {
        throw new Error(`multiple Cloudflare tokens are named ${tokenName}`);
    }
    return matches[0] ?? null;
}

export function assertTokenPolicy(token, expectedPolicy) {
    if (token.status !== "active") {
        throw new Error("the existing environment R2 token is not active");
    }
    if (!Array.isArray(token.policies) || token.policies.length !== 1) {
        throw new Error("the existing environment R2 token has unexpected policies");
    }
    if (
        token.expires_on != null ||
        token.not_before != null ||
        (token.condition != null && Object.keys(token.condition).length > 0)
    ) {
        throw new Error("the existing environment R2 token has unsupported restrictions");
    }
    const [policy] = token.policies;
    const actualResources = Object.entries(policy.resources ?? {}).sort(([left], [right]) =>
        left.localeCompare(right),
    );
    const expectedResources = Object.entries(expectedPolicy.resources).sort(([left], [right]) =>
        left.localeCompare(right),
    );
    const actualGroups = (policy.permission_groups ?? []).map(({ id }) => id).sort();
    const expectedGroups = expectedPolicy.permission_groups.map(({ id }) => id).sort();
    if (
        policy.effect !== "allow" ||
        JSON.stringify(actualResources) !== JSON.stringify(expectedResources) ||
        JSON.stringify(actualGroups) !== JSON.stringify(expectedGroups)
    ) {
        throw new Error("the existing environment R2 token is not bucket scoped as expected");
    }
}

export function credentialFromToken(tokenId, tokenValue) {
    if (
        !/^[0-9a-f]{32}$/.test(tokenId) ||
        typeof tokenValue !== "string" ||
        tokenValue.length < 40
    ) {
        throw new Error("Cloudflare returned an invalid R2 token credential");
    }
    return {
        access_key_id: tokenId,
        secret_access_key: createHash("sha256").update(tokenValue).digest("hex"),
    };
}

export function assertManagedDriver(driver, profile) {
    if (
        driver?.id !== DEFAULT_R2_DRIVER_ID ||
        driver.kind !== "r2/v1" ||
        driver.lifecycle_owner !== "environment" ||
        driver.config?.endpoint !== profile.endpoint ||
        driver.config?.bucket !== profile.bucket ||
        driver.config?.prefix !== "" ||
        driver.config?.managed !== true
    ) {
        throw new Error("r2-default does not match the committed environment profile");
    }
}

export function hasBootstrappedVfs(filesystems) {
    if (!Array.isArray(filesystems)) {
        throw new Error("management snapshot omitted filesystems");
    }
    return filesystems.length > 0;
}

export function desiredRootPlacements(policy) {
    if (!Number.isSafeInteger(policy?.placement_revision) || !Array.isArray(policy.placements)) {
        throw new Error("invalid root placement policy");
    }
    const existing = policy.placements.map(({ driver_id: driverId, write_priority: priority }) => {
        if (
            typeof driverId !== "string" ||
            driverId.length === 0 ||
            !Number.isSafeInteger(priority) ||
            priority !== 0
        ) {
            throw new Error("invalid root placement entry");
        }
        return { driverId, priority };
    });
    if (existing.length > 1) {
        throw new Error("root must have at most one effective driver");
    }
    if (existing.some(({ driverId }) => driverId === DEFAULT_R2_DRIVER_ID)) {
        return { action: "present", placements: existing };
    }
    if (existing.length === 0) {
        return {
            action: "add-to-empty-root",
            placements: [{ driverId: DEFAULT_R2_DRIVER_ID, priority: 0 }],
        };
    }
    return { action: "preserve-other-default", placements: existing };
}

export function stableKey(prefix, value) {
    return `${prefix}-${createHash("sha256").update(value).digest("hex").slice(0, 24)}`;
}
