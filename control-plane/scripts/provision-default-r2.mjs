import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import {
    DEFAULT_R2_DRIVER_ID,
    R2_BUCKET_WRITE_PERMISSION,
    assertManagedDriver,
    assertTokenPolicy,
    credentialFromToken,
    desiredRootPlacements,
    desiredTokenPolicy,
    environmentProfile,
    hasBootstrappedVfs,
    selectExactNamedToken,
    stableKey,
} from "./default-r2-provisioning.mjs";

const [environmentName, ...options] = process.argv.slice(2);
const allowedOptions = new Set(["--check", "--append-root-placement", "--recover-existing-token"]);
if (
    (environmentName !== "dev" && environmentName !== "prod") ||
    options.some((option) => !allowedOptions.has(option))
) {
    throw new Error(
        "usage: provision-default-r2.mjs <dev|prod> [--check] " +
            "[--append-root-placement] [--recover-existing-token]",
    );
}
const check = options.includes("--check");
const appendRootPlacement = options.includes("--append-root-placement");
const recoverExistingToken = options.includes("--recover-existing-token");
if (!check && process.env.CARRACK_PROVISION_R2 !== "1") {
    throw new Error("set CARRACK_PROVISION_R2=1 to authorize environment R2 provisioning");
}
if (!check && environmentName === "prod" && process.env.CARRACK_PROVISION_PROD !== "1") {
    throw new Error("set CARRACK_PROVISION_PROD=1 to authorize production provisioning");
}
if (!check && recoverExistingToken && process.env.CARRACK_RECOVER_R2_TOKEN !== "1") {
    throw new Error("set CARRACK_RECOVER_R2_TOKEN=1 to authorize an existing-token recovery");
}

const requiredEnvironment = [
    "CLOUDFLARE_ACCOUNT_ID",
    "CARRACK_OPERATOR_CREDENTIAL",
];
for (const name of requiredEnvironment) {
    if (!process.env[name]) throw new Error(`${name} is required`);
}

const repositoryRoot = path.resolve(import.meta.dirname, "../..");
const config = JSON.parse(
    fs.readFileSync(path.join(repositoryRoot, "control-plane/wrangler.jsonc"), "utf8"),
);
const profile = environmentProfile(config, environmentName, process.env.CLOUDFLARE_ACCOUNT_ID);
if (process.env.CARRACK_CONTROL_URL && process.env.CARRACK_CONTROL_URL !== profile.controlUrl) {
    throw new Error("CARRACK_CONTROL_URL does not match the selected environment");
}
const carrackctl = path.resolve(
    repositoryRoot,
    process.env.CARRACKCTL_BIN ?? "target/debug/carrackctl",
);
fs.accessSync(carrackctl, fs.constants.X_OK);

function runCarrackctl(arguments_) {
    const childEnvironment = { ...process.env, CARRACK_CONTROL_URL: profile.controlUrl };
    delete childEnvironment.CLOUDFLARE_TOKEN_FACTORY_API_TOKEN;
    delete childEnvironment.CLOUDFLARE_API_TOKEN;
    if (arguments_[0] === "vfs") {
        delete childEnvironment.CARRACK_OPERATOR_CREDENTIAL;
    } else if (arguments_[0] === "compatibility") {
        delete childEnvironment.CARRACK_OPERATOR_CREDENTIAL;
        delete childEnvironment.CARRACK_VFS_TOKEN;
    } else {
        delete childEnvironment.CARRACK_VFS_TOKEN;
    }
    const result = spawnSync(carrackctl, arguments_, {
        cwd: repositoryRoot,
        encoding: "utf8",
        env: childEnvironment,
        maxBuffer: 16 * 1024 * 1024,
    });
    if (result.status !== 0) {
        const detail = result.stderr.trim();
        throw new Error(
            `carrackctl ${arguments_.slice(0, 3).join(" ")} failed${detail ? `: ${detail}` : ""}`,
        );
    }
    try {
        return JSON.parse(result.stdout);
    } catch {
        throw new Error("carrackctl returned invalid JSON");
    }
}

function snapshot() {
    return runCarrackctl(["snapshot", "--control-url", profile.controlUrl, "--format", "json"]);
}

function rootPlacements() {
    return runCarrackctl([
        "vfs",
        "placement",
        "show",
        "/",
        "--control-url",
        profile.controlUrl,
        "--format",
        "json",
    ]);
}

async function cloudflareApi(apiPath, init = {}) {
    const token = process.env.CLOUDFLARE_TOKEN_FACTORY_API_TOKEN;
    if (!token) {
        throw new Error(
            "CLOUDFLARE_TOKEN_FACTORY_API_TOKEN is required while r2-default has no credential",
        );
    }
    const response = await fetch(`https://api.cloudflare.com/client/v4${apiPath}`, {
        ...init,
        signal: AbortSignal.timeout(30_000),
        headers: {
            Authorization: `Bearer ${token}`,
            ...(init.body === undefined ? {} : { "Content-Type": "application/json" }),
            ...init.headers,
        },
    });
    const body = await response.json();
    if (!response.ok || body.success !== true) {
        throw new Error(`Cloudflare API request failed for ${apiPath}`);
    }
    return body;
}

async function listAccountTokens() {
    const tokens = [];
    for (let page = 1; ; page += 1) {
        const response = await cloudflareApi(
            `/accounts/${process.env.CLOUDFLARE_ACCOUNT_ID}/tokens?page=${String(page)}&per_page=50`,
        );
        tokens.push(...(response.result ?? []));
        const totalPages = response.result_info?.total_pages;
        if (
            (Number.isInteger(totalPages) && page >= totalPages) ||
            (!Number.isInteger(totalPages) && (response.result?.length ?? 0) < 50)
        ) {
            return tokens;
        }
    }
}

async function inspectTokenFactory() {
    const accountId = process.env.CLOUDFLARE_ACCOUNT_ID;
    const [permissionResponse, tokens] = await Promise.all([
        cloudflareApi(`/accounts/${accountId}/tokens/permission_groups`),
        listAccountTokens(),
    ]);
    const groups = (permissionResponse.result ?? []).filter(
        ({ name, scopes }) =>
            name === R2_BUCKET_WRITE_PERMISSION &&
            Array.isArray(scopes) &&
            scopes.includes("com.cloudflare.edge.r2.bucket"),
    );
    if (groups.length !== 1 || !/^[0-9a-f]{32}$/.test(groups[0].id)) {
        throw new Error("Cloudflare did not expose one exact R2 bucket-item write permission");
    }
    const policy = desiredTokenPolicy(accountId, profile.bucket, groups[0].id);
    const existing = selectExactNamedToken(tokens, profile.tokenName);
    if (existing === null) return { action: "create", existing: null, policy };
    const detail = await cloudflareApi(`/accounts/${accountId}/tokens/${existing.id}`);
    assertTokenPolicy(detail.result, policy);
    return { action: "recover", existing: detail.result, policy };
}

runCarrackctl(["compatibility", "--control-url", profile.controlUrl, "--format", "json"]);
let management = snapshot();
let driver = management.drivers.find(({ id }) => id === DEFAULT_R2_DRIVER_ID);
assertManagedDriver(driver, profile);
const hasVfs = hasBootstrappedVfs(management.filesystems);
if (hasVfs && !process.env.CARRACK_VFS_TOKEN) {
    throw new Error("CARRACK_VFS_TOKEN is required after VFS bootstrap");
}
let placementPolicy = hasVfs ? rootPlacements() : null;
let placementPlan = hasVfs
    ? desiredRootPlacements(placementPolicy, appendRootPlacement)
    : { action: "not-applicable", placements: [] };
let tokenPlan = null;
if (!driver.credential_present) tokenPlan = await inspectTokenFactory();

if (check) {
    console.log(
        JSON.stringify(
            {
                schema: "carrack.environment-r2-provision-plan.v1",
                environment: environmentName,
                control_url: profile.controlUrl,
                driver_id: DEFAULT_R2_DRIVER_ID,
                bucket: profile.bucket,
                credential: driver.credential_present ? "present" : tokenPlan.action,
                driver_state: driver.enabled ? "enabled" : "enable",
                root_placement: placementPlan.action,
                token_name: profile.tokenName,
            },
            null,
            2,
        ),
    );
    process.exit(0);
}

if (tokenPlan?.action === "recover" && !recoverExistingToken) {
    throw new Error(
        "a scoped environment token already exists while Carrack has no credential; " +
            "run --check, exclude parallel provisioners, then use --recover-existing-token",
    );
}

let credentialAction = "present";
if (!driver.credential_present) {
    const accountId = process.env.CLOUDFLARE_ACCOUNT_ID;
    let tokenId;
    let tokenValue;
    if (tokenPlan.action === "create") {
        const response = await cloudflareApi(`/accounts/${accountId}/tokens`, {
            method: "POST",
            body: JSON.stringify({ name: profile.tokenName, policies: [tokenPlan.policy] }),
        });
        tokenId = response.result?.id;
        tokenValue = response.result?.value;
        credentialFromToken(tokenId, tokenValue);
        const observed = selectExactNamedToken(await listAccountTokens(), profile.tokenName);
        if (observed?.id !== tokenId) {
            try {
                await cloudflareApi(`/accounts/${accountId}/tokens/${tokenId}`, {
                    method: "DELETE",
                });
            } catch {
                console.error(
                    "warning: failed to remove this provisioner's token after a naming race",
                );
            }
            throw new Error(
                "environment R2 token creation raced with another provisioner; inspect and retry",
            );
        }
        const detail = await cloudflareApi(`/accounts/${accountId}/tokens/${tokenId}`);
        assertTokenPolicy(detail.result, tokenPlan.policy);
        credentialAction = "created";
    } else {
        tokenId = tokenPlan.existing.id;
        const response = await cloudflareApi(`/accounts/${accountId}/tokens/${tokenId}/value`, {
            method: "PUT",
            body: "{}",
        });
        tokenValue = response.result;
        credentialAction = "recovered";
    }
    const credential = credentialFromToken(tokenId, tokenValue);
    const temporaryDirectory = fs.mkdtempSync(path.join(os.tmpdir(), "carrack-r2-"));
    fs.chmodSync(temporaryDirectory, 0o700);
    const credentialFile = path.join(temporaryDirectory, "credential.json");
    try {
        fs.writeFileSync(credentialFile, JSON.stringify(credential), { mode: 0o600, flag: "wx" });
        const baseArguments = [
            "driver",
            "credential",
            "set",
            DEFAULT_R2_DRIVER_ID,
            "--control-url",
            profile.controlUrl,
            "--credential-file",
            credentialFile,
            "--expected-revision",
            String(driver.revision),
        ];
        const validation = runCarrackctl([...baseArguments, "--check", "--format", "json"]);
        if (
            validation.driver_id !== DEFAULT_R2_DRIVER_ID ||
            validation.expected_revision !== driver.revision
        ) {
            throw new Error("r2-default credential validation did not match the inspected state");
        }
        runCarrackctl([
            ...baseArguments,
            "--idempotency-key",
            stableKey(
                `environment-r2-${environmentName}-credential-r${String(driver.revision)}`,
                tokenId,
            ),
            "--format",
            "json",
        ]);
    } finally {
        fs.rmSync(temporaryDirectory, { recursive: true, force: true });
    }
    management = snapshot();
    driver = management.drivers.find(({ id }) => id === DEFAULT_R2_DRIVER_ID);
    assertManagedDriver(driver, profile);
    if (!driver.credential_present) {
        throw new Error("r2-default credential was not present after verified apply");
    }
}

if (!driver.enabled) {
    const baseArguments = [
        "driver",
        "enable",
        DEFAULT_R2_DRIVER_ID,
        "--control-url",
        profile.controlUrl,
        "--expected-revision",
        String(driver.revision),
    ];
    const validation = runCarrackctl([...baseArguments, "--check", "--format", "json"]);
    if (
        validation.driver_id !== DEFAULT_R2_DRIVER_ID ||
        validation.expected_revision !== driver.revision ||
        validation.enabled !== true
    ) {
        throw new Error("r2-default enable validation did not match the inspected state");
    }
    runCarrackctl([
        ...baseArguments,
        "--idempotency-key",
        `environment-r2-${environmentName}-enable-r${String(driver.revision)}`,
        "--format",
        "json",
    ]);
    management = snapshot();
    driver = management.drivers.find(({ id }) => id === DEFAULT_R2_DRIVER_ID);
    assertManagedDriver(driver, profile);
    if (!driver.enabled) throw new Error("r2-default was not enabled after verified apply");
}

if (hasVfs) {
    placementPolicy = rootPlacements();
    placementPlan = desiredRootPlacements(placementPolicy, appendRootPlacement);
}
if (
    placementPolicy !== null &&
    (placementPlan.action === "add-to-empty-root" || placementPlan.action === "append-to-root")
) {
    const encoded = placementPlan.placements
        .map(({ driverId, priority }) => `${driverId}:${String(priority)}`)
        .join(",");
    runCarrackctl([
        "vfs",
        "placement",
        "replace",
        "/",
        "--control-url",
        profile.controlUrl,
        "--placement",
        encoded,
        "--expected-revision",
        String(placementPolicy.placement_revision),
        "--idempotency-key",
        stableKey(
            `environment-r2-${environmentName}-root-r${String(placementPolicy.placement_revision)}`,
            encoded,
        ),
        "--format",
        "json",
    ]);
    placementPolicy = rootPlacements();
    const effective = desiredRootPlacements(placementPolicy, false);
    if (effective.action !== "present") {
        throw new Error("r2-default root placement did not match the verified replacement");
    }
    placementPlan = { ...placementPlan, action: "applied" };
} else if (placementPlan.action === "preserve-nonempty-root") {
    console.error(
        "warning: root already has placements; r2-default was enabled but policy was preserved. " +
            "Re-run with --append-root-placement only after reviewing the complete root policy.",
    );
}

console.log(
    JSON.stringify(
        {
            schema: "carrack.environment-r2-provision-receipt.v1",
            environment: environmentName,
            control_url: profile.controlUrl,
            driver_id: DEFAULT_R2_DRIVER_ID,
            bucket: profile.bucket,
            credential: credentialAction,
            driver_state: "enabled",
            driver_revision: driver.revision,
            root_placement: placementPlan.action,
            token_name: profile.tokenName,
        },
        null,
        2,
    ),
);
