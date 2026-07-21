import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const sha256 = (value) => createHash("sha256").update(value).digest("hex");

export function deploymentAcceptanceProfile(config, environmentName, assetsDirectory) {
    if (environmentName !== "dev" && environmentName !== "prod") {
        throw new Error("deployment environment must be dev or prod");
    }
    const environment = config.env?.[environmentName];
    const routes = environment?.routes?.filter(({ custom_domain: customDomain }) => customDomain);
    if (routes?.length !== 1) {
        throw new Error(`${environmentName} must define one custom domain`);
    }
    const hostname = routes[0].pattern;
    if (
        typeof hostname !== "string" ||
        !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(hostname)
    ) {
        throw new Error(`${environmentName} has an invalid custom domain`);
    }
    const indexPath = path.join(assetsDirectory, "index.html");
    const indexHtml = fs.readFileSync(indexPath, "utf8");
    const scriptPaths = [...indexHtml.matchAll(/\bsrc="(\/assets\/[A-Za-z0-9._-]+\.js)"/g)].map(
        ([, scriptPath]) => scriptPath,
    );
    if (scriptPaths.length !== 1) {
        throw new Error("built UI index must reference one hashed JavaScript asset");
    }
    const [scriptPath] = scriptPaths;
    const scriptBytes = fs.readFileSync(path.join(assetsDirectory, scriptPath.slice(1)));
    return {
        environment: environmentName,
        controlUrl: `https://${hostname}`,
        scriptPath,
        scriptSha256: sha256(scriptBytes),
    };
}

async function checkedResponse(fetchImplementation, url, label, accept) {
    const response = await fetchImplementation(url, {
        headers: { Accept: accept },
        signal: AbortSignal.timeout(10_000),
    });
    if (!response.ok) {
        throw new Error(`${label} returned HTTP ${response.status}`);
    }
    return response;
}

async function probe(profile, deploymentTag, attempt, fetchImplementation) {
    const query = new URLSearchParams({ deployment: deploymentTag, attempt: String(attempt) });
    const url = (pathname) => new URL(`${pathname}?${query}`, profile.controlUrl);
    const healthResponse = await checkedResponse(
        fetchImplementation,
        url("/api/health"),
        "health endpoint",
        "application/json",
    );
    const health = await healthResponse.json();
    if (health?.service !== "skydriver-control-plane" || health.environment !== profile.environment) {
        throw new Error("health endpoint reported the wrong deployment identity");
    }
    const wasmResponse = await checkedResponse(
        fetchImplementation,
        url("/api/acceptance/wasm-sdk"),
        "WASM SDK acceptance",
        "application/json",
    );
    const wasm = await wasmResponse.json();
    if (wasm?.schema !== "carrack.sdk.wasm-acceptance.v1" || wasm.round_trip_verified !== true) {
        throw new Error("WASM SDK acceptance did not verify its round trip");
    }
    const indexResponse = await checkedResponse(
        fetchImplementation,
        url("/"),
        "UI index",
        "text/html",
    );
    const indexHtml = await indexResponse.text();
    if (!indexHtml.includes(`src="${profile.scriptPath}"`)) {
        throw new Error("UI index does not reference the deployed asset");
    }
    const scriptResponse = await checkedResponse(
        fetchImplementation,
        url(profile.scriptPath),
        "UI asset",
        "application/javascript",
    );
    const scriptBytes = Buffer.from(await scriptResponse.arrayBuffer());
    if (sha256(scriptBytes) !== profile.scriptSha256) {
        throw new Error("deployed UI asset hash differs from the verified build");
    }
    return {
        schema: "carrack.deployment-acceptance.v1",
        environment: profile.environment,
        control_url: profile.controlUrl,
        sdk_version: wasm.sdk_version,
        script_path: profile.scriptPath,
        script_sha256: profile.scriptSha256,
        attempt,
        accepted: true,
    };
}

export async function waitForDeploymentAcceptance(
    profile,
    deploymentTag,
    {
        fetchImplementation = fetch,
        sleep = (milliseconds) =>
            new Promise((resolve) => {
                setTimeout(resolve, milliseconds);
            }),
        maximumAttempts = 12,
    } = {},
) {
    if (!/^[A-Za-z0-9._-]{1,128}$/.test(deploymentTag)) {
        throw new Error("deployment tag is invalid");
    }
    if (!Number.isSafeInteger(maximumAttempts) || maximumAttempts < 1 || maximumAttempts > 30) {
        throw new Error("deployment acceptance attempt bound is invalid");
    }
    let lastError;
    for (let attempt = 1; attempt <= maximumAttempts; attempt += 1) {
        try {
            return await probe(profile, deploymentTag, attempt, fetchImplementation);
        } catch (error) {
            lastError = error;
            if (attempt !== maximumAttempts) {
                await sleep(Math.min(500 * 2 ** (attempt - 1), 5_000));
            }
        }
    }
    const detail = lastError instanceof Error ? lastError.message : "unknown acceptance failure";
    throw new Error(
        `${profile.environment} deployment acceptance failed after ${maximumAttempts} attempts: ${detail}`,
    );
}
