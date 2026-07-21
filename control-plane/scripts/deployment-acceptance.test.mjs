import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
    deploymentAcceptanceProfile,
    waitForDeploymentAcceptance,
} from "./deployment-acceptance.mjs";

function fixture() {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "carrack-deploy-acceptance-"));
    fs.mkdirSync(path.join(directory, "assets"));
    fs.writeFileSync(
        path.join(directory, "index.html"),
        '<!doctype html><script type="module" src="/assets/index-test.js"></script>',
    );
    fs.writeFileSync(path.join(directory, "assets/index-test.js"), "console.log('carrack');\n");
    return directory;
}

const config = {
    env: {
        dev: {
            routes: [{ pattern: "dev.skydriver.example", custom_domain: true }],
        },
    },
};

test("derives one exact custom-domain profile and verified UI asset", () => {
    const directory = fixture();
    try {
        const profile = deploymentAcceptanceProfile(config, "dev", directory);
        assert.equal(profile.controlUrl, "https://dev.skydriver.example");
        assert.equal(profile.scriptPath, "/assets/index-test.js");
        assert.match(profile.scriptSha256, /^[0-9a-f]{64}$/);
        assert.throws(
            () =>
                deploymentAcceptanceProfile(
                    {
                        env: {
                            dev: {
                                routes: [
                                    { pattern: "one.example", custom_domain: true },
                                    { pattern: "two.example", custom_domain: true },
                                ],
                            },
                        },
                    },
                    "dev",
                    directory,
                ),
            /one custom domain/,
        );
    } finally {
        fs.rmSync(directory, { recursive: true, force: true });
    }
});

test("retries edge propagation and accepts only the exact environment and UI build", async () => {
    const directory = fixture();
    try {
        const profile = deploymentAcceptanceProfile(config, "dev", directory);
        const script = fs.readFileSync(path.join(directory, "assets/index-test.js"));
        const requests = [];
        const sleeps = [];
        const fetchImplementation = async (input) => {
            const url = new URL(input);
            requests.push(url);
            const attempt = Number(url.searchParams.get("attempt"));
            if (attempt === 1 && url.pathname === "/api/acceptance/wasm-sdk") {
                return new Response("not propagated", { status: 404 });
            }
            if (url.pathname === "/api/health") {
                return Response.json({ service: "skydriver-control-plane", environment: "dev" });
            }
            if (url.pathname === "/api/acceptance/wasm-sdk") {
                return Response.json({
                    schema: "carrack.sdk.wasm-acceptance.v1",
                    sdk_version: "0.3.6",
                    round_trip_verified: true,
                });
            }
            if (url.pathname === "/") {
                return new Response(
                    '<!doctype html><script type="module" src="/assets/index-test.js"></script>',
                );
            }
            if (url.pathname === "/assets/index-test.js") {
                return new Response(script);
            }
            return new Response("unexpected", { status: 500 });
        };
        const receipt = await waitForDeploymentAcceptance(profile, "dev-verified", {
            fetchImplementation,
            sleep: async (milliseconds) => sleeps.push(milliseconds),
            maximumAttempts: 3,
        });
        assert.equal(receipt.accepted, true);
        assert.equal(receipt.attempt, 2);
        assert.deepEqual(sleeps, [500]);
        assert.ok(requests.every((url) => url.searchParams.get("deployment") === "dev-verified"));
    } finally {
        fs.rmSync(directory, { recursive: true, force: true });
    }
});

test("fails closed when the deployed UI bytes do not match", async () => {
    const directory = fixture();
    try {
        const profile = deploymentAcceptanceProfile(config, "dev", directory);
        const fetchImplementation = async (input) => {
            const { pathname } = new URL(input);
            if (pathname === "/api/health") {
                return Response.json({ service: "skydriver-control-plane", environment: "dev" });
            }
            if (pathname === "/api/acceptance/wasm-sdk") {
                return Response.json({
                    schema: "carrack.sdk.wasm-acceptance.v1",
                    sdk_version: "0.3.6",
                    round_trip_verified: true,
                });
            }
            if (pathname === "/") {
                return new Response(
                    '<!doctype html><script type="module" src="/assets/index-test.js"></script>',
                );
            }
            return new Response("wrong asset");
        };
        await assert.rejects(
            waitForDeploymentAcceptance(profile, "dev-wrong-asset", {
                fetchImplementation,
                sleep: async () => {},
                maximumAttempts: 2,
            }),
            /deployed UI asset hash differs/,
        );
    } finally {
        fs.rmSync(directory, { recursive: true, force: true });
    }
});

test("fails closed when the custom domain resolves to another environment", async () => {
    const directory = fixture();
    try {
        const profile = deploymentAcceptanceProfile(config, "dev", directory);
        await assert.rejects(
            waitForDeploymentAcceptance(profile, "dev-wrong-environment", {
                fetchImplementation: async () =>
                    Response.json({ service: "skydriver-control-plane", environment: "prod" }),
                sleep: async () => {},
                maximumAttempts: 1,
            }),
            /wrong deployment identity/,
        );
    } finally {
        fs.rmSync(directory, { recursive: true, force: true });
    }
});
