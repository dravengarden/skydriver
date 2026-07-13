import { randomUUID } from "node:crypto";
import { spawnSync } from "node:child_process";
import path from "node:path";

const environmentName = process.argv[2];
if (environmentName !== "dev" && environmentName !== "prod") {
    throw new Error("usage: deploy-worker.mjs <dev|prod>");
}
if (environmentName === "prod" && process.env.CARRACK_DEPLOY_PROD !== "1") {
    throw new Error("set CARRACK_DEPLOY_PROD=1 to deploy production");
}

const repositoryRoot = path.resolve(import.meta.dirname, "../..");
const configPath = path.join(repositoryRoot, "control-plane/wrangler.jsonc");
const timestamp = new Date().toISOString().replaceAll(/[-:.]/g, "").replace("Z", "Z");
const tag = `${environmentName}-${timestamp}-${randomUUID().slice(0, 8)}`;

function wrangler(args) {
    const result = spawnSync("pnpm", ["exec", "wrangler", ...args], {
        cwd: repositoryRoot,
        stdio: "inherit",
    });
    if (result.status !== 0) {
        throw new Error(`wrangler ${args.join(" ")} failed`);
    }
}

wrangler([
    "versions",
    "upload",
    "--env",
    environmentName,
    "--config",
    configPath,
    "--tag",
    tag,
]);
wrangler([
    "versions",
    "deploy",
    "--env",
    environmentName,
    "--config",
    configPath,
    "--version-tag",
    tag,
    "--message",
    `Deploy verified Carrack ${environmentName} version`,
    "--yes",
]);
