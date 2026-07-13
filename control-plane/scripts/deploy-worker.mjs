import { randomUUID } from "node:crypto";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const environmentName = process.argv[2];
if (environmentName !== "dev" && environmentName !== "prod") {
    throw new Error("usage: deploy-worker.mjs <dev|prod>");
}
if (environmentName === "prod" && process.env.CARRACK_DEPLOY_PROD !== "1") {
    throw new Error("set CARRACK_DEPLOY_PROD=1 to deploy production");
}
const accountId = process.env.CLOUDFLARE_ACCOUNT_ID;
const apiToken = process.env.CLOUDFLARE_API_TOKEN;
if (accountId === undefined || apiToken === undefined) {
    throw new Error("CLOUDFLARE_ACCOUNT_ID and CLOUDFLARE_API_TOKEN are required");
}

const repositoryRoot = path.resolve(import.meta.dirname, "../..");
const configPath = path.join(repositoryRoot, "control-plane/wrangler.jsonc");
const config = JSON.parse(fs.readFileSync(configPath, "utf8"));
const environment = config.env?.[environmentName];
const workerName = environment?.name;
const cronSchedules = environment?.triggers?.crons;
if (
    typeof workerName !== "string" ||
    !Array.isArray(cronSchedules) ||
    cronSchedules.length === 0 ||
    cronSchedules.some((cron) => typeof cron !== "string")
) {
    throw new Error(`${environmentName} must define a Worker name and Cron schedules`);
}
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

// Sync schedules through the account-scoped API. `wrangler triggers deploy`
// also reads custom-domain routes and therefore requires the zone-scoped
// Workers Routes permission that Carrack deliberately excludes from its
// routine deploy token.
const scheduleResponse = await fetch(
    `https://api.cloudflare.com/client/v4/accounts/${accountId}` +
        `/workers/scripts/${workerName}/schedules`,
    {
        method: "PUT",
        headers: {
            Authorization: `Bearer ${apiToken}`,
            "Content-Type": "application/json",
        },
        body: JSON.stringify(cronSchedules.map((cron) => ({ cron }))),
    },
);
const scheduleBody = await scheduleResponse.json();
if (!scheduleResponse.ok || scheduleBody.success !== true) {
    throw new Error(`failed to synchronize ${environmentName} Cron schedules`);
}
const deployedSchedules = (scheduleBody.result?.schedules ?? []).map(({ cron }) => cron).sort();
if (JSON.stringify(deployedSchedules) !== JSON.stringify([...cronSchedules].sort())) {
    throw new Error(`${environmentName} Cron schedules failed post-deploy verification`);
}
console.log(`${environmentName}: synchronized ${deployedSchedules.length} Cron schedule(s)`);
