import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const environmentName = process.argv[2];
if (environmentName !== "dev" && environmentName !== "prod") {
    throw new Error("usage: rotate-operator-credential.mjs <dev|prod>");
}
if (environmentName === "prod" && process.env.SKYDRIVER_ROTATE_OPERATOR_PROD !== "1") {
    throw new Error("set SKYDRIVER_ROTATE_OPERATOR_PROD=1 to rotate production credentials");
}

const credential = fs.readFileSync(0, "utf8").trim();
if (!/^[A-Za-z0-9_-]{43}$/.test(credential)) {
    throw new Error("operator credential must be canonical unpadded base64url");
}
const decoded = Buffer.from(credential, "base64url");
if (decoded.length !== 32 || decoded.every((byte) => byte === 0)) {
    throw new Error("operator credential must encode exactly 32 nonzero bytes");
}

const repositoryRoot = path.resolve(import.meta.dirname, "../..");
const configPath = path.resolve(
    process.env.SKYDRIVER_WRANGLER_CONFIG ??
        path.join(repositoryRoot, "control-plane/wrangler.jsonc"),
);
const result = spawnSync(
    "pnpm",
    [
        "exec",
        "wrangler",
        "secret",
        "put",
        "SKYDRIVER_ADMIN_TOKEN",
        "--env",
        environmentName,
        "--config",
        configPath,
    ],
    {
        cwd: repositoryRoot,
        input: `${credential}\n`,
        stdio: ["pipe", "inherit", "inherit"],
    },
);
if (result.status !== 0) {
    throw new Error(`operator credential rotation failed for ${environmentName}`);
}

console.log(`${environmentName}: rotated operator credential only`);
