import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const environmentName = process.argv[2];
if (environmentName !== "dev" && environmentName !== "prod") {
    throw new Error("usage: apply-migrations.mjs <dev|prod>");
}
if (environmentName === "prod" && process.env.SKYDRIVER_MIGRATE_PROD !== "1") {
    throw new Error("set SKYDRIVER_MIGRATE_PROD=1 to migrate production");
}

const accountId = process.env.CLOUDFLARE_ACCOUNT_ID;
const apiToken = process.env.CLOUDFLARE_API_TOKEN;
if ((accountId === undefined) !== (apiToken === undefined)) {
    throw new Error(
        "CLOUDFLARE_ACCOUNT_ID and CLOUDFLARE_API_TOKEN must be provided together",
    );
}

const repositoryRoot = path.resolve(import.meta.dirname, "../..");
const configPath = path.join(repositoryRoot, "control-plane/wrangler.jsonc");
const migrationsPath = path.join(repositoryRoot, "control-plane/migrations");
const config = JSON.parse(fs.readFileSync(configPath, "utf8"));
const environment = config.env?.[environmentName];
const databases = environment?.d1_databases;
if (!Array.isArray(databases) || databases.length !== 1) {
    throw new Error(`${environmentName} must define exactly one D1 database`);
}
const databaseId = databases[0].database_id;

async function query(sql) {
    if (accountId === undefined) {
        const result = spawnSync(
            "pnpm",
            [
                "exec",
                "wrangler",
                "d1",
                "execute",
                "SKYDRIVER_INDEX",
                "--remote",
                "--env",
                environmentName,
                "--command",
                sql,
                "--config",
                configPath,
                "--json",
            ],
            { cwd: repositoryRoot, encoding: "utf8" },
        );
        if (result.status !== 0) {
            throw new Error(`D1 query failed for ${environmentName}`);
        }
        try {
            return JSON.parse(result.stdout);
        } catch {
            throw new Error(`D1 query returned invalid JSON for ${environmentName}`);
        }
    }
    const response = await fetch(
        `https://api.cloudflare.com/client/v4/accounts/${accountId}/d1/database/${databaseId}/query`,
        {
            method: "POST",
            headers: {
                Authorization: `Bearer ${apiToken}`,
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ sql }),
        },
    );
    const body = await response.json();
    if (!response.ok || body.success !== true) {
        throw new Error(`D1 query failed for ${environmentName}`);
    }
    return body.result;
}

const migrationFiles = fs
    .readdirSync(migrationsPath)
    .filter((name) => /^\d+_[a-z0-9_]+\.sql$/.test(name))
    .sort();

function sleep(milliseconds) {
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, milliseconds);
}

const migrationTable = await query(
    "SELECT name FROM sqlite_schema WHERE type = 'table' AND name = 'd1_migrations'",
);
if (migrationTable[0]?.results?.length === 0) {
    await query(`CREATE TABLE d1_migrations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE,
        applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
    )`);
}

const appliedRows = await query("SELECT name FROM d1_migrations ORDER BY id");
const applied = new Set(appliedRows[0]?.results?.map(({ name }) => name) ?? []);
for (const name of applied) {
    if (!migrationFiles.includes(name)) {
        throw new Error(`${environmentName} contains unknown migration ${name}`);
    }
}

const pending = migrationFiles.filter((name) => !applied.has(name));
if (pending.length !== 0) {
    const migration = pending
        .map((name) => {
            const sql = fs.readFileSync(path.join(migrationsPath, name), "utf8").trimEnd();
            const escapedName = name.replaceAll("'", "''");
            return `${sql}\n\nINSERT INTO d1_migrations (name) VALUES ('${escapedName}');`;
        })
        .join("\n\n");
    const temporaryDirectory = fs.mkdtempSync(path.join(os.tmpdir(), "skydriver-d1-migration-"));
    const temporaryFile = path.join(temporaryDirectory, "pending.sql");
    try {
        fs.writeFileSync(temporaryFile, `${migration}\n`, { encoding: "utf8", mode: 0o600 });
        let imported = false;
        for (let attempt = 0; attempt < 5; attempt += 1) {
            const result = spawnSync(
                "pnpm",
                [
                    "exec",
                    "wrangler",
                    "d1",
                    "execute",
                    "SKYDRIVER_INDEX",
                    "--remote",
                    "--env",
                    environmentName,
                    "--yes",
                    "--file",
                    temporaryFile,
                    "--config",
                    configPath,
                ],
                { cwd: repositoryRoot, stdio: "inherit" },
            );
            if (result.status === 0) {
                imported = true;
                break;
            }
            try {
                const rows = await query("SELECT name FROM d1_migrations ORDER BY id");
                const received = new Set(rows[0]?.results?.map(({ name }) => name) ?? []);
                if (pending.every((name) => received.has(name))) {
                    imported = true;
                    break;
                }
            } catch {
                // The bounded retry below covers both an import and receipt-read outage.
            }
            if (attempt < 4) {
                sleep(2 ** attempt * 1_000);
            }
        }
        if (!imported) {
            throw new Error(`${environmentName} migration batch failed after retries`);
        }
    } finally {
        fs.rmSync(temporaryDirectory, { recursive: true, force: true });
    }
}

const receiptRows = await query("SELECT name FROM d1_migrations ORDER BY id");
const receipts = receiptRows[0]?.results?.map(({ name }) => name) ?? [];
if (
    receipts.length !== migrationFiles.length ||
    receipts.some((name, index) => name !== migrationFiles[index])
) {
    throw new Error(`${environmentName} migration receipts are incomplete or out of order`);
}
if (pending.length !== 0) {
    console.log(`${environmentName}: atomically applied ${pending.length} migrations`);
}
console.log(`${environmentName}: ${migrationFiles.length} migrations current`);
