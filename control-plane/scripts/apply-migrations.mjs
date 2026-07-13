import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const environmentName = process.argv[2];
if (environmentName !== "dev" && environmentName !== "prod") {
    throw new Error("usage: apply-migrations.mjs <dev|prod>");
}
if (environmentName === "prod" && process.env.CARRACK_MIGRATE_PROD !== "1") {
    throw new Error("set CARRACK_MIGRATE_PROD=1 to migrate production");
}

const accountId = process.env.CLOUDFLARE_ACCOUNT_ID;
const apiToken = process.env.CLOUDFLARE_API_TOKEN;
if (accountId === undefined || apiToken === undefined) {
    throw new Error("CLOUDFLARE_ACCOUNT_ID and CLOUDFLARE_API_TOKEN are required");
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

for (const name of migrationFiles) {
    if (applied.has(name)) {
        continue;
    }

    const sql = fs.readFileSync(path.join(migrationsPath, name), "utf8").trimEnd();
    const escapedName = name.replaceAll("'", "''");
    const migration = `${sql}\n\nINSERT INTO d1_migrations (name) VALUES ('${escapedName}');\n`;
    const temporaryDirectory = fs.mkdtempSync(path.join(os.tmpdir(), "carrack-d1-migration-"));
    const temporaryFile = path.join(temporaryDirectory, name);
    try {
        fs.writeFileSync(temporaryFile, migration, { encoding: "utf8", mode: 0o600 });
        const result = spawnSync(
            "pnpm",
            [
                "exec",
                "wrangler",
                "d1",
                "execute",
                "CARRACK_INDEX",
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
        if (result.status !== 0) {
            throw new Error(`${environmentName} migration ${name} failed`);
        }
    } finally {
        fs.rmSync(temporaryDirectory, { recursive: true, force: true });
    }

    const receipt = await query(
        `SELECT name FROM d1_migrations WHERE name = '${escapedName}'`,
    );
    if (receipt[0]?.results?.[0]?.name !== name) {
        throw new Error(`${environmentName} migration ${name} has no durable receipt`);
    }
    console.log(`${environmentName}: applied ${name}`);
}

console.log(`${environmentName}: ${migrationFiles.length} migrations current`);
