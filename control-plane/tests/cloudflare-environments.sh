#!/usr/bin/env bash
set -euo pipefail

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
config="$repository_root/control-plane/wrangler.jsonc"

node - "$config" <<'NODE'
const fs = require("node:fs");

const configPath = process.argv[2];
const config = JSON.parse(fs.readFileSync(configPath, "utf8"));

function fail(message) {
    throw new Error(`invalid Cloudflare environment configuration: ${message}`);
}

function requireSingleBinding(environment, key, binding) {
    const values = environment[key];
    if (!Array.isArray(values) || values.length !== 1 || values[0].binding !== binding) {
        fail(`${environment.name} must define exactly one ${binding} binding`);
    }
    return values[0];
}

if (config.name !== "carrack-control-plane-local") {
    fail("the default Worker must remain local-only");
}
if (config.workers_dev !== false || config.preview_urls !== false) {
    fail("the default Worker must not expose public URLs");
}

const localDatabase = requireSingleBinding(config, "d1_databases", "CARRACK_INDEX");
if (localDatabase.database_id !== "00000000-0000-0000-0000-000000000000") {
    fail("the default Worker must use the non-routable local D1 sentinel");
}
requireSingleBinding(config, "r2_buckets", "CARRACK_MANIFESTS");

const expected = {
    dev: {
        worker: "carrack-control-plane-dev",
        database: "carrack-index-dev",
        bucket: "carrack-manifests-dev",
        hostname: "dev.carrack.stormbird.xyz",
    },
    prod: {
        worker: "carrack-control-plane-prod",
        database: "carrack-index-prod",
        bucket: "carrack-manifests-prod",
        hostname: "carrack.stormbird.xyz",
    },
};

const identities = [];
for (const [name, wanted] of Object.entries(expected)) {
    const environment = config.env?.[name];
    if (environment === undefined) {
        fail(`missing ${name} environment`);
    }
    if (environment.name !== wanted.worker) {
        fail(`${name} Worker must be named ${wanted.worker}`);
    }
    if (environment.workers_dev !== false || environment.preview_urls !== false) {
        fail(`${name} must disable workers.dev and preview URLs`);
    }
    if (
        !Array.isArray(environment.routes) ||
        environment.routes.length !== 1 ||
        environment.routes[0].pattern !== wanted.hostname ||
        environment.routes[0].custom_domain !== true
    ) {
        fail(`${name} must expose exactly the ${wanted.hostname} custom domain`);
    }
    if (environment.vars?.CARRACK_ENVIRONMENT !== name) {
        fail(`${name} must identify itself through CARRACK_ENVIRONMENT`);
    }

    const database = requireSingleBinding(environment, "d1_databases", "CARRACK_INDEX");
    const bucket = requireSingleBinding(environment, "r2_buckets", "CARRACK_MANIFESTS");
    if (database.database_name !== wanted.database) {
        fail(`${name} D1 must be named ${wanted.database}`);
    }
    if (!/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(database.database_id)) {
        fail(`${name} D1 must have a concrete UUID`);
    }
    if (bucket.bucket_name !== wanted.bucket) {
        fail(`${name} R2 bucket must be named ${wanted.bucket}`);
    }
    if ("preview_bucket_name" in bucket) {
        fail(`${name} must not overload preview_bucket_name as an environment`);
    }
    identities.push(environment.name, database.database_id, bucket.bucket_name, wanted.hostname);
}

if (new Set(identities).size !== identities.length) {
    fail("dev and prod resource identities must never overlap");
}
NODE
