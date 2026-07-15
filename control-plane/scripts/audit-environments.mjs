import fs from "node:fs";

const accountId = process.env.CLOUDFLARE_ACCOUNT_ID;
const apiToken = process.env.CLOUDFLARE_API_TOKEN;
if (accountId === undefined || apiToken === undefined) {
    throw new Error("CLOUDFLARE_ACCOUNT_ID and CLOUDFLARE_API_TOKEN are required");
}

const config = JSON.parse(fs.readFileSync("control-plane/wrangler.jsonc", "utf8"));
const requiredSecrets = ["CARRACK_ADMIN_TOKEN", "CARRACK_VFS_MASTER_KEY_V1"];
const forbiddenSecrets = ["CARRACK_ROOT_KEY_V1", "CARRACK_SESSION_KEY"];

async function api(path, init = {}) {
    const response = await fetch(`https://api.cloudflare.com/client/v4/accounts/${accountId}${path}`, {
        ...init,
        headers: {
            Authorization: `Bearer ${apiToken}`,
            ...(init.body === undefined ? {} : { "Content-Type": "application/json" }),
            ...init.headers,
        },
    });
    const body = await response.json();
    if (!response.ok || body.success !== true) {
        throw new Error(`Cloudflare API request failed for ${path}`);
    }
    return body.result;
}

async function queryD1(environment, sql) {
    const result = await api(`/d1/database/${environment.databaseId}/query`, {
        method: "POST",
        body: JSON.stringify({ sql }),
    });
    return result[0]?.results ?? [];
}

function singleBinding(environment, key, binding) {
    const values = environment[key]?.filter((value) => value.binding === binding);
    if (!Array.isArray(values) || values.length !== 1) {
        throw new Error(`${environment.name} has an invalid ${binding} binding`);
    }
    return values[0];
}

const expected = Object.fromEntries(
    ["dev", "prod"].map((name) => {
        const environment = config.env[name];
        const database = singleBinding(environment, "d1_databases", "CARRACK_INDEX");
        const bucket = singleBinding(environment, "r2_buckets", "CARRACK_MANIFESTS");
        const payload = singleBinding(environment, "r2_buckets", "CARRACK_PAYLOAD");
        return [
            name,
            {
                name,
                worker: environment.name,
                databaseId: database.database_id,
                databaseName: database.database_name,
                bucketName: bucket.bucket_name,
                payloadBucketName: payload.bucket_name,
                hostname: environment.routes?.[0]?.pattern,
            },
        ];
    }),
);

const [databases, r2, scripts, domains] = await Promise.all([
    api("/d1/database?per_page=100"),
    api("/r2/buckets"),
    api("/workers/scripts"),
    api("/workers/domains"),
]);

for (const environment of Object.values(expected)) {
    const database = databases.find(({ uuid }) => uuid === environment.databaseId);
    if (database?.name !== environment.databaseName) {
        throw new Error(`${environment.name} D1 does not match the committed identity`);
    }
    if (!r2.buckets.some(({ name }) => name === environment.bucketName)) {
        throw new Error(`${environment.name} R2 bucket is missing`);
    }
    if (!r2.buckets.some(({ name }) => name === environment.payloadBucketName)) {
        throw new Error(`${environment.name} payload R2 bucket is missing`);
    }
    if (!scripts.some(({ id }) => id === environment.worker)) {
        throw new Error(`${environment.name} Worker is missing`);
    }
    const workerDomains = domains.filter(({ service }) => service === environment.worker);
    if (
        workerDomains.length !== 1 ||
        workerDomains[0].hostname !== environment.hostname ||
        workerDomains[0].enabled !== true ||
        workerDomains[0].previews_enabled !== false ||
        typeof workerDomains[0].cert_id !== "string" ||
        workerDomains[0].cert_id.length === 0
    ) {
        throw new Error(`${environment.name} Worker custom domain does not match the committed identity`);
    }
}

for (const { id: script } of scripts) {
    const settings = await api(`/workers/scripts/${script}/settings`);
    for (const environment of Object.values(expected)) {
        const ownsDatabase = settings.bindings.some(
            ({ type, id }) => type === "d1" && id === environment.databaseId,
        );
        const ownsBucket = settings.bindings.some(
            ({ type, bucket_name: bucketName }) =>
                type === "r2_bucket" && bucketName === environment.bucketName,
        );
        const ownsPayloadBucket = settings.bindings.some(
            ({ type, bucket_name: bucketName }) =>
                type === "r2_bucket" && bucketName === environment.payloadBucketName,
        );
        if ((ownsDatabase || ownsBucket || ownsPayloadBucket) && script !== environment.worker) {
            throw new Error(`${script} overlaps ${environment.name} Carrack resources`);
        }
    }
}

for (const environment of Object.values(expected)) {
    const settings = await api(`/workers/scripts/${environment.worker}/settings`);
    const secretNames = new Set(
        settings.bindings
            .filter(({ type }) => type === "secret_text")
            .map(({ name }) => name),
    );
    for (const secret of requiredSecrets) {
        if (!secretNames.has(secret)) {
            throw new Error(`${environment.name} Worker is missing ${secret}`);
        }
    }
    for (const secret of forbiddenSecrets) {
        if (secretNames.has(secret)) {
            throw new Error(`${environment.name} Worker still exposes legacy ${secret}`);
        }
    }

    const marker = settings.bindings.find(
        ({ type, name }) => type === "plain_text" && name === "CARRACK_ENVIRONMENT",
    );
    if (marker?.text !== environment.name) {
        throw new Error(`${environment.name} Worker has the wrong environment marker`);
    }

    const subdomain = await api(`/workers/scripts/${environment.worker}/subdomain`);
    if (subdomain.enabled !== false || subdomain.previews_enabled !== false) {
        throw new Error(`${environment.name} Worker routing is not isolated as configured`);
    }

    const defaultR2 = await queryD1(
        environment,
        `SELECT kind, enabled, lifecycle_owner,
                retired_at IS NULL AS active,
                credential_ref IS NOT NULL AS credential_present,
                json_extract(config_json, '$.bucket') AS bucket,
                json_extract(config_json, '$.managed') AS managed,
                json_extract(config_json, '$.prefix') AS prefix,
                quota.max_physical_bytes
         FROM driver_instances AS driver
         LEFT JOIN driver_quota_policies AS quota ON quota.driver_id = driver.id
         WHERE driver.id = 'r2-default'`,
    );
    const [driver] = defaultR2;
    if (
        defaultR2.length !== 1 ||
        driver.kind !== "r2/v1" ||
        driver.enabled !== 1 ||
        driver.lifecycle_owner !== "environment" ||
        driver.active !== 1 ||
        driver.credential_present !== 1 ||
        driver.bucket !== environment.payloadBucketName ||
        driver.managed !== 1 ||
        driver.prefix !== "" ||
        !Number.isSafeInteger(driver.max_physical_bytes) ||
        driver.max_physical_bytes <= 0
    ) {
        throw new Error(
            `${environment.name} r2-default is not provisioned with an enabled environment profile and hard quota`,
        );
    }
}

for (const environment of Object.values(expected)) {
    console.log(
        `${environment.name}: ${environment.hostname}, ${environment.worker}, ${environment.databaseName}, ${environment.bucketName}`,
    );
}
