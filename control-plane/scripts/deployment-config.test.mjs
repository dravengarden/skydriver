import assert from "node:assert/strict";
import test from "node:test";

import { durableObjectMigrationConfig } from "./deployment-config.mjs";

test("preserves Worker state while excluding independently managed routes and schedules", () => {
    const config = {
        main: "build/worker/shim.mjs",
        routes: [{ pattern: "inherited.example", custom_domain: true }],
        triggers: { crons: ["0 0 * * *"] },
        migrations: [{ tag: "v1", new_sqlite_classes: ["WatchHub"] }],
        env: {
            dev: {
                name: "skydriver-dev",
                routes: [{ pattern: "dev.example", custom_domain: true }],
                triggers: { crons: ["*/15 * * * *"] },
                durable_objects: {
                    bindings: [{ name: "WATCH", class_name: "WatchHub" }],
                },
            },
        },
    };

    const deployment = durableObjectMigrationConfig(config, "dev");
    assert.equal(deployment.routes, undefined);
    assert.equal(deployment.triggers, undefined);
    assert.equal(deployment.env.dev.routes, undefined);
    assert.equal(deployment.env.dev.triggers, undefined);
    assert.deepEqual(deployment.migrations, config.migrations);
    assert.deepEqual(deployment.env.dev.durable_objects, config.env.dev.durable_objects);
    assert.ok(config.env.dev.routes, "the audited source configuration must remain unchanged");
});

test("rejects an unknown or absent environment", () => {
    assert.throws(() => durableObjectMigrationConfig({ env: {} }, "dev"), /is missing/);
    assert.throws(() => durableObjectMigrationConfig({ env: {} }, "staging"), /must be dev or prod/);
});
