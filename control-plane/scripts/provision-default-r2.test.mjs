import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

const repositoryRoot = path.resolve(import.meta.dirname, "../..");
const provisioner = path.join(import.meta.dirname, "provision-default-r2.mjs");

test("orchestrates validated enablement and empty-root placement without forwarding cloud secrets", () => {
    const stateDirectory = fs.mkdtempSync(path.join(os.tmpdir(), "carrack-r2-provision-test-"));
    fs.chmodSync(stateDirectory, 0o700);
    try {
        const config = JSON.parse(
            fs.readFileSync(path.join(repositoryRoot, "control-plane/wrangler.jsonc"), "utf8"),
        );
        const endpoint = config.env.dev.vars.CARRACK_R2_ENDPOINT;
        const accountId = new URL(endpoint).hostname.split(".")[0];
        const stateFile = path.join(stateDirectory, "state.json");
        const logFile = path.join(stateDirectory, "calls.jsonl");
        const fakeCarrackctl = path.join(stateDirectory, "carrackctl");
        fs.writeFileSync(
            stateFile,
            JSON.stringify({ enabled: false, revision: 1, placementRevision: 1, placements: [] }),
            { mode: 0o600 },
        );
        fs.writeFileSync(
            fakeCarrackctl,
            `#!/usr/bin/env node
import fs from "node:fs";
const stateFile = process.env.FAKE_CARRACK_STATE;
const logFile = process.env.FAKE_CARRACK_LOG;
const args = process.argv.slice(2);
const state = JSON.parse(fs.readFileSync(stateFile, "utf8"));
fs.appendFileSync(logFile, JSON.stringify({
  command: args.slice(0, 4),
  factory: Boolean(process.env.CLOUDFLARE_TOKEN_FACTORY_API_TOKEN),
  deploy: Boolean(process.env.CLOUDFLARE_API_TOKEN),
  operator: Boolean(process.env.CARRACK_OPERATOR_CREDENTIAL),
  vfs: Boolean(process.env.CARRACK_VFS_TOKEN),
}) + "\\n");
const value = (name) => args[args.indexOf(name) + 1];
if (args[0] === "compatibility") {
  console.log(JSON.stringify({ protocol_epoch: 2, enforcement: "required" }));
} else if (args[0] === "snapshot") {
  console.log(JSON.stringify({ filesystems: [{ id: "vfs" }], drivers: [{
    id: "r2-default",
    kind: "r2/v1",
    lifecycle_owner: "environment",
    config: {
      endpoint: process.env.FAKE_R2_ENDPOINT,
      bucket: "carrack-payload-dev",
      prefix: "",
      managed: true,
    },
    credential_present: true,
    enabled: state.enabled,
    revision: state.revision,
  }] }));
} else if (args[0] === "driver" && args[1] === "enable") {
  const expectedRevision = Number(value("--expected-revision"));
  if (args.includes("--check")) {
    console.log(JSON.stringify({
      driver_id: "r2-default",
      expected_revision: expectedRevision,
      enabled: true,
    }));
  } else {
    state.enabled = true;
    state.revision += 1;
    fs.writeFileSync(stateFile, JSON.stringify(state), { mode: 0o600 });
    console.log(JSON.stringify({ driver_id: "r2-default", final_revision: state.revision }));
  }
} else if (args[0] === "vfs" && args[1] === "placement" && args[2] === "show") {
  console.log(JSON.stringify({
    placement_revision: state.placementRevision,
    placements: state.placements.map(({ driverId, priority }) => ({
      driver_id: driverId,
      driver_kind: "r2/v1",
      driver_revision: state.revision,
      write_priority: priority,
      state: "active",
    })),
  }));
} else if (args[0] === "vfs" && args[1] === "placement" && args[2] === "replace") {
  state.placements = value("--placement").split(",").map((encoded) => {
    const [driverId, priority] = encoded.split(":");
    return { driverId, priority: Number(priority) };
  });
  state.placementRevision += 1;
  fs.writeFileSync(stateFile, JSON.stringify(state), { mode: 0o600 });
  console.log(JSON.stringify({ final_revision: state.placementRevision }));
} else {
  console.error("unexpected fake carrackctl command", args);
  process.exit(2);
}
`,
            { mode: 0o700 },
        );

        const result = spawnSync(process.execPath, [provisioner, "dev"], {
            cwd: repositoryRoot,
            encoding: "utf8",
            env: {
                ...process.env,
                CARRACKCTL_BIN: fakeCarrackctl,
                CARRACK_PROVISION_R2: "1",
                CLOUDFLARE_ACCOUNT_ID: accountId,
                CLOUDFLARE_API_TOKEN: "routine-deploy-token",
                CLOUDFLARE_TOKEN_FACTORY_API_TOKEN: "token-factory",
                CARRACK_OPERATOR_CREDENTIAL: "operator",
                CARRACK_VFS_TOKEN: "vfs",
                FAKE_CARRACK_STATE: stateFile,
                FAKE_CARRACK_LOG: logFile,
                FAKE_R2_ENDPOINT: endpoint,
            },
        });
        assert.equal(result.status, 0, result.stderr);
        assert.match(result.stdout, /carrack\.environment-r2-provision-receipt\.v1/);
        const finalState = JSON.parse(fs.readFileSync(stateFile, "utf8"));
        assert.deepEqual(finalState, {
            enabled: true,
            revision: 2,
            placementRevision: 2,
            placements: [{ driverId: "r2-default", priority: 0 }],
        });
        const calls = fs
            .readFileSync(logFile, "utf8")
            .trim()
            .split("\n")
            .map((line) => JSON.parse(line));
        assert.ok(calls.every(({ factory, deploy }) => !factory && !deploy));
        assert.ok(
            calls
                .filter(({ command }) => command[0] === "snapshot")
                .every(({ operator, vfs }) => operator && !vfs),
        );
        assert.ok(
            calls
                .filter(({ command }) => command[0] === "vfs")
                .every(({ operator, vfs }) => !operator && vfs),
        );
        assert.ok(
            calls
                .filter(({ command }) => command[0] === "compatibility")
                .every(({ operator, vfs }) => !operator && !vfs),
        );
    } finally {
        fs.rmSync(stateDirectory, { recursive: true, force: true });
    }
});
