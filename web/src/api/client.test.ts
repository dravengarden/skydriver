import { afterEach, describe, expect, it, vi } from "vitest";
import {
    fetchSession,
    login,
    parseHealth,
    parseIntegrityFindings,
    parseSession,
    validateDriverCredential,
    validateDriverRegistration,
    validateDriverState,
} from "./client";

afterEach(() => {
    vi.unstubAllGlobals();
});

describe("parseSession", () => {
    it("accepts a valid authenticated session", () => {
        expect(parseSession({ authenticated: true })).toEqual({ authenticated: true });
    });

    it("rejects malformed API data", () => {
        expect(() => parseSession({ authenticated: "yes" })).toThrow();
    });
});

describe("operator session", () => {
    it("maps an unauthorized status to a logged-out session", async () => {
        vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(null, { status: 401 })));

        await expect(fetchSession()).resolves.toEqual({ authenticated: false });
    });

    it("sends only the operator credential during login", async () => {
        const fetchMock = vi
            .fn<typeof fetch>()
            .mockResolvedValue(Response.json({ authenticated: true }, { status: 200 }));
        vi.stubGlobal("fetch", fetchMock);

        await expect(login("operator-secret")).resolves.toEqual({ authenticated: true });
        const call = fetchMock.mock.calls[0];
        expect(call?.[0]).toBe("/api/auth/login");
        expect(JSON.parse(String(call?.[1]?.body))).toEqual({ password: "operator-secret" });
    });
});

describe("driver configuration", () => {
    it("pins validation to the exact desired state and revision", async () => {
        const validation = {
            schema: "carrack.management.driver-state-validation.v1",
            driver_id: "local-main",
            kind: "local-filesystem/v2",
            current_enabled: true,
            enabled: false,
            expected_revision: 7,
            placement_count: 2,
            available_location_count: 4,
            validation_expires_at: 2_000_000_000,
            validation_digest: "signed-digest",
            warnings: ["Disabling affects active placements."],
        };
        const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(Response.json(validation));
        vi.stubGlobal("fetch", fetchMock);

        await expect(validateDriverState("local-main", false, 7)).resolves.toEqual(validation);
        const call = fetchMock.mock.calls[0];
        expect(call?.[0]).toBe("/api/admin/drivers/local-main/state/validate");
        expect(JSON.parse(String(call?.[1]?.body))).toEqual({
            enabled: false,
            expected_revision: 7,
        });
    });

    it("normalizes typed registration without embedding a credential", async () => {
        const validation = {
            schema: "carrack.management.driver-registration-validation.v1",
            driver_id: "aliyun-main",
            kind: "aliyundrive-open/v2",
            config: { root_folder_id: "root" },
            enabled: false,
            expected_revision: 0,
            requires_credential: true,
            validation_expires_at: 2_000_000_000,
            validation_digest: "signed-digest",
            warnings: [],
        };
        const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(Response.json(validation));
        vi.stubGlobal("fetch", fetchMock);

        await expect(
            validateDriverRegistration("aliyun-main", "aliyundrive-open/v2", {
                root_folder_id: "root",
            }),
        ).resolves.toEqual(validation);
        const body = JSON.parse(String(fetchMock.mock.calls[0]?.[1]?.body));
        expect(body).toEqual({
            driver_id: "aliyun-main",
            kind: "aliyundrive-open/v2",
            config: { root_folder_id: "root" },
        });
        expect(JSON.stringify(body)).not.toContain("access_token");
    });

    it("keeps the write-only credential out of the validation response", async () => {
        const validation = {
            schema: "carrack.management.driver-credential-validation.v1",
            driver_id: "aliyun-main",
            kind: "aliyundrive-open/v2",
            current_credential_present: false,
            credential_revision: 1,
            expected_revision: 1,
            validation_expires_at: 2_000_000_000,
            validation_digest: "signed-secret-bound-digest",
            warnings: [],
        };
        const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(Response.json(validation));
        vi.stubGlobal("fetch", fetchMock);

        await expect(validateDriverCredential("aliyun-main", "private-token", 1)).resolves.toEqual(
            validation,
        );
        const body = JSON.parse(String(fetchMock.mock.calls[0]?.[1]?.body));
        expect(body.credential).toEqual({ access_token: "private-token" });
        expect(JSON.stringify(validation)).not.toContain("private-token");
    });
});

describe("parseHealth", () => {
    it("requires an explicit deployment environment", () => {
        expect(
            parseHealth({
                service: "carrack-control-plane",
                environment: "dev",
                transfer_mode: "direct",
                mode: "active",
                incarnation: "0123456789abcdef0123456789abcdef",
                revision: 1,
                external_maintenance: false,
                mutations_allowed: true,
            }),
        ).toMatchObject({ environment: "dev", mutations_allowed: true });
    });

    it("rejects health without an environment", () => {
        expect(() =>
            parseHealth({
                service: "carrack-control-plane",
                transfer_mode: "direct",
                mode: "active",
                incarnation: "0123456789abcdef0123456789abcdef",
                revision: 1,
                external_maintenance: false,
                mutations_allowed: true,
            }),
        ).toThrow();
    });
});

describe("parseIntegrityFindings", () => {
    it("accepts a server-classified repairable finding", () => {
        const parsed = parseIntegrityFindings({
            observed_at: 10,
            next_cursor: "cursor",
            findings: [
                {
                    id: "finding-1",
                    namespace_id: "namespace-1",
                    namespace_name: "archive",
                    subject_kind: "location",
                    subject_id: "location-1",
                    condition: "missing",
                    state: "open",
                    evidence: { condition: "missing" },
                    first_observed_at: 1,
                    last_observed_at: 9,
                    resolved_at: null,
                    revision: 1,
                    manifest_sha256: "a".repeat(64),
                    root_version: 1,
                    extent_sha256: "b".repeat(64),
                    driver_id: "mirror",
                    storage_key: "objects/one",
                    location_state: "missing",
                    last_verified_at: 2,
                    quarantine_revision: null,
                    quarantine_until: null,
                    acknowledgement_reason: null,
                    acknowledged_at: null,
                    tombstone_reason: null,
                    tombstoned_at: null,
                    delete_after: null,
                    available_repair_sources: 1,
                    repairable: true,
                    required_action: "Repair from a separately verified replica.",
                },
            ],
        });

        expect(parsed.findings[0]?.repairable).toBe(true);
        expect(parsed.next_cursor).toBe("cursor");
    });

    it("rejects an unclassified finding payload", () => {
        expect(() =>
            parseIntegrityFindings({ observed_at: 10, next_cursor: null, findings: [{}] }),
        ).toThrow();
    });
});
