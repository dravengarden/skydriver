import { afterEach, describe, expect, it, vi } from "vitest";
import {
    fetchSession,
    login,
    parseHealth,
    parseManagementActivity,
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
        expect(parseSession({ authenticated: true })).toEqual({
            authenticated: true,
        });
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

        await expect(login("operator-secret")).resolves.toEqual({
            authenticated: true,
        });
        const call = fetchMock.mock.calls[0];
        expect(call?.[0]).toBe("/api/auth/login");
        expect(JSON.parse(String(call?.[1]?.body))).toEqual({
            password: "operator-secret",
        });
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
            refresh_token_expires_at: 2_000_000_000,
            expected_revision: 1,
            validation_expires_at: 2_000_000_000,
            validation_digest: "signed-secret-bound-digest",
            warnings: [],
        };
        const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(Response.json(validation));
        vi.stubGlobal("fetch", fetchMock);

        await expect(
            validateDriverCredential(
                "aliyun-main",
                {
                    refresh_token: "refresh-private",
                    refresh_issuer: "openlist-online/v1",
                },
                1,
            ),
        ).resolves.toEqual(validation);
        const body = JSON.parse(String(fetchMock.mock.calls[0]?.[1]?.body));
        expect(body.credential).toEqual({
            refresh_token: "refresh-private",
            refresh_issuer: "openlist-online/v1",
        });
        const headers = new Headers(fetchMock.mock.calls[0]?.[1]?.headers);
        expect(headers.get("Carrack-Protocol-Epoch")).toBe("2");
        expect(headers.get("Carrack-SDK-Version")).toBe("0.3.2");
        expect(JSON.stringify(validation)).not.toContain("refresh-private");
    });

    it("preserves a bounded server rejection reason for operator recovery", async () => {
        vi.stubGlobal(
            "fetch",
            vi
                .fn<typeof fetch>()
                .mockResolvedValue(
                    new Response("refresh token was rejected by the provider\n", { status: 400 }),
                ),
        );

        await expect(validateDriverCredential("aliyun-main", "refresh-private", 1)).rejects.toThrow(
            "Carrack API returned 400: refresh token was rejected by the provider",
        );
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

describe("parseManagementActivity", () => {
    it("accepts durable lifecycle work and audit events", () => {
        const parsed = parseManagementActivity({
            schema: "carrack.management.activity.v1",
            observed_at: 10,
            event_cursor: 7,
            active_items: [
                {
                    kind: "credential_refresh",
                    id: "credential-1",
                    subject_kind: "driver_credential",
                    subject_id: "aliyun-main",
                    state: "reauth_required",
                    driver_id: "aliyun-main",
                    created_at: 1,
                    updated_at: 9,
                    deadline_at: null,
                    attempt_count: 2,
                    last_error_code: "invalid_grant",
                    attention_required: true,
                },
            ],
            events: [
                {
                    id: 7,
                    filesystem_id: null,
                    principal_id: null,
                    token_id: null,
                    event_kind: "driver.credential.refreshed",
                    subject_kind: "driver",
                    subject_id: "aliyun-main",
                    details: { source: "control_plane" },
                    created_at: 8,
                },
            ],
        });

        expect(parsed.active_items[0]?.attention_required).toBe(true);
        expect(parsed.events[0]?.event_kind).toBe("driver.credential.refreshed");
    });

    it("rejects legacy archive activity payloads", () => {
        expect(() =>
            parseManagementActivity({
                observed_at: 10,
                components: [],
            }),
        ).toThrow();
    });
});
