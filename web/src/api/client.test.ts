import { afterEach, describe, expect, it, vi } from "vitest";
import {
    fetchSession,
    fetchManagementDirectoryEntries,
    fetchTransferAnalytics,
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

describe("management directory entry pages", () => {
    it("serializes a revision-pinned keyset cursor and validates the page", async () => {
        const response = {
            schema: "skydriver.management.directory-entry-page.v1",
            observed_at: 2_000_000_000,
            directory_id: "0123456789abcdef0123456789abcdef",
            directory_revision: 7,
            prefix: "archive-",
            after_kind: "directory",
            after_name: "archive-a",
            next_after_kind: "file",
            next_after_name: "archive-b.parquet",
            limit: 25,
            has_more: false,
            entries: [
                {
                    name: "archive-b.parquet",
                    kind: "file",
                    file_id: "1123456789abcdef0123456789abcdef",
                    version_id: "2123456789abcdef0123456789abcdef",
                    child_directory_id: null,
                    size_bytes: 4096,
                    data_root: "sha256:plain",
                    metadata_root: "sha256:metadata",
                    revision: 4,
                    updated_at: 2_000_000_000,
                    driver_ids: ["r2-default"],
                },
            ],
        };
        const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(Response.json(response));
        vi.stubGlobal("fetch", fetchMock);

        await expect(
            fetchManagementDirectoryEntries(
                response.directory_id,
                7,
                "archive-",
                "directory",
                "archive-a",
                25,
            ),
        ).resolves.toEqual(response);
        expect(fetchMock).toHaveBeenCalledWith(
            `/api/admin/directories/${response.directory_id}/entries?revision=7&prefix=archive-&after_kind=directory&after_name=archive-a&limit=25`,
            expect.any(Object),
        );
    });
});

describe("transfer analytics", () => {
    it("serializes intersecting filters and validates the sampled response", async () => {
        const response = {
            schema: "skydriver.management.transfer-analytics.v2",
            observed_at: 2_000_000_000,
            from: 1_999_900_000,
            to: 2_000_000_000,
            interval: "hour",
            group_by: "driver",
            driver_id: "driver-a",
            token_id: "token-a",
            directory_id: "0123456789abcdef0123456789abcdef",
            include_descendants: true,
            direction: "download",
            approximate: true,
            small_transfer_sample_modulus: 10,
            large_transfer_bytes: 67_108_864,
            rows: [
                {
                    bucket: 1_999_900_800,
                    group_id: "driver-a",
                    direction: "download",
                    weighted_transfers: 10,
                    weighted_bytes: 10_485_760,
                    weighted_provider_ms: 10_000,
                    weighted_total_ms: 20_000,
                    weighted_retries: 0,
                    weighted_phase_transfers: 10,
                    weighted_plan_ms: 2_000,
                    weighted_queue_ms: 3_000,
                    weighted_phase_provider_ms: 10_000,
                    weighted_post_provider_ms: 4_000,
                    speed_b0: 0,
                    speed_b1: 10,
                    speed_b2: 0,
                    speed_b3: 0,
                    speed_b4: 0,
                    speed_b5: 0,
                    speed_b6: 0,
                    speed_b7: 0,
                    speed_b8: 0,
                    speed_b9: 0,
                    speed_b10: 0,
                    speed_b11: 0,
                },
            ],
        };
        const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(Response.json(response));
        vi.stubGlobal("fetch", fetchMock);

        await expect(
            fetchTransferAnalytics({
                from: response.from,
                to: response.to,
                interval: "auto",
                groupBy: "driver",
                driverId: "driver-a",
                tokenId: "token-a",
                directoryId: response.directory_id,
                includeDescendants: true,
                direction: "download",
            }),
        ).resolves.toEqual(response);
        const requested = new URL(String(fetchMock.mock.calls[0]?.[0]), "https://skydriver.test");
        expect(requested.pathname).toBe("/api/admin/analytics/transfers");
        expect(Object.fromEntries(requested.searchParams)).toMatchObject({
            interval: "auto",
            group_by: "driver",
            driver: "driver-a",
            token: "token-a",
            directory: response.directory_id,
            include_descendants: "true",
            direction: "download",
        });
    });
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

    it("sends the operator account and credential during login", async () => {
        const fetchMock = vi
            .fn<typeof fetch>()
            .mockResolvedValue(Response.json({ authenticated: true }, { status: 200 }));
        vi.stubGlobal("fetch", fetchMock);

        await expect(
            login({ account: "draven@skydriver-dev", password: "operator-secret" }),
        ).resolves.toEqual({
            authenticated: true,
        });
        const call = fetchMock.mock.calls[0];
        expect(call?.[0]).toBe("/api/auth/login");
        expect(JSON.parse(String(call?.[1]?.body))).toEqual({
            account: "draven@skydriver-dev",
            password: "operator-secret",
        });
    });
});

describe("driver configuration", () => {
    it("pins validation to the exact desired state and revision", async () => {
        const validation = {
            schema: "skydriver.management.driver-state-validation.v1",
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
            schema: "skydriver.management.driver-registration-validation.v1",
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
            schema: "skydriver.management.driver-credential-validation.v1",
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
        expect(headers.get("Skydriver-Protocol-Epoch")).toBe("2");
        expect(headers.get("Skydriver-SDK-Version")).toBe("0.3.6");
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
            "Skydriver API returned 400: refresh token was rejected by the provider",
        );
    });
});

describe("parseHealth", () => {
    it("requires an explicit deployment environment", () => {
        expect(
            parseHealth({
                service: "skydriver-control-plane",
                environment: "dev",
                operator_account: "draven",
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
                service: "skydriver-control-plane",
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
    it("accepts a bounded durable lifecycle work page", () => {
        const parsed = parseManagementActivity({
            schema: "skydriver.management.activity.v2",
            observed_at: 10,
            offset: 0,
            limit: 25,
            has_more: false,
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
        });

        expect(parsed.active_items[0]?.attention_required).toBe(true);
        expect(parsed.has_more).toBe(false);
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
