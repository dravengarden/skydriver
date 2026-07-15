import * as v from "valibot";

const SessionSchema = v.object({
    authenticated: v.boolean(),
});

const ConfigurationSessionSchema = v.object({
    enabled: v.boolean(),
    expires_at: v.nullable(v.number()),
});

const HealthSchema = v.object({
    service: v.string(),
    environment: v.string(),
    operator_account: v.string(),
    transfer_mode: v.string(),
    mode: v.string(),
    incarnation: v.string(),
    revision: v.number(),
    external_maintenance: v.boolean(),
    mutations_allowed: v.boolean(),
});

const DriverViewSchema = v.object({
    id: v.string(),
    kind: v.string(),
    lifecycle_owner: v.string(),
    config: v.unknown(),
    enabled: v.boolean(),
    revision: v.number(),
    credential_present: v.boolean(),
    credential_rotated_at: v.nullable(v.number()),
    credential_expires_at: v.nullable(v.number()),
    credential_refresh_state: v.nullable(v.string()),
    credential_refresh_after: v.nullable(v.number()),
    credential_refresh_last_succeeded_at: v.nullable(v.number()),
    credential_refresh_last_error_code: v.nullable(v.string()),
    credential_refresh_token_expires_at: v.nullable(v.number()),
    placement_count: v.number(),
    location_count: v.number(),
    available_location_count: v.number(),
    encoded_bytes: v.number(),
    file_count: v.number(),
    quota_revision: v.number(),
    max_physical_bytes: v.nullable(v.number()),
    max_object_count: v.nullable(v.number()),
    reserved_physical_bytes: v.number(),
    reserved_object_count: v.number(),
    updated_at: v.number(),
});

const FilesystemViewSchema = v.object({
    id: v.string(),
    name: v.string(),
    state: v.string(),
    revision: v.number(),
    root_directory_id: v.string(),
    directory_count: v.number(),
    file_count: v.number(),
    logical_bytes: v.number(),
    available_location_count: v.number(),
    encoded_bytes: v.number(),
    updated_at: v.number(),
});

const TokenViewSchema = v.object({
    id: v.string(),
    label: v.string(),
    note: v.string(),
    metadata_revision: v.number(),
    principal_id: v.string(),
    principal_name: v.string(),
    root_directory_id: v.string(),
    root_directory_name: v.string(),
    parent_token_id: v.nullable(v.string()),
    snapshot_id: v.nullable(v.string()),
    actions: v.array(v.string()),
    driver_ids: v.array(v.string()),
    expires_at: v.number(),
    sealed_at: v.nullable(v.number()),
    revoked_at: v.nullable(v.number()),
    created_at: v.number(),
    last_used_at: v.nullable(v.number()),
});

const ManagementSnapshotSchema = v.object({
    schema: v.literal("carrack.management.snapshot.v2"),
    observed_at: v.number(),
    event_cursor: v.number(),
    drivers: v.array(DriverViewSchema),
    filesystems: v.array(FilesystemViewSchema),
    tokens: v.array(TokenViewSchema),
});

const ManagementEventCursorSchema = v.object({
    schema: v.literal("carrack.management.event-cursor.v1"),
    observed_at: v.number(),
    event_cursor: v.number(),
});

const ManagementActivityItemSchema = v.object({
    kind: v.string(),
    id: v.string(),
    subject_kind: v.string(),
    subject_id: v.string(),
    state: v.string(),
    driver_id: v.nullable(v.string()),
    created_at: v.number(),
    updated_at: v.number(),
    deadline_at: v.nullable(v.number()),
    attempt_count: v.number(),
    last_error_code: v.nullable(v.string()),
    attention_required: v.boolean(),
});

const ManagementActivityEventSchema = v.object({
    id: v.number(),
    filesystem_id: v.nullable(v.string()),
    principal_id: v.nullable(v.string()),
    token_id: v.nullable(v.string()),
    event_kind: v.string(),
    subject_kind: v.string(),
    subject_id: v.string(),
    details: v.unknown(),
    created_at: v.number(),
});

const ManagementActivitySchema = v.object({
    schema: v.literal("carrack.management.activity.v1"),
    observed_at: v.number(),
    event_cursor: v.number(),
    active_items: v.array(ManagementActivityItemSchema),
    events: v.array(ManagementActivityEventSchema),
});

const TransferMetricRowSchema = v.object({
    day: v.number(),
    scope_kind: v.picklist(["global", "driver", "token", "directory"]),
    scope_id: v.string(),
    direction: v.picklist(["upload", "download"]),
    weighted_transfers: v.number(),
    weighted_bytes: v.number(),
    weighted_provider_ms: v.number(),
    weighted_total_ms: v.number(),
    weighted_retries: v.number(),
    speed_b0: v.number(),
    speed_b1: v.number(),
    speed_b2: v.number(),
    speed_b3: v.number(),
    speed_b4: v.number(),
    speed_b5: v.number(),
    speed_b6: v.number(),
    speed_b7: v.number(),
    speed_b8: v.number(),
    speed_b9: v.number(),
    speed_b10: v.number(),
    speed_b11: v.number(),
    updated_at: v.number(),
});

const TransferMetricsSchema = v.object({
    schema: v.literal("carrack.management.transfer-metrics.v1"),
    observed_at: v.number(),
    scope_kind: v.picklist(["global", "driver", "token", "directory"]),
    scope_id: v.string(),
    retention_days: v.number(),
    window_days: v.number(),
    rows: v.array(TransferMetricRowSchema),
});

const ManagementDirectorySchema = v.object({
    schema: v.literal("carrack.management.directory.v1"),
    observed_at: v.number(),
    directory: v.object({
        id: v.string(),
        filesystem_id: v.string(),
        parent_id: v.nullable(v.string()),
        name: v.string(),
        data_root: v.string(),
        crypto_suite: v.string(),
        active_key_epoch: v.number(),
        acl_inherits: v.boolean(),
        revision: v.number(),
        acl_revision: v.number(),
        placement_revision: v.number(),
        child_directory_count: v.number(),
        recursive_directory_count: v.number(),
        recursive_file_count: v.number(),
        recursive_logical_bytes: v.number(),
        quota_revision: v.number(),
        max_file_bytes: v.nullable(v.number()),
        max_logical_bytes: v.nullable(v.number()),
        max_file_count: v.nullable(v.number()),
    }),
    breadcrumbs: v.array(v.object({ id: v.string(), name: v.string(), depth: v.number() })),
    placements: v.array(v.string()),
    entries: v.array(
        v.object({
            name: v.string(),
            kind: v.string(),
            file_id: v.nullable(v.string()),
            version_id: v.nullable(v.string()),
            child_directory_id: v.nullable(v.string()),
            size_bytes: v.number(),
            data_root: v.string(),
            metadata_root: v.nullable(v.string()),
            revision: v.number(),
            updated_at: v.number(),
            driver_ids: v.array(v.string()),
        }),
    ),
});

const TokenAnnotationValidationSchema = v.object({
    schema: v.literal("carrack.management.token-annotation-validation.v1"),
    token_id: v.string(),
    current_label: v.string(),
    current_note: v.string(),
    label: v.string(),
    note: v.string(),
    expected_revision: v.number(),
    validation_expires_at: v.number(),
    validation_digest: v.string(),
    warnings: v.array(v.string()),
});

const TokenAnnotationReceiptSchema = v.object({
    schema: v.literal("carrack.management.token-annotation-receipt.v1"),
    operation_id: v.string(),
    token_id: v.string(),
    label: v.string(),
    note: v.string(),
    final_revision: v.number(),
    committed_at: v.number(),
    state: v.literal("committed"),
});

const DriverStateValidationSchema = v.object({
    schema: v.literal("carrack.management.driver-state-validation.v1"),
    driver_id: v.string(),
    kind: v.string(),
    current_enabled: v.boolean(),
    enabled: v.boolean(),
    expected_revision: v.number(),
    placement_count: v.number(),
    available_location_count: v.number(),
    validation_expires_at: v.number(),
    validation_digest: v.string(),
    warnings: v.array(v.string()),
});

const DriverStateReceiptSchema = v.object({
    schema: v.literal("carrack.management.driver-state-receipt.v1"),
    operation_id: v.string(),
    driver_id: v.string(),
    enabled: v.boolean(),
    final_revision: v.number(),
    committed_at: v.number(),
    state: v.literal("committed"),
});

const DriverRegistrationValidationSchema = v.object({
    schema: v.literal("carrack.management.driver-registration-validation.v1"),
    driver_id: v.string(),
    kind: v.string(),
    config: v.unknown(),
    enabled: v.literal(false),
    expected_revision: v.literal(0),
    requires_credential: v.boolean(),
    validation_expires_at: v.number(),
    validation_digest: v.string(),
    warnings: v.array(v.string()),
});

const DriverRegistrationReceiptSchema = v.object({
    schema: v.literal("carrack.management.driver-registration-receipt.v1"),
    operation_id: v.string(),
    driver_id: v.string(),
    kind: v.string(),
    config: v.unknown(),
    enabled: v.literal(false),
    final_revision: v.literal(1),
    committed_at: v.number(),
    state: v.literal("committed"),
});

const DriverCredentialValidationSchema = v.object({
    schema: v.literal("carrack.management.driver-credential-validation.v1"),
    driver_id: v.string(),
    kind: v.string(),
    current_credential_present: v.boolean(),
    credential_revision: v.number(),
    refresh_token_expires_at: v.number(),
    expected_revision: v.number(),
    validation_expires_at: v.number(),
    validation_digest: v.string(),
    warnings: v.array(v.string()),
});

const DriverCredentialReceiptSchema = v.object({
    schema: v.literal("carrack.management.driver-credential-receipt.v1"),
    operation_id: v.string(),
    driver_id: v.string(),
    credential_id: v.string(),
    credential_revision: v.number(),
    credential_expires_at: v.number(),
    refresh_token_expires_at: v.number(),
    final_revision: v.number(),
    rotated_at: v.number(),
    state: v.literal("committed"),
});

const QuotaLimitsSchema = v.object({
    max_file_bytes: v.nullable(v.number()),
    max_logical_bytes: v.nullable(v.number()),
    max_file_count: v.nullable(v.number()),
    max_physical_bytes: v.nullable(v.number()),
    max_object_count: v.nullable(v.number()),
});

const QuotaValidationSchema = v.object({
    schema: v.literal("carrack.management.quota-validation.v1"),
    scope: v.picklist(["directory", "driver"]),
    resource_id: v.string(),
    current_limits: QuotaLimitsSchema,
    limits: QuotaLimitsSchema,
    expected_revision: v.number(),
    validation_expires_at: v.number(),
    validation_digest: v.string(),
    warnings: v.array(v.string()),
});

const QuotaReceiptSchema = v.object({
    schema: v.literal("carrack.management.quota-receipt.v1"),
    operation_id: v.string(),
    scope: v.picklist(["directory", "driver"]),
    resource_id: v.string(),
    ...QuotaLimitsSchema.entries,
    final_revision: v.number(),
    committed_at: v.number(),
    state: v.literal("committed"),
});

const AccessMutationDesiredSchema = v.object({
    operation: v.string(),
    resource_id: v.nullable(v.string()),
    filesystem_id: v.nullable(v.string()),
    principal_id: v.nullable(v.string()),
    group_id: v.nullable(v.string()),
    kind: v.nullable(v.string()),
    display_name: v.nullable(v.string()),
    state: v.nullable(v.string()),
    name: v.nullable(v.string()),
    expected_revision: v.number(),
});

const ManagementAccessSchema = v.object({
    schema: v.literal("carrack.management.access.v1"),
    observed_at: v.number(),
    principals: v.array(
        v.object({
            id: v.string(),
            kind: v.picklist(["human", "service"]),
            display_name: v.string(),
            state: v.picklist(["active", "disabled"]),
            revision: v.number(),
            created_at: v.number(),
            updated_at: v.number(),
        }),
    ),
    groups: v.array(
        v.object({
            id: v.string(),
            filesystem_id: v.string(),
            name: v.string(),
            revision: v.number(),
            created_at: v.number(),
            updated_at: v.number(),
        }),
    ),
    memberships: v.array(
        v.object({
            group_id: v.string(),
            principal_id: v.string(),
            created_at: v.number(),
        }),
    ),
});

const AccessMutationValidationSchema = v.object({
    schema: v.literal("carrack.management.access-validation.v1"),
    desired: AccessMutationDesiredSchema,
    validation_expires_at: v.number(),
    validation_digest: v.string(),
    warnings: v.array(v.string()),
});

const AccessMutationReceiptSchema = v.object({
    schema: v.literal("carrack.management.access-receipt.v1"),
    operation_id: v.string(),
    operation: v.string(),
    resource_id: v.string(),
    final_revision: v.number(),
    committed_at: v.number(),
    state: v.literal("committed"),
});

const ProviderInventorySchema = v.object({
    schema: v.literal("carrack.management.provider-inventory.v1"),
    observed_at: v.number(),
    drivers: v.array(
        v.object({
            driver_id: v.string(),
            driver_kind: v.string(),
            generation: v.number(),
            state: v.picklist(["idle", "scanning", "complete", "unsupported", "error"]),
            scanned_objects: v.number(),
            unknown_objects: v.number(),
            quarantined_objects: v.number(),
            quarantined_bytes: v.number(),
            oldest_quarantined_at: v.nullable(v.number()),
            last_started_at: v.nullable(v.number()),
            last_completed_at: v.nullable(v.number()),
            last_error_code: v.nullable(v.string()),
            updated_at: v.number(),
        }),
    ),
});

export type Session = v.InferOutput<typeof SessionSchema>;
export type ConfigurationSession = v.InferOutput<typeof ConfigurationSessionSchema>;
export type Health = v.InferOutput<typeof HealthSchema>;
export type DriverView = v.InferOutput<typeof DriverViewSchema>;
export type FilesystemView = v.InferOutput<typeof FilesystemViewSchema>;
export type TokenView = v.InferOutput<typeof TokenViewSchema>;
export type ManagementSnapshot = v.InferOutput<typeof ManagementSnapshotSchema>;
export type ManagementEventCursor = v.InferOutput<typeof ManagementEventCursorSchema>;
export type ManagementActivityItem = v.InferOutput<typeof ManagementActivityItemSchema>;
export type ManagementActivityEvent = v.InferOutput<typeof ManagementActivityEventSchema>;
export type ManagementActivity = v.InferOutput<typeof ManagementActivitySchema>;
export type TransferMetrics = v.InferOutput<typeof TransferMetricsSchema>;
export type TransferMetricScope = TransferMetrics["scope_kind"];
export type ManagementDirectory = v.InferOutput<typeof ManagementDirectorySchema>;
export type TokenAnnotationValidation = v.InferOutput<typeof TokenAnnotationValidationSchema>;
export type TokenAnnotationReceipt = v.InferOutput<typeof TokenAnnotationReceiptSchema>;
export type DriverStateValidation = v.InferOutput<typeof DriverStateValidationSchema>;
export type DriverStateReceipt = v.InferOutput<typeof DriverStateReceiptSchema>;
export type DriverRegistrationValidation = v.InferOutput<typeof DriverRegistrationValidationSchema>;
export type DriverRegistrationReceipt = v.InferOutput<typeof DriverRegistrationReceiptSchema>;
export type DriverCredentialValidation = v.InferOutput<typeof DriverCredentialValidationSchema>;
export type DriverCredentialReceipt = v.InferOutput<typeof DriverCredentialReceiptSchema>;
export type QuotaLimits = v.InferOutput<typeof QuotaLimitsSchema>;
export type QuotaValidation = v.InferOutput<typeof QuotaValidationSchema>;
export type QuotaReceipt = v.InferOutput<typeof QuotaReceiptSchema>;
export type ManagementAccess = v.InferOutput<typeof ManagementAccessSchema>;
export type AccessMutationDesired = v.InferOutput<typeof AccessMutationDesiredSchema>;
export type AccessMutationValidation = v.InferOutput<typeof AccessMutationValidationSchema>;
export type AccessMutationReceipt = v.InferOutput<typeof AccessMutationReceiptSchema>;
export type ProviderInventory = v.InferOutput<typeof ProviderInventorySchema>;

export function parseSession(input: unknown): Session {
    return v.parse(SessionSchema, input);
}

export function parseHealth(input: unknown): Health {
    return v.parse(HealthSchema, input);
}

export function parseManagementActivity(input: unknown): ManagementActivity {
    return v.parse(ManagementActivitySchema, input);
}

async function requestJson<TSchema extends v.BaseSchema<unknown, unknown, v.BaseIssue<unknown>>>(
    input: RequestInfo | URL,
    init: RequestInit | undefined,
    schema: TSchema,
): Promise<v.InferOutput<TSchema>> {
    const headers = new Headers(init?.headers);
    headers.set("Carrack-Protocol-Epoch", "2");
    headers.set("Carrack-SDK-Version", "0.3.6");
    const response = await fetch(input, { ...init, headers });
    if (!response.ok) {
        const detail = (await response.text())
            .slice(0, 512)
            .split("")
            .map((character) => {
                const code = character.charCodeAt(0);
                return code < 32 || code === 127 ? " " : character;
            })
            .join("")
            .trim();
        throw new Error(
            detail === ""
                ? `Carrack API returned ${String(response.status)}`
                : `Carrack API returned ${String(response.status)}: ${detail}`,
        );
    }

    const body: unknown = await response.json();
    return v.parse(schema, body);
}

export async function fetchSession(): Promise<Session> {
    const response = await fetch("/api/auth/session");
    if (response.status === 401) {
        return { authenticated: false };
    }
    if (!response.ok) {
        throw new Error(`Carrack API returned ${String(response.status)}`);
    }

    const body: unknown = await response.json();
    return v.parse(SessionSchema, body);
}

export function fetchHealth(): Promise<Health> {
    return requestJson("/api/health", undefined, HealthSchema);
}

export interface LoginInput {
    readonly account: string;
    readonly password: string;
}

export function login({ account, password }: LoginInput): Promise<Session> {
    return requestJson(
        "/api/auth/login",
        {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ account, password }),
        },
        SessionSchema,
    );
}

export function logout(): Promise<Session> {
    return requestJson("/api/auth/logout", { method: "POST" }, SessionSchema);
}

export function fetchConfigurationSession(): Promise<ConfigurationSession> {
    return requestJson("/api/auth/configuration", undefined, ConfigurationSessionSchema);
}

export function enableConfiguration(password: string): Promise<ConfigurationSession> {
    return requestJson(
        "/api/auth/configuration/enable",
        {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ password }),
        },
        ConfigurationSessionSchema,
    );
}

export function disableConfiguration(): Promise<ConfigurationSession> {
    return requestJson(
        "/api/auth/configuration/disable",
        { method: "POST" },
        ConfigurationSessionSchema,
    );
}

export function fetchManagementSnapshot(): Promise<ManagementSnapshot> {
    return requestJson("/api/admin/snapshot", undefined, ManagementSnapshotSchema);
}

export function fetchManagementAccess(): Promise<ManagementAccess> {
    return requestJson("/api/admin/access", undefined, ManagementAccessSchema);
}

export function fetchProviderInventory(): Promise<ProviderInventory> {
    return requestJson("/api/admin/provider-inventory", undefined, ProviderInventorySchema);
}

export function validateAccessMutation(
    desired: AccessMutationDesired,
): Promise<AccessMutationValidation> {
    return requestJson(
        "/api/admin/access/validate",
        {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(desired),
        },
        AccessMutationValidationSchema,
    );
}

export function applyAccessMutation(
    validation: AccessMutationValidation,
): Promise<AccessMutationReceipt> {
    return requestJson(
        "/api/admin/access/apply",
        {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                desired: validation.desired,
                validation_expires_at: validation.validation_expires_at,
                validation_digest: validation.validation_digest,
                idempotency_key: newIdempotencyKey(),
            }),
        },
        AccessMutationReceiptSchema,
    );
}

export function fetchManagementEventCursor(): Promise<ManagementEventCursor> {
    return requestJson("/api/admin/events/cursor", undefined, ManagementEventCursorSchema);
}

export function fetchTransferMetrics(
    scope: TransferMetricScope,
    scopeId: string,
): Promise<TransferMetrics> {
    return requestJson(
        `/api/admin/metrics/${scope}/${encodeURIComponent(scopeId)}?days=30`,
        undefined,
        TransferMetricsSchema,
    );
}

export function fetchManagementDirectory(directoryId: string): Promise<ManagementDirectory> {
    return requestJson(
        `/api/admin/directories/${encodeURIComponent(directoryId)}`,
        undefined,
        ManagementDirectorySchema,
    );
}

export function validateTokenAnnotation(
    tokenId: string,
    label: string,
    note: string,
    expectedRevision: number,
): Promise<TokenAnnotationValidation> {
    return requestJson(
        `/api/admin/tokens/${encodeURIComponent(tokenId)}/annotation/validate`,
        {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                label,
                note,
                expected_revision: expectedRevision,
            }),
        },
        TokenAnnotationValidationSchema,
    );
}

export function applyTokenAnnotation(
    validation: TokenAnnotationValidation,
): Promise<TokenAnnotationReceipt> {
    return requestJson(
        `/api/admin/tokens/${encodeURIComponent(validation.token_id)}/annotation/apply`,
        {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                label: validation.label,
                note: validation.note,
                expected_revision: validation.expected_revision,
                validation_expires_at: validation.validation_expires_at,
                validation_digest: validation.validation_digest,
                idempotency_key: newIdempotencyKey(),
            }),
        },
        TokenAnnotationReceiptSchema,
    );
}

export function validateDriverState(
    driverId: string,
    enabled: boolean,
    expectedRevision: number,
): Promise<DriverStateValidation> {
    return requestJson(
        `/api/admin/drivers/${encodeURIComponent(driverId)}/state/validate`,
        {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                enabled,
                expected_revision: expectedRevision,
            }),
        },
        DriverStateValidationSchema,
    );
}

export function applyDriverState(validation: DriverStateValidation): Promise<DriverStateReceipt> {
    return requestJson(
        `/api/admin/drivers/${encodeURIComponent(validation.driver_id)}/state/apply`,
        {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                enabled: validation.enabled,
                expected_revision: validation.expected_revision,
                validation_expires_at: validation.validation_expires_at,
                validation_digest: validation.validation_digest,
                idempotency_key: newIdempotencyKey(),
            }),
        },
        DriverStateReceiptSchema,
    );
}

export function validateDriverRegistration(
    driverId: string,
    kind: string,
    config: unknown,
): Promise<DriverRegistrationValidation> {
    return requestJson(
        "/api/admin/drivers/registration/validate",
        {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ driver_id: driverId, kind, config }),
        },
        DriverRegistrationValidationSchema,
    );
}

export function applyDriverRegistration(
    validation: DriverRegistrationValidation,
): Promise<DriverRegistrationReceipt> {
    return requestJson(
        "/api/admin/drivers/registration/apply",
        {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                driver_id: validation.driver_id,
                kind: validation.kind,
                config: validation.config,
                validation_expires_at: validation.validation_expires_at,
                validation_digest: validation.validation_digest,
                idempotency_key: newIdempotencyKey(),
            }),
        },
        DriverRegistrationReceiptSchema,
    );
}

export function validateDriverCredential(
    driverId: string,
    credential: unknown,
    expectedRevision: number,
): Promise<DriverCredentialValidation> {
    return requestJson(
        `/api/admin/drivers/${encodeURIComponent(driverId)}/credential/validate`,
        {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                credential,
                expected_revision: expectedRevision,
            }),
        },
        DriverCredentialValidationSchema,
    );
}

export function applyDriverCredential(
    validation: DriverCredentialValidation,
    credential: unknown,
): Promise<DriverCredentialReceipt> {
    return requestJson(
        `/api/admin/drivers/${encodeURIComponent(validation.driver_id)}/credential/apply`,
        {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                credential,
                expected_revision: validation.expected_revision,
                validation_expires_at: validation.validation_expires_at,
                validation_digest: validation.validation_digest,
                idempotency_key: newIdempotencyKey(),
            }),
        },
        DriverCredentialReceiptSchema,
    );
}

export function validateQuota(
    scope: "directory" | "driver",
    resourceId: string,
    limits: QuotaLimits,
    expectedRevision: number,
): Promise<QuotaValidation> {
    return requestJson(
        `/api/admin/quotas/${scope}/${encodeURIComponent(resourceId)}/validate`,
        {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                limits,
                expected_revision: expectedRevision,
            }),
        },
        QuotaValidationSchema,
    );
}

export function applyQuota(validation: QuotaValidation): Promise<QuotaReceipt> {
    return requestJson(
        `/api/admin/quotas/${validation.scope}/${encodeURIComponent(validation.resource_id)}/apply`,
        {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                limits: validation.limits,
                expected_revision: validation.expected_revision,
                validation_expires_at: validation.validation_expires_at,
                validation_digest: validation.validation_digest,
                idempotency_key: newIdempotencyKey(),
            }),
        },
        QuotaReceiptSchema,
    );
}

function newIdempotencyKey(): string {
    const entropy = new Uint8Array(16);
    crypto.getRandomValues(entropy);
    return `ui-${Array.from(entropy, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

export function fetchManagementActivity(): Promise<ManagementActivity> {
    return requestJson("/api/admin/activity", undefined, ManagementActivitySchema);
}
