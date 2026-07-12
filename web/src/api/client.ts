import * as v from "valibot";

const SessionSchema = v.object({
    authenticated: v.boolean(),
    username: v.nullable(v.string()),
});

const SummarySchema = v.object({
    operations: v.number(),
    objects: v.number(),
    packs: v.number(),
    verified_locations: v.number(),
});

const LiveComponentSchema = v.object({
    component_id: v.string(),
    operation_id: v.string(),
    operation_kind: v.string(),
    operation_phase: v.string(),
    component_kind: v.string(),
    component_state: v.string(),
    client_name: v.nullable(v.string()),
    useful_bytes_total: v.nullable(v.number()),
    useful_bytes_verified: v.number(),
    wire_bytes_read: v.number(),
    wire_bytes_written: v.number(),
    retry_count: v.number(),
    throttle_count: v.number(),
    last_sample_at: v.nullable(v.number()),
    rate_1m_bps: v.number(),
    rate_5m_bps: v.number(),
    rate_15m_bps: v.number(),
    lifetime_active_bps: v.number(),
});

const LiveComponentsSchema = v.object({
    observed_at: v.number(),
    components: v.array(LiveComponentSchema),
});

const IntegrityFindingSchema = v.object({
    id: v.string(),
    namespace_id: v.nullable(v.string()),
    namespace_name: v.nullable(v.string()),
    subject_kind: v.string(),
    subject_id: v.string(),
    condition: v.string(),
    state: v.string(),
    evidence: v.unknown(),
    first_observed_at: v.number(),
    last_observed_at: v.number(),
    resolved_at: v.nullable(v.number()),
    revision: v.number(),
    manifest_sha256: v.nullable(v.string()),
    root_version: v.nullable(v.number()),
    extent_sha256: v.nullable(v.string()),
    driver_id: v.nullable(v.string()),
    storage_key: v.nullable(v.string()),
    location_state: v.nullable(v.string()),
    last_verified_at: v.nullable(v.number()),
    quarantine_revision: v.nullable(v.number()),
    quarantine_until: v.nullable(v.number()),
    acknowledgement_reason: v.nullable(v.string()),
    acknowledged_at: v.nullable(v.number()),
    tombstone_reason: v.nullable(v.string()),
    tombstoned_at: v.nullable(v.number()),
    delete_after: v.nullable(v.number()),
    available_repair_sources: v.number(),
    repairable: v.boolean(),
    required_action: v.string(),
});

const IntegrityFindingsSchema = v.object({
    observed_at: v.number(),
    next_cursor: v.nullable(v.string()),
    findings: v.array(IntegrityFindingSchema),
});

export type Session = v.InferOutput<typeof SessionSchema>;
export type Summary = v.InferOutput<typeof SummarySchema>;
export type LiveComponent = v.InferOutput<typeof LiveComponentSchema>;
export type LiveComponents = v.InferOutput<typeof LiveComponentsSchema>;
export type IntegrityFinding = v.InferOutput<typeof IntegrityFindingSchema>;
export type IntegrityFindings = v.InferOutput<typeof IntegrityFindingsSchema>;

export function parseSession(input: unknown): Session {
    return v.parse(SessionSchema, input);
}

export function parseIntegrityFindings(input: unknown): IntegrityFindings {
    return v.parse(IntegrityFindingsSchema, input);
}

async function requestJson<TSchema extends v.BaseSchema<unknown, unknown, v.BaseIssue<unknown>>>(
    input: RequestInfo | URL,
    init: RequestInit | undefined,
    schema: TSchema,
): Promise<v.InferOutput<TSchema>> {
    const response = await fetch(input, init);
    if (!response.ok) {
        throw new Error(`Carrack API returned ${response.status}`);
    }

    const body: unknown = await response.json();
    return v.parse(schema, body);
}

export function fetchSession(): Promise<Session> {
    return requestJson("/api/auth/session", undefined, SessionSchema);
}

export function login(username: string, password: string): Promise<Session> {
    return requestJson(
        "/api/auth/login",
        {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, password }),
        },
        SessionSchema,
    );
}

export function logout(): Promise<Session> {
    return requestJson("/api/auth/logout", { method: "POST" }, SessionSchema);
}

export function fetchSummary(): Promise<Summary> {
    return requestJson("/api/summary", undefined, SummarySchema);
}

export function fetchLiveComponents(): Promise<LiveComponents> {
    return requestJson("/api/components/live", undefined, LiveComponentsSchema);
}

export function fetchIntegrityFindings(cursor: string | null): Promise<IntegrityFindings> {
    const parameters = new URLSearchParams({ state: "open", limit: "50" });
    if (cursor !== null) {
        parameters.set("cursor", cursor);
    }

    return requestJson(
        `/api/integrity/findings?${parameters.toString()}`,
        undefined,
        IntegrityFindingsSchema,
    );
}
