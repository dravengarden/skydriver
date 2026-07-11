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

export type Session = v.InferOutput<typeof SessionSchema>;
export type Summary = v.InferOutput<typeof SummarySchema>;
export type LiveComponent = v.InferOutput<typeof LiveComponentSchema>;
export type LiveComponents = v.InferOutput<typeof LiveComponentsSchema>;

export function parseSession(input: unknown): Session {
    return v.parse(SessionSchema, input);
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
