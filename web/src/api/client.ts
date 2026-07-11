import * as v from "valibot";

const SessionSchema = v.object({
    authenticated: v.boolean(),
    username: v.nullable(v.string()),
});

const SummarySchema = v.object({
    jobs: v.number(),
    objects: v.number(),
    blocks: v.number(),
    replicas: v.number(),
});

export type Session = v.InferOutput<typeof SessionSchema>;
export type Summary = v.InferOutput<typeof SummarySchema>;

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
