import { describe, expect, it } from "vitest";
import { parseIntegrityFindings, parseSession } from "./client";

describe("parseSession", () => {
    it("accepts a valid authenticated session", () => {
        expect(parseSession({ authenticated: true, username: "operator" })).toEqual({
            authenticated: true,
            username: "operator",
        });
    });

    it("rejects malformed API data", () => {
        expect(() => parseSession({ authenticated: "yes", username: null })).toThrow();
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
