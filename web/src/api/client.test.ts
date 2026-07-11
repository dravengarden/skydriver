import { describe, expect, it } from "vitest";
import { parseSession } from "./client";

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
