import { describe, it, expect } from "vitest";
import {
  sanitizeFindingText,
  sanitizeOptionalFindingText,
  sanitizeReferenceList,
} from "../src/lib/sanitize-text.js";

describe("sanitizeFindingText — credential redaction", () => {
  it("redacts an Authorization header, keeping the header name (and its original casing) for context", () => {
    const result = sanitizeFindingText("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.secret.payload", 1000);
    expect(result).toContain("Authorization: [REDACTED]");
    expect(result).not.toContain("eyJhbGciOiJIUzI1NiJ9");
  });

  it("redacts a Cookie header", () => {
    const result = sanitizeFindingText("Cookie: session=abc123verysecretvalue", 1000);
    expect(result).toContain("[REDACTED]");
    expect(result).not.toContain("abc123verysecretvalue");
  });

  it("redacts a Set-Cookie header", () => {
    const result = sanitizeFindingText("Set-Cookie: sid=deadbeef1234567890; HttpOnly", 1000);
    expect(result).not.toContain("deadbeef1234567890");
  });

  it("redacts a generic api_key=value pair", () => {
    const result = sanitizeFindingText("request?api_key=sk_live_abcdef123456", 1000);
    expect(result).not.toContain("sk_live_abcdef123456");
    expect(result).toContain("[REDACTED]");
  });

  it("redacts a bearer token key=value pair", () => {
    const result = sanitizeFindingText("bearer=abcdefghijklmnop", 1000);
    expect(result).not.toContain("abcdefghijklmnop");
  });

  it("redacts an obvious password field", () => {
    const result = sanitizeFindingText('{"password": "hunter2hunter2"}', 1000);
    expect(result).not.toContain("hunter2hunter2");
  });

  it("redacts a session id field", () => {
    const result = sanitizeFindingText("session_id=abcdef0123456789", 1000);
    expect(result).not.toContain("abcdef0123456789");
  });

  it("leaves ordinary, non-credential text unchanged", () => {
    const result = sanitizeFindingText("The response returned a 500 Internal Server Error.", 1000);
    expect(result).toBe("The response returned a 500 Internal Server Error.");
  });
});

describe("sanitizeFindingText — length capping", () => {
  it("caps an oversized string and marks it truncated", () => {
    const huge = "x".repeat(5000);
    const result = sanitizeFindingText(huge, 100);
    expect(result.length).toBeLessThanOrEqual(100 + "… [truncated]".length);
    expect(result).toContain("… [truncated]");
  });

  it("prefers redaction over truncation: a secret near the boundary is still fully redacted", () => {
    const value = `padding-${"a".repeat(50)} Authorization: Bearer sensitive-value-that-must-not-leak`;
    const result = sanitizeFindingText(value, 40);
    expect(result).not.toContain("sensitive-value-that-must-not-leak");
  });

  it("does not truncate a string within the limit", () => {
    const result = sanitizeFindingText("short", 100);
    expect(result).toBe("short");
  });
});

describe("sanitizeOptionalFindingText", () => {
  it("passes null and undefined through unchanged", () => {
    expect(sanitizeOptionalFindingText(null, 100)).toBeNull();
    expect(sanitizeOptionalFindingText(undefined, 100)).toBeNull();
  });

  it("treats a blank string as absent", () => {
    expect(sanitizeOptionalFindingText("   ", 100)).toBeNull();
  });

  it("sanitizes a present value the same way sanitizeFindingText does", () => {
    expect(sanitizeOptionalFindingText("Cookie: session=verysecretvalue1234", 1000)).not.toContain(
      "verysecretvalue1234",
    );
  });
});

describe("sanitizeReferenceList", () => {
  it("drops blank entries", () => {
    expect(sanitizeReferenceList(["https://a.example", "", "   ", "https://b.example"], 10, 100)).toEqual([
      "https://a.example",
      "https://b.example",
    ]);
  });

  it("caps the number of entries", () => {
    const many = Array.from({ length: 50 }, (_, i) => `https://example.com/${i}`);
    expect(sanitizeReferenceList(many, 5, 100)).toHaveLength(5);
  });

  it("caps each entry's length", () => {
    const [result] = sanitizeReferenceList(["x".repeat(500)], 10, 50);
    expect(result.length).toBeLessThanOrEqual(50 + "… [truncated]".length);
  });
});
