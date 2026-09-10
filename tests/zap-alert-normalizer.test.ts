import { describe, it, expect } from "vitest";
import { normalizeZapAlerts } from "../src/modules/findings/zap/zap-alert-normalizer.js";
import { mapZapRiskToSeverity, FALLBACK_SEVERITY } from "../src/modules/findings/zap/zap-severity-mapping.js";
import { mapZapConfidenceToConfidence, FALLBACK_CONFIDENCE } from "../src/modules/findings/zap/zap-confidence-mapping.js";
import { mapZapPluginIdToCategory, FALLBACK_CATEGORY } from "../src/modules/findings/zap/zap-category-mapping.js";
import type { ZapRawAlert } from "../src/modules/findings/zap/zap-alert.js";

function alert(overrides: Partial<ZapRawAlert> = {}): ZapRawAlert {
  return {
    alert: "SQL Injection",
    name: "SQL Injection",
    risk: "High",
    confidence: "Medium",
    description: "SQL injection may be possible.",
    solution: "Use parameterized queries.",
    reference: "https://example.org/sqli\nhttps://example.org/sqli2",
    pluginId: "40018",
    cweid: "89",
    wascid: "19",
    url: "https://example.com/search?q=1",
    method: "GET",
    param: "q",
    attack: "1' OR '1'='1",
    evidence: "SQL syntax error",
    ...overrides,
  };
}

describe("zap-severity-mapping", () => {
  it.each([
    ["High", "high"],
    ["Medium", "medium"],
    ["Low", "low"],
    ["Informational", "informational"],
    ["high", "high"],
    ["  Medium  ", "medium"],
  ])("maps ZAP risk %s to severity %s", (risk, expected) => {
    expect(mapZapRiskToSeverity(risk)).toBe(expected);
  });

  it("falls back conservatively for an unrecognized risk value, never crashing", () => {
    expect(mapZapRiskToSeverity("Nonsense")).toBe(FALLBACK_SEVERITY);
    expect(mapZapRiskToSeverity(undefined)).toBe(FALLBACK_SEVERITY);
  });
});

describe("zap-confidence-mapping", () => {
  it.each([
    ["High", "high"],
    ["Medium", "medium"],
    ["Low", "low"],
    ["Confirmed", "high"],
  ])("maps ZAP confidence %s to confidence %s", (confidence, expected) => {
    expect(mapZapConfidenceToConfidence(confidence)).toBe(expected);
  });

  it("maps False Positive to unknown rather than discarding it", () => {
    expect(mapZapConfidenceToConfidence("False Positive")).toBe("unknown");
  });

  it("falls back to unknown for an unrecognized or missing confidence, never inventing a real level", () => {
    expect(mapZapConfidenceToConfidence("Nonsense")).toBe(FALLBACK_CONFIDENCE);
    expect(mapZapConfidenceToConfidence(undefined)).toBe(FALLBACK_CONFIDENCE);
  });
});

describe("zap-category-mapping", () => {
  it("maps known stable pluginIds to their SentinelScan category", () => {
    expect(mapZapPluginIdToCategory("40018")).toBe("injection"); // SQL Injection
    expect(mapZapPluginIdToCategory("40012")).toBe("client-side"); // Reflected XSS
    expect(mapZapPluginIdToCategory("10020")).toBe("security-header"); // X-Frame-Options
  });

  it("falls back to 'other' for an unrecognized pluginId, never guessing", () => {
    expect(mapZapPluginIdToCategory("999999")).toBe(FALLBACK_CATEGORY);
    expect(mapZapPluginIdToCategory(undefined)).toBe(FALLBACK_CATEGORY);
  });
});

describe("normalizeZapAlerts", () => {
  it("preserves title, description, remediation, sourceRuleId, CWE and WASC", () => {
    const [finding] = normalizeZapAlerts([alert()]);
    expect(finding.title).toBe("SQL Injection");
    expect(finding.description).toBe("SQL injection may be possible.");
    expect(finding.remediation).toBe("Use parameterized queries.");
    expect(finding.source).toBe("zap");
    expect(finding.sourceRuleId).toBe("40018");
    expect(finding.cweId).toBe(89);
    expect(finding.wascId).toBe(19);
  });

  it("splits ZAP's newline-delimited reference string into a list", () => {
    const [finding] = normalizeZapAlerts([alert()]);
    expect(finding.references).toEqual(["https://example.org/sqli", "https://example.org/sqli2"]);
  });

  it("treats ZAP's '0' sentinel as 'no CWE/WASC', not CWE-0/WASC-0", () => {
    const [finding] = normalizeZapAlerts([alert({ cweid: "0", wascid: "0" })]);
    expect(finding.cweId).toBeNull();
    expect(finding.wascId).toBeNull();
  });

  it("handles missing optional fields defensively without crashing", () => {
    const [finding] = normalizeZapAlerts([
      { alert: "Something", risk: "Low", pluginId: "99001" } as ZapRawAlert,
    ]);
    expect(finding.description).toBe("");
    expect(finding.remediation).toBeNull();
    expect(finding.references).toEqual([]);
    expect(finding.cweId).toBeNull();
    expect(finding.instances).toHaveLength(1);
    expect(finding.instances[0].url).toBe("");
  });

  it("handles malformed/unexpected scanner fields (wrong types) without crashing", () => {
    const malformed = { alert: 12345, risk: {}, pluginId: ["40018"], cweid: null } as unknown as ZapRawAlert;
    expect(() => normalizeZapAlerts([malformed])).not.toThrow();
    const [finding] = normalizeZapAlerts([malformed]);
    expect(finding.severity).toBe(FALLBACK_SEVERITY);
  });

  it("groups one ZAP alert reported at multiple instances into one Finding with multiple FindingInstances", () => {
    const findings = normalizeZapAlerts([
      alert({ url: "https://example.com/a?q=1", param: "q" }),
      alert({ url: "https://example.com/b?q=2", param: "q" }),
      alert({ url: "https://example.com/c?name=x", param: "name" }),
    ]);
    expect(findings).toHaveLength(1);
    expect(findings[0].instances).toHaveLength(3);
    expect(findings[0].instances.map((i) => i.url)).toEqual([
      "https://example.com/a?q=1",
      "https://example.com/b?q=2",
      "https://example.com/c?name=x",
    ]);
  });

  it("collapses exact-duplicate raw alerts into a single instance", () => {
    const duplicate = alert();
    const findings = normalizeZapAlerts([duplicate, { ...duplicate }, { ...duplicate }]);
    expect(findings).toHaveLength(1);
    expect(findings[0].instances).toHaveLength(1);
  });

  it("keeps distinct rules with similar names as separate findings (grouped by pluginId, not name)", () => {
    const findings = normalizeZapAlerts([
      alert({ pluginId: "40018", name: "SQL Injection" }),
      alert({ pluginId: "40019", name: "SQL Injection - MySQL" }),
    ]);
    expect(findings).toHaveLength(2);
    expect(new Set(findings.map((f) => f.sourceRuleId))).toEqual(new Set(["40018", "40019"]));
  });

  it("does not merge alerts for different rules that happen to share a name, when pluginId differs", () => {
    const findings = normalizeZapAlerts([
      alert({ pluginId: "10010", name: "Cookie Issue" }),
      alert({ pluginId: "10011", name: "Cookie Issue" }),
    ]);
    expect(findings).toHaveLength(2);
  });

  it("falls back to name-based grouping (with a null sourceRuleId) when pluginId is absent", () => {
    const findings = normalizeZapAlerts([
      alert({ pluginId: undefined, name: "Mystery Alert", url: "https://example.com/x" }),
      alert({ pluginId: undefined, name: "Mystery Alert", url: "https://example.com/y" }),
    ]);
    expect(findings).toHaveLength(1);
    expect(findings[0].sourceRuleId).toBeNull();
    expect(findings[0].instances).toHaveLength(2);
  });

  it("picks the worst-case severity/confidence across a group's occurrences", () => {
    const findings = normalizeZapAlerts([
      alert({ risk: "Low", confidence: "Low" }),
      alert({ risk: "High", confidence: "High", url: "https://example.com/worse" }),
    ]);
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("high");
    expect(findings[0].confidence).toBe("high");
  });

  it("returns an empty array for an empty input (a clean scan)", () => {
    expect(normalizeZapAlerts([])).toEqual([]);
  });

  it("redacts credential-like content in evidence before it ever reaches a NormalizedFinding", () => {
    const [finding] = normalizeZapAlerts([
      alert({ evidence: "Authorization: Bearer abc.def.ghi123456\nContent-Type: text/html" }),
    ]);
    expect(finding.instances[0].evidence).toContain("[REDACTED]");
    expect(finding.instances[0].evidence).not.toContain("abc.def.ghi123456");
  });

  it("redacts a Cookie header found in evidence", () => {
    const [finding] = normalizeZapAlerts([alert({ evidence: "Cookie: session=supersecretvalue123" })]);
    expect(finding.instances[0].evidence).not.toContain("supersecretvalue123");
    expect(finding.instances[0].evidence).toContain("[REDACTED]");
  });

  it("caps an oversized description rather than storing it unbounded", () => {
    const huge = "A".repeat(10000);
    const [finding] = normalizeZapAlerts([alert({ description: huge })]);
    expect(finding.description.length).toBeLessThan(6000);
    expect(finding.description).toContain("[truncated]");
  });
});
