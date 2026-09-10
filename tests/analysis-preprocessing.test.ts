import { describe, it, expect } from "vitest";
import {
  buildSecurityAnalysisInput,
  MAX_DESCRIPTION_LENGTH,
  MAX_EVIDENCE_LENGTH,
  MAX_FINDINGS_PER_ANALYSIS,
  MAX_INSTANCES_PER_FINDING,
} from "../src/modules/analysis/analysis-preprocessing.js";
import type { FindingWithInstances, FindingCounts } from "../src/repositories/finding.repository.js";

const EMPTY_COUNTS: FindingCounts = { critical: 0, high: 0, medium: 0, low: 0, informational: 0, total: 0 };

function makeFinding(overrides: Partial<FindingWithInstances> = {}): FindingWithInstances {
  return {
    id: overrides.id ?? "00000000-0000-0000-0000-000000000001",
    scanId: "scan-1",
    title: "Some Finding",
    description: "A description.",
    severity: "medium",
    confidence: "medium",
    category: "other",
    cweId: null,
    wascId: null,
    remediation: null,
    references: [],
    source: "zap",
    sourceRuleId: "1",
    createdAt: new Date(),
    updatedAt: new Date(),
    instances: [{ id: "i1", findingId: "f1", url: "https://example.com/", method: "GET", parameter: null, attack: null, evidence: null, createdAt: new Date() }],
    ...overrides,
  };
}

const SCAN = { id: "scan-1", targetName: "Acme Staging", targetOrigin: "https://staging.acme.example.com" };

describe("buildSecurityAnalysisInput", () => {
  it("carries the correct scan metadata through unchanged", () => {
    const input = buildSecurityAnalysisInput(SCAN, [makeFinding()], EMPTY_COUNTS);
    expect(input.scan).toEqual(SCAN);
  });

  it("loads every supplied finding and its instances", () => {
    const finding = makeFinding({
      instances: [
        { id: "i1", findingId: "f1", url: "https://example.com/a", method: "GET", parameter: "q", attack: null, evidence: null, createdAt: new Date() },
        { id: "i2", findingId: "f1", url: "https://example.com/b", method: "POST", parameter: "name", attack: null, evidence: null, createdAt: new Date() },
      ],
    });
    const input = buildSecurityAnalysisInput(SCAN, [finding], EMPTY_COUNTS);
    expect(input.findings).toHaveLength(1);
    expect(input.findings[0].instances).toHaveLength(2);
    expect(input.findings[0].instances[0].url).toBe("https://example.com/a");
    expect(input.findings[0].instances[1].parameter).toBe("name");
  });

  it("passes deterministic counts through unchanged rather than letting the AI recompute them", () => {
    const counts: FindingCounts = { critical: 1, high: 2, medium: 3, low: 0, informational: 0, total: 6 };
    const input = buildSecurityAnalysisInput(SCAN, [makeFinding()], counts);
    expect(input.findingCounts).toEqual(counts);
  });

  it("sorts findings deterministically by severity (highest first), independent of input order", () => {
    const low = makeFinding({ id: "id-low", severity: "low" });
    const critical = makeFinding({ id: "id-critical", severity: "critical" });
    const medium = makeFinding({ id: "id-medium", severity: "medium" });

    const input = buildSecurityAnalysisInput(SCAN, [low, medium, critical], EMPTY_COUNTS);

    expect(input.findings.map((f) => f.id)).toEqual(["id-critical", "id-medium", "id-low"]);
  });

  it("breaks severity ties deterministically by id, regardless of input order", () => {
    const a = makeFinding({ id: "aaaa", severity: "high" });
    const b = makeFinding({ id: "bbbb", severity: "high" });

    const first = buildSecurityAnalysisInput(SCAN, [b, a], EMPTY_COUNTS);
    const second = buildSecurityAnalysisInput(SCAN, [a, b], EMPTY_COUNTS);

    expect(first.findings.map((f) => f.id)).toEqual(["aaaa", "bbbb"]);
    expect(second.findings.map((f) => f.id)).toEqual(["aaaa", "bbbb"]);
  });

  it("removes sensitive information from finding text a second time (defense in depth)", () => {
    const finding = makeFinding({
      description: "Cookie: session=verysecretsessionvalue123",
      remediation: "Set api_key=abcdef123456 to disable it (example only).",
    });
    const input = buildSecurityAnalysisInput(SCAN, [finding], EMPTY_COUNTS);
    expect(input.findings[0].description).not.toContain("verysecretsessionvalue123");
    expect(input.findings[0].remediation).not.toContain("abcdef123456");
  });

  it("removes sensitive information from instance evidence", () => {
    const finding = makeFinding({
      instances: [{ id: "i1", findingId: "f1", url: "https://example.com/", method: "GET", parameter: null, attack: null, evidence: "Authorization: Bearer sometoken12345", createdAt: new Date() }],
    });
    const input = buildSecurityAnalysisInput(SCAN, [finding], EMPTY_COUNTS);
    expect(input.findings[0].instances[0].evidence).not.toContain("sometoken12345");
  });

  it("caps description length", () => {
    const finding = makeFinding({ description: "A".repeat(10000) });
    const input = buildSecurityAnalysisInput(SCAN, [finding], EMPTY_COUNTS);
    expect(input.findings[0].description.length).toBeLessThan(MAX_DESCRIPTION_LENGTH + 50);
  });

  it("caps evidence length per instance", () => {
    const finding = makeFinding({
      instances: [{ id: "i1", findingId: "f1", url: "https://example.com/", method: "GET", parameter: null, attack: null, evidence: "E".repeat(5000), createdAt: new Date() }],
    });
    const input = buildSecurityAnalysisInput(SCAN, [finding], EMPTY_COUNTS);
    expect(input.findings[0].instances[0].evidence!.length).toBeLessThan(MAX_EVIDENCE_LENGTH + 50);
  });

  it("bounds instances per finding", () => {
    const manyInstances = Array.from({ length: 20 }, (_, i) => ({
      id: `i${i}`,
      findingId: "f1",
      url: `https://example.com/${i}`,
      method: "GET",
      parameter: null,
      attack: null,
      evidence: null,
      createdAt: new Date(),
    }));
    const finding = makeFinding({ instances: manyInstances });
    const input = buildSecurityAnalysisInput(SCAN, [finding], EMPTY_COUNTS);
    expect(input.findings[0].instances).toHaveLength(MAX_INSTANCES_PER_FINDING);
  });

  it("bounds the number of findings and reports how many were truncated", () => {
    const manyFindings = Array.from({ length: MAX_FINDINGS_PER_ANALYSIS + 15 }, (_, i) =>
      makeFinding({ id: `finding-${i}`, severity: "low" }),
    );
    const input = buildSecurityAnalysisInput(SCAN, manyFindings, EMPTY_COUNTS);
    expect(input.findings).toHaveLength(MAX_FINDINGS_PER_ANALYSIS);
    expect(input.truncatedFindingsCount).toBe(15);
  });

  it("reports zero truncation when nothing was dropped", () => {
    const input = buildSecurityAnalysisInput(SCAN, [makeFinding()], EMPTY_COUNTS);
    expect(input.truncatedFindingsCount).toBe(0);
  });

  it("returns an empty findings array for a scan with no findings", () => {
    const input = buildSecurityAnalysisInput(SCAN, [], EMPTY_COUNTS);
    expect(input.findings).toEqual([]);
    expect(input.truncatedFindingsCount).toBe(0);
  });

  it("keeps the highest-severity findings when truncating, not an arbitrary subset", () => {
    const criticals = Array.from({ length: 5 }, (_, i) => makeFinding({ id: `critical-${i}`, severity: "critical" }));
    const lows = Array.from({ length: MAX_FINDINGS_PER_ANALYSIS }, (_, i) => makeFinding({ id: `low-${i}`, severity: "low" }));
    const input = buildSecurityAnalysisInput(SCAN, [...lows, ...criticals], EMPTY_COUNTS);
    expect(input.findings.every((f) => f.severity === "critical")).toBe(false);
    // All 5 criticals must have survived the cut, since they rank above every "low".
    const criticalIdsInInput = input.findings.filter((f) => f.severity === "critical").map((f) => f.id);
    expect(criticalIdsInInput).toHaveLength(5);
  });
});
