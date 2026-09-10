import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { SecurityAnalysisExecutor } from "../src/modules/analysis/security-analysis-executor.js";
import { FakeSecurityAnalysisModel, fakeProviderError } from "./helpers/fake-security-analysis-model.js";
import {
  createInMemoryAnalysisRepository,
  type InMemoryAnalysisRepository,
} from "./helpers/in-memory-analysis.repository.js";
import {
  createInMemoryFindingRepository,
  type InMemoryFindingRepository,
} from "./helpers/in-memory-finding.repository.js";
import type { NormalizedFinding } from "../src/modules/findings/normalized-finding.js";
import type { SecurityAnalysisOutput } from "../src/modules/analysis/security-analysis-output.schema.js";

let analyses: InMemoryAnalysisRepository;
let findings: InMemoryFindingRepository;
let model: FakeSecurityAnalysisModel;
let executor: SecurityAnalysisExecutor;

const OWNER_ID = "owner-1";
const CONTEXT = { targetName: "Acme Staging", targetOrigin: "https://staging.acme.example.com" };

function sampleFinding(overrides: Partial<NormalizedFinding> = {}): NormalizedFinding {
  return {
    title: "Cross Site Scripting (Reflected)",
    description: "Reflected XSS was detected.",
    severity: "high",
    confidence: "medium",
    category: "client-side",
    cweId: 79,
    wascId: 8,
    remediation: "Encode output.",
    references: ["https://owasp.org/xss"],
    source: "zap",
    sourceRuleId: "40012",
    instances: [{ url: "https://staging.acme.example.com/search?q=1", method: "GET", parameter: "q" }],
    ...overrides,
  };
}

async function seedScanWithFindings(normalizedFindings: NormalizedFinding[]): Promise<{ scanId: string; analysisId: string }> {
  const scanId = `scan-${Math.random().toString(36).slice(2)}`;
  analyses.scanOwners.set(scanId, OWNER_ID);
  await findings.createMany(scanId, normalizedFindings);
  const analysis = await analyses.create({ scanId, promptVersion: "1.0" });
  return { scanId, analysisId: analysis.id };
}

beforeEach(() => {
  analyses = createInMemoryAnalysisRepository();
  findings = createInMemoryFindingRepository();
  model = new FakeSecurityAnalysisModel();
  executor = new SecurityAnalysisExecutor(model, analyses, findings, { modelName: "fake-model-1" });
  vi.spyOn(console, "info").mockImplementation(() => undefined);
  vi.spyOn(console, "error").mockImplementation(() => undefined);
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("execution — happy path", () => {
  it("moves a queued analysis through running to completed", async () => {
    const { scanId, analysisId } = await seedScanWithFindings([sampleFinding()]);

    await executor.execute({ analysisId, scanId, ...CONTEXT });

    const final = await analyses.findById(analysisId);
    expect(final?.status).toBe("completed");
    expect(final?.model).toBe("fake-model-1");
    expect(final?.completedAt).toBeInstanceOf(Date);
  });

  it("builds a deterministic input from the persisted findings and passes it to the model", async () => {
    const { scanId, analysisId } = await seedScanWithFindings([sampleFinding()]);

    await executor.execute({ analysisId, scanId, ...CONTEXT });

    expect(model.calls).toHaveLength(1);
    expect(model.calls[0].scan).toEqual({ id: scanId, targetName: CONTEXT.targetName, targetOrigin: CONTEXT.targetOrigin });
    expect(model.calls[0].findings).toHaveLength(1);
    expect(model.calls[0].findingCounts.high).toBe(1);
  });

  it("persists FindingAssessment rows returned by the model, linked to the analysis", async () => {
    const { scanId, analysisId } = await seedScanWithFindings([sampleFinding()]);
    const findingId = [...findings.rows.values()][0].id;
    model.result = {
      overallRisk: "high",
      executiveSummary: "One XSS finding requires attention.",
      keyRisks: ["Reflected XSS"],
      findingAssessments: [
        {
          findingId,
          priority: "high",
          riskAssessment: "Exploitable reflected XSS on a search endpoint.",
          confidence: "high",
          reasoning: "Evidence directly demonstrates script reflection.",
          remediationPriority: "high",
          falsePositiveLikelihood: "low",
        },
      ],
      correlations: [],
      remediationPriorities: ["Encode search query output"],
      limitations: [],
    };

    await executor.execute({ analysisId, scanId, ...CONTEXT });

    const final = await analyses.findById(analysisId);
    expect(final?.status).toBe("completed");
    const stored = analyses.rows.get(analysisId);
    expect(stored?.assessments).toHaveLength(1);
    expect(stored?.assessments[0].findingId).toBe(findingId);
    expect(stored?.assessments[0].priority).toBe("high");
  });

  it("persists FindingCorrelation rows, canonicalizing the pair order", async () => {
    const { scanId, analysisId } = await seedScanWithFindings([
      sampleFinding({ sourceRuleId: "40012" }),
      sampleFinding({ sourceRuleId: "10020", title: "X-Frame-Options Header Not Set", category: "security-header" }),
    ]);
    const [findingA, findingB] = [...findings.rows.values()];
    model.result = baseOutput({
      correlations: [
        {
          findingAId: findingB.id,
          findingBId: findingA.id,
          relationship: "related",
          confidence: "medium",
          explanation: "Both affect the same page.",
        },
      ],
    });

    await executor.execute({ analysisId, scanId, ...CONTEXT });

    const stored = analyses.rows.get(analysisId);
    expect(stored?.correlations).toHaveLength(1);
    // Canonicalized to lexicographic order regardless of the order the model returned them in.
    const [correlation] = stored!.correlations;
    expect([correlation.findingAId, correlation.findingBId]).toEqual(
      [findingA.id, findingB.id].sort(),
    );
  });

  it("completes with zero assessments/correlations for an empty result", async () => {
    const { scanId, analysisId } = await seedScanWithFindings([sampleFinding()]);

    await executor.execute({ analysisId, scanId, ...CONTEXT });

    const final = await analyses.findById(analysisId);
    expect(final?.status).toBe("completed");
  });
});

describe("failure handling", () => {
  it("marks the analysis failed when the provider rejects", async () => {
    const { scanId, analysisId } = await seedScanWithFindings([sampleFinding()]);
    model.failWith = fakeProviderError("AI provider request failed (HTTP 500)");

    await executor.execute({ analysisId, scanId, ...CONTEXT });

    const final = await analyses.findById(analysisId);
    expect(final?.status).toBe("failed");
    expect(final?.errorMessage).toBe("AI provider request failed (HTTP 500)");
  });

  it("never leaks a raw underlying error message into errorMessage", async () => {
    const { scanId, analysisId } = await seedScanWithFindings([sampleFinding()]);
    model.failWith = new Error("ECONNREFUSED 10.0.0.9:443 apikey=super-secret-value");

    await executor.execute({ analysisId, scanId, ...CONTEXT });

    const final = await analyses.findById(analysisId);
    expect(final?.status).toBe("failed");
    expect(final?.errorMessage).not.toContain("super-secret-value");
    expect(final?.errorMessage).not.toContain("10.0.0.9");
  });

  it("marks the analysis failed (rejecting the output) when the AI references a finding id that was never supplied", async () => {
    const { scanId, analysisId } = await seedScanWithFindings([sampleFinding()]);
    model.result = baseOutput({
      findingAssessments: [
        {
          findingId: "00000000-0000-0000-0000-000000000000",
          priority: "high",
          riskAssessment: "x",
          confidence: "high",
          reasoning: "x",
          remediationPriority: "high",
          falsePositiveLikelihood: "low",
        },
      ],
    });

    await executor.execute({ analysisId, scanId, ...CONTEXT });

    const final = await analyses.findById(analysisId);
    expect(final?.status).toBe("failed");
    expect(final?.errorMessage).toContain("not present in the analysis input");
    const stored = analyses.rows.get(analysisId);
    expect(stored?.assessments).toHaveLength(0);
  });

  it("marks the analysis failed when a correlation references an unknown finding id", async () => {
    const { scanId, analysisId } = await seedScanWithFindings([sampleFinding()]);
    const findingId = [...findings.rows.values()][0].id;
    model.result = baseOutput({
      correlations: [
        {
          findingAId: findingId,
          findingBId: "00000000-0000-0000-0000-000000000000",
          relationship: "related",
          confidence: "low",
          explanation: "x",
        },
      ],
    });

    await executor.execute({ analysisId, scanId, ...CONTEXT });

    const final = await analyses.findById(analysisId);
    expect(final?.status).toBe("failed");
  });

  it("does not persist any child rows when persistence is rejected for invalid ids", async () => {
    const { scanId, analysisId } = await seedScanWithFindings([sampleFinding()]);
    model.result = baseOutput({
      findingAssessments: [
        {
          findingId: "00000000-0000-0000-0000-000000000000",
          priority: "high",
          riskAssessment: "x",
          confidence: "high",
          reasoning: "x",
          remediationPriority: "high",
          falsePositiveLikelihood: "low",
        },
      ],
    });

    await executor.execute({ analysisId, scanId, ...CONTEXT });

    const stored = analyses.rows.get(analysisId);
    expect(stored?.status).toBe("failed");
    expect(stored?.assessments).toHaveLength(0);
    expect(stored?.correlations).toHaveLength(0);
  });
});

function baseOutput(overrides: Partial<SecurityAnalysisOutput> = {}): SecurityAnalysisOutput {
  return {
    overallRisk: "medium",
    executiveSummary: "Summary.",
    keyRisks: [],
    findingAssessments: [],
    correlations: [],
    remediationPriorities: [],
    limitations: [],
    ...overrides,
  };
}
