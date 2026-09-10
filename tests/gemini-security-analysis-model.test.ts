import { describe, it, expect, vi } from "vitest";
import {
  GeminiSecurityAnalysisModel,
  type GeminiClientLike,
} from "../src/modules/analysis/providers/gemini-security-analysis-model.js";
import { AiProviderError } from "../src/modules/analysis/security-analysis-model.js";
import type { SecurityAnalysisInput } from "../src/modules/analysis/security-analysis-input.js";

const CONFIG = {
  apiKey: "test-gemini-key",
  model: "gemini-2.5-flash",
  timeoutMs: 5000,
  maxOutputTokens: 4000,
};

const SAMPLE_INPUT: SecurityAnalysisInput = {
  scan: { id: "scan-1", targetName: "Acme Staging", targetOrigin: "https://staging.acme.example.com" },
  findingCounts: { critical: 0, high: 1, medium: 0, low: 0, informational: 0, total: 1 },
  findings: [
    {
      id: "11111111-1111-1111-1111-111111111111",
      title: "Reflected XSS",
      description: "Reflected XSS was detected.",
      severity: "high",
      confidence: "medium",
      category: "client-side",
      cweId: 79,
      wascId: 8,
      remediation: "Encode output.",
      references: [],
      instances: [{ url: "https://staging.acme.example.com/search?q=1", method: "GET", parameter: "q" }],
    },
  ],
  truncatedFindingsCount: 0,
};

const VALID_ANALYSIS_OUTPUT = {
  overallRisk: "high",
  executiveSummary: "One high-severity XSS finding.",
  keyRisks: ["Reflected XSS on the search endpoint"],
  findingAssessments: [
    {
      findingId: "11111111-1111-1111-1111-111111111111",
      priority: "high",
      riskAssessment: "Exploitable reflected XSS.",
      confidence: "high",
      reasoning: "Evidence directly demonstrates reflection.",
      remediationPriority: "high",
      falsePositiveLikelihood: "low",
    },
  ],
  correlations: [],
  remediationPriorities: ["Encode the q parameter on output"],
  limitations: [],
};

function fakeClientReturning(text: string | null): GeminiClientLike {
  return {
    models: {
      generateContent: vi.fn().mockResolvedValue({ text }),
    },
  };
}

function fakeClientRejecting(error: unknown): GeminiClientLike {
  return {
    models: {
      generateContent: vi.fn().mockRejectedValue(error),
    },
  };
}

describe("GeminiSecurityAnalysisModel", () => {
  it("returns a validated structured analysis for a valid JSON response", async () => {
    const client = fakeClientReturning(JSON.stringify(VALID_ANALYSIS_OUTPUT));
    const model = new GeminiSecurityAnalysisModel(CONFIG, client);

    const result = await model.analyzeSecurityFindings(SAMPLE_INPUT);

    expect(result.overallRisk).toBe("high");
    expect(result.findingAssessments).toHaveLength(1);
    expect(result.findingAssessments[0].findingId).toBe("11111111-1111-1111-1111-111111111111");
  });

  it("passes the system instruction and structured schema config", async () => {
    const generateContent = vi.fn().mockResolvedValue({ text: JSON.stringify(VALID_ANALYSIS_OUTPUT) });
    const client: GeminiClientLike = { models: { generateContent } };
    const model = new GeminiSecurityAnalysisModel(CONFIG, client);

    await model.analyzeSecurityFindings(SAMPLE_INPUT);

    expect(generateContent).toHaveBeenCalledTimes(1);
    const params = generateContent.mock.calls[0][0];
    expect(params.model).toBe("gemini-2.5-flash");
    expect(params.config?.systemInstruction).toContain("SentinelScan AI Security Analyst");
    expect(params.config?.responseMimeType).toBe("application/json");
    expect(params.config?.responseSchema).toBeDefined();
  });

  it("rejects with AiProviderError when the response has an invalid enum value", async () => {
    const client = fakeClientReturning(
      JSON.stringify({ ...VALID_ANALYSIS_OUTPUT, overallRisk: "extremely-bad" }),
    );
    const model = new GeminiSecurityAnalysisModel(CONFIG, client);

    await expect(model.analyzeSecurityFindings(SAMPLE_INPUT)).rejects.toBeInstanceOf(AiProviderError);
  });

  it("rejects with AiProviderError when a required field is missing", async () => {
    const withoutSummary: Record<string, unknown> = { ...VALID_ANALYSIS_OUTPUT };
    delete withoutSummary.executiveSummary;
    const client = fakeClientReturning(JSON.stringify(withoutSummary));
    const model = new GeminiSecurityAnalysisModel(CONFIG, client);

    await expect(model.analyzeSecurityFindings(SAMPLE_INPUT)).rejects.toBeInstanceOf(AiProviderError);
  });

  it("rejects with AiProviderError when findingId is not a UUID", async () => {
    const client = fakeClientReturning(
      JSON.stringify({
        ...VALID_ANALYSIS_OUTPUT,
        findingAssessments: [{ ...VALID_ANALYSIS_OUTPUT.findingAssessments[0], findingId: "not-a-uuid" }],
      }),
    );
    const model = new GeminiSecurityAnalysisModel(CONFIG, client);

    await expect(model.analyzeSecurityFindings(SAMPLE_INPUT)).rejects.toBeInstanceOf(AiProviderError);
  });

  it("rejects with AiProviderError when response is not valid JSON", async () => {
    const client = fakeClientReturning("Here is your analysis: not valid json at all");
    const model = new GeminiSecurityAnalysisModel(CONFIG, client);

    await expect(model.analyzeSecurityFindings(SAMPLE_INPUT)).rejects.toThrow("AI provider returned invalid JSON");
  });

  it("rejects with AiProviderError when response text is empty", async () => {
    const client = fakeClientReturning("");
    const model = new GeminiSecurityAnalysisModel(CONFIG, client);

    await expect(model.analyzeSecurityFindings(SAMPLE_INPUT)).rejects.toThrow(
      "AI provider did not return an analysis response",
    );
  });

  it("rejects with safe 401 when API key is missing", async () => {
    const client = fakeClientReturning(JSON.stringify(VALID_ANALYSIS_OUTPUT));
    const model = new GeminiSecurityAnalysisModel({ ...CONFIG, apiKey: undefined }, client);

    await expect(model.analyzeSecurityFindings(SAMPLE_INPUT)).rejects.toThrow(
      "AI provider request failed (HTTP 401)",
    );
  });

  it("maps an abort / timeout error to a safe timeout message", async () => {
    const abortError = new Error("This operation was aborted");
    abortError.name = "AbortError";
    const client = fakeClientRejecting(abortError);
    const model = new GeminiSecurityAnalysisModel(CONFIG, client);

    await expect(model.analyzeSecurityFindings(SAMPLE_INPUT)).rejects.toThrow("AI provider request timed out");
  });

  it("maps an HTTP error to a safe message including only the status code", async () => {
    const httpError = new Error("Request failed with status: [503] Service Unavailable");
    const client = fakeClientRejecting(httpError);
    const model = new GeminiSecurityAnalysisModel(CONFIG, client);

    await expect(model.analyzeSecurityFindings(SAMPLE_INPUT)).rejects.toThrow(
      "AI provider request failed (HTTP 503)",
    );
  });

  it("never leaks the raw provider error or key into the thrown error", async () => {
    const secretError = new Error(
      "GoogleGenerativeAIError: [400] API key AIzaSyFakeSecretKeyValueIsNotValid for project 12345",
    );
    const client = fakeClientRejecting(secretError);
    const model = new GeminiSecurityAnalysisModel(CONFIG, client);

    try {
      await model.analyzeSecurityFindings(SAMPLE_INPUT);
      expect.unreachable("expected analyzeSecurityFindings to reject");
    } catch (err) {
      expect(err).toBeInstanceOf(AiProviderError);
      expect((err as Error).message).not.toContain("AIzaSyFakeSecretKeyValueIsNotValid");
      expect((err as Error).message).toBe("AI provider request failed (HTTP 400)");
    }
  });

  it("wraps an unexpected provider failure in a safe generic message", async () => {
    const client = fakeClientRejecting(new Error("unexpected internal SDK detail"));
    const model = new GeminiSecurityAnalysisModel(CONFIG, client);

    await expect(model.analyzeSecurityFindings(SAMPLE_INPUT)).rejects.toThrow("AI provider request failed");
  });
});
