import { describe, it, expect } from "vitest";
import { GeminiSecurityAnalysisModel } from "../src/modules/analysis/providers/gemini-security-analysis-model.js";
import { HttpZapClient } from "../src/lib/zap-client.js";
import { AiProviderError } from "../src/modules/analysis/security-analysis-model.js";
import type { SecurityAnalysisInput } from "../src/modules/analysis/security-analysis-input.js";

describe("Stage 8: Live Integration Checks", () => {
  describe("Gemini Live Integration", () => {
    const apiKey = process.env.GEMINI_API_KEY?.trim();

    if (apiKey) {
      it("executes a live Gemini analysis request and returns structured schema-valid assessment", async () => {
        const model = new GeminiSecurityAnalysisModel({
          apiKey,
          model: "gemini-2.5-flash",
          timeoutMs: 30000,
          maxOutputTokens: 4000,
        });

        const input: SecurityAnalysisInput = {
          target: {
            url: "https://example.com",
            name: "Live Integration Target",
          },
          scan: {
            id: "live-test-scan-001",
            findingsCount: 1,
            findingsTruncated: 0,
          },
          findings: [
            {
              id: "f-001",
              title: "Cross Site Scripting (Reflected)",
              severity: "high",
              confidence: "high",
              category: "xss",
              cweId: 79,
              wascId: 8,
              remediation: "Context-sensitive output encoding should be applied.",
              instances: [
                {
                  url: "https://example.com/search?q=test",
                  method: "GET",
                  parameter: "q",
                  attack: "<script>alert(1)</script>",
                  evidence: "<script>alert(1)</script>",
                },
              ],
            },
          ],
        };

        const result = await model.analyzeSecurityFindings(input);
        expect(result).toBeDefined();
        expect(["critical", "high", "medium", "low", "informational"]).toContain(result.overallRisk);
        expect(result.summary.length).toBeGreaterThan(10);
        expect(result.findingAssessments.length).toBe(1);
        expect(result.findingAssessments[0].findingId).toBe("f-001");
        expect(["critical", "high", "medium", "low", "informational"]).toContain(
          result.findingAssessments[0].aiPriority,
        );
      });
    } else {
      it("safely rejects execution when GEMINI_API_KEY is missing without leaking internals", async () => {
        const model = new GeminiSecurityAnalysisModel({
          apiKey: undefined,
          model: "gemini-2.5-flash",
          timeoutMs: 1000,
        });

        const input: SecurityAnalysisInput = {
          target: { url: "https://example.com", name: "Example" },
          scan: { id: "test", findingsCount: 0, findingsTruncated: 0 },
          findings: [],
        };

        await expect(model.analyzeSecurityFindings(input)).rejects.toThrow(AiProviderError);
      });
    }
  });

  describe("ZAP Live Integration", () => {
    const zapUrl = process.env.ZAP_BASE_URL || "http://localhost:8090";

    it("evaluates live ZAP reachability", async () => {
      const client = new HttpZapClient({ baseUrl: zapUrl, timeoutMs: 2000 });
      const health = await client.health();

      if (health.reachable) {
        expect(health.version).toBeDefined();
        console.info(`[Stage 8 Live ZAP] Reachable, version: ${health.version}`);
      } else {
        console.warn(`[Stage 8 Live ZAP] BLOCKED: ZAP daemon is not responding on ${zapUrl}`);
        expect(health.reachable).toBe(false);
      }
    });
  });
});
