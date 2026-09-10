import { AiProviderError, type SecurityAnalysisModel } from "../../src/modules/analysis/security-analysis-model.js";
import type { SecurityAnalysisInput } from "../../src/modules/analysis/security-analysis-input.js";
import type { SecurityAnalysisOutput } from "../../src/modules/analysis/security-analysis-output.schema.js";

/**
 * A hand-written `SecurityAnalysisModel` test double with fully controllable,
 * synchronous behavior — no real HTTP, no real AI provider. Mirrors
 * `FakeZapClient`'s role for `ZapClient` in Stage 4/5's tests.
 */
export class FakeSecurityAnalysisModel implements SecurityAnalysisModel {
  readonly calls: SecurityAnalysisInput[] = [];

  /** What `analyzeSecurityFindings` resolves with by default — override per test. */
  result: SecurityAnalysisOutput = {
    overallRisk: "medium",
    executiveSummary: "A default fake analysis summary.",
    keyRisks: [],
    findingAssessments: [],
    correlations: [],
    remediationPriorities: [],
    limitations: [],
  };

  /** When set, `analyzeSecurityFindings` rejects with this instead of resolving. */
  failWith: Error | null = null;

  async analyzeSecurityFindings(input: SecurityAnalysisInput): Promise<SecurityAnalysisOutput> {
    this.calls.push(input);
    if (this.failWith) {
      throw this.failWith;
    }
    return this.result;
  }
}

/** Convenience factory for a provider-style failure, matching what a real adapter would throw. */
export function fakeProviderError(message = "AI provider request failed"): AiProviderError {
  return new AiProviderError(message);
}
