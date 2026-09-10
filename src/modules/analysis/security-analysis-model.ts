import type { SecurityAnalysisInput } from "./security-analysis-input.js";
import type { SecurityAnalysisOutput } from "./security-analysis-output.schema.js";

/**
 * The provider-neutral boundary between `AnalysisService`/`SecurityAnalysisExecutor`
 * and any one AI provider. Mirrors `lib/zap-client.ts`'s `ZapClient` role for
 * Stage 4/5: nothing outside a concrete provider adapter
 * (`providers/gemini-security-analysis-model.ts` today) constructs a
 * provider API request or parses a provider response body.
 *
 * `AnalysisService → SecurityAnalysisModel → provider` is the layering this
 * type exists to enforce. A future second provider would be a new class
 * implementing this same interface — no change required anywhere else.
 */
export interface SecurityAnalysisModel {
  /**
   * Analyzes `input` and returns a structured result already validated
   * against `securityAnalysisOutputSchema`. Implementations must reject
   * (throw `AiProviderError`) rather than return anything that doesn't pass
   * that schema — this method's return type is a promise, never a partial
   * or best-effort result.
   */
  analyzeSecurityFindings(input: SecurityAnalysisInput): Promise<SecurityAnalysisOutput>;
}

/**
 * Thrown for any failure talking to an AI provider, or for a response that
 * doesn't satisfy the structured output contract. The message is always
 * safe to store in `SecurityAnalysis.errorMessage` and never includes a raw
 * provider error, API key, or response body — see each provider adapter's
 * own `safeMessage` helper for what "safe" means for that provider's SDK.
 */
export class AiProviderError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AiProviderError";
  }
}
