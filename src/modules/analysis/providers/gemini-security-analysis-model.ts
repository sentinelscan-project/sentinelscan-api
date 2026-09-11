import { GoogleGenAI } from "@google/genai";
import { SECURITY_ANALYSIS_SYSTEM_PROMPT } from "../analysis-prompt.js";
import { AiProviderError, type SecurityAnalysisModel } from "../security-analysis-model.js";
import type { SecurityAnalysisInput } from "../security-analysis-input.js";
import { securityAnalysisOutputSchema, type SecurityAnalysisOutput } from "../security-analysis-output.schema.js";
import {
  ASSESSMENT_PRIORITIES,
  CORRELATION_RELATIONSHIPS,
  FALSE_POSITIVE_LIKELIHOODS,
  ANALYSIS_CONFIDENCE_LEVELS,
  OVERALL_RISK_LEVELS,
} from "../analysis-enums.js";

/**
 * Google Gemini implementation of {@link SecurityAnalysisModel}.
 *
 * Provider-agnostic concepts (the input contract, the output schema, prompt
 * versioning, cross-referencing finding IDs) live outside this file. A future
 * provider would be a new class implementing {@link SecurityAnalysisModel},
 * never branches inside this adapter.
 *
 * Structured output is obtained by setting `responseMimeType: "application/json"`
 * and `responseSchema: GEMINI_ANALYSIS_SCHEMA`. The response is rigorously validated
 * against `securityAnalysisOutputSchema` with Zod before being trusted.
 */

const stringConstraint = { type: "string" as const, minLength: 1 };

const findingAssessmentSchema = {
  type: "object" as const,
  properties: {
    findingId: { type: "string" as const, description: 'Must exactly match the "id" of a finding supplied in the input.' },
    priority: { type: "string" as const, enum: [...ASSESSMENT_PRIORITIES] },
    riskAssessment: stringConstraint,
    confidence: { type: "string" as const, enum: [...ANALYSIS_CONFIDENCE_LEVELS] },
    reasoning: stringConstraint,
    businessImpact: stringConstraint,
    technicalImpact: stringConstraint,
    remediationPriority: { type: "string" as const, enum: [...ASSESSMENT_PRIORITIES] },
    falsePositiveLikelihood: { type: "string" as const, enum: [...FALSE_POSITIVE_LIKELIHOODS] },
  },
  required: ["findingId", "priority", "riskAssessment", "confidence", "reasoning", "remediationPriority", "falsePositiveLikelihood"],
};

const findingCorrelationSchema = {
  type: "object" as const,
  properties: {
    findingAId: { type: "string" as const, description: 'Must exactly match the "id" of a finding supplied in the input.' },
    findingBId: { type: "string" as const, description: 'Must exactly match the "id" of a different finding supplied in the input.' },
    relationship: { type: "string" as const, enum: [...CORRELATION_RELATIONSHIPS] },
    confidence: { type: "string" as const, enum: [...ANALYSIS_CONFIDENCE_LEVELS] },
    explanation: stringConstraint,
  },
  required: ["findingAId", "findingBId", "relationship", "confidence", "explanation"],
};

export const GEMINI_ANALYSIS_SCHEMA = {
  type: "object" as const,
  properties: {
    overallRisk: { type: "string" as const, enum: [...OVERALL_RISK_LEVELS] },
    executiveSummary: stringConstraint,
    methodologySummary: stringConstraint,
    keyRisks: { type: "array" as const, items: stringConstraint },
    findingAssessments: { type: "array" as const, items: findingAssessmentSchema },
    correlations: { type: "array" as const, items: findingCorrelationSchema },
    remediationPriorities: { type: "array" as const, items: stringConstraint },
    limitations: { type: "array" as const, items: stringConstraint },
  },
  required: ["overallRisk", "executiveSummary", "keyRisks", "findingAssessments", "correlations", "remediationPriorities", "limitations"],
};

export interface GeminiSecurityAnalysisModelConfig {
  /**
   * Undefined when `GEMINI_API_KEY` isn't set — the app still boots and every
   * other feature keeps working (see `config.ts`). A `/analyze` request in
   * that state fails with a safe, generic provider error.
   */
  apiKey: string | undefined;
  model: string;
  timeoutMs: number;
  maxOutputTokens?: number;
}

export interface GeminiClientLike {
  models: {
    generateContent(params: {
      model: string;
      contents: string | { role: string; parts: { text: string }[] }[];
      config?: {
        systemInstruction?: string;
        responseMimeType?: string;
        responseSchema?: unknown;
        maxOutputTokens?: number;
        abortSignal?: AbortSignal;
      };
    }): Promise<{ text?: string | null }>;
  };
}

/**
 * Maps raw provider errors to safe, high-level error descriptions.
 * Never leaks raw provider messages, API keys, or payload details into
 * `SecurityAnalysis.errorMessage`.
 */
export function safeMessage(err: unknown): string {
  if (typeof err === "object" && err !== null) {
    const errorObj = err as { name?: string; message?: string; status?: number; statusCode?: number };
    if (errorObj.name === "AbortError" || (typeof errorObj.message === "string" && /timeout/i.test(errorObj.message))) {
      return "AI provider request timed out";
    }
    if (typeof errorObj.status === "number") {
      return `AI provider request failed (HTTP ${errorObj.status})`;
    }
    if (typeof errorObj.statusCode === "number") {
      return `AI provider request failed (HTTP ${errorObj.statusCode})`;
    }
    if (typeof errorObj.message === "string") {
      const statusMatch = errorObj.message.match(/\[(\d{3})\]|status[:\s]+(\d{3})|HTTP (\d{3})/i);
      if (statusMatch) {
        const code = statusMatch[1] || statusMatch[2] || statusMatch[3];
        return `AI provider request failed (HTTP ${code})`;
      }
    }
  }
  return "AI provider request failed";
}

export class GeminiSecurityAnalysisModel implements SecurityAnalysisModel {
  private client?: GeminiClientLike;
  private readonly isMockClient: boolean;

  constructor(
    private readonly config: GeminiSecurityAnalysisModelConfig,
    client?: GeminiClientLike,
  ) {
    this.isMockClient = Boolean(client);
    if (client) {
      this.client = client;
    }
  }

  private getClient(): GeminiClientLike {
    if (!this.client) {
      this.client = new GoogleGenAI({
        apiKey: this.config.apiKey || "",
      }) as unknown as GeminiClientLike;
    }
    return this.client;
  }

  async analyzeSecurityFindings(input: SecurityAnalysisInput): Promise<SecurityAnalysisOutput> {
    if (!this.config.apiKey) {
      throw new AiProviderError("AI provider request failed (HTTP 401)");
    }

    const client = this.getClient();
    let response: { text?: string | null } | undefined;
    const abortController = new AbortController();
    const timer = setTimeout(() => {
      abortController.abort();
    }, this.config.timeoutMs);

    let lastErr: unknown;
    const maxRetries = this.isMockClient ? 1 : 3;

    try {
      for (let attempt = 1; attempt <= maxRetries; attempt++) {
        try {
          response = await client.models.generateContent({
            model: this.config.model,
            contents: [
              {
                role: "user",
                parts: [{ text: JSON.stringify(input) }],
              },
            ],
            config: {
              systemInstruction: SECURITY_ANALYSIS_SYSTEM_PROMPT,
              responseMimeType: "application/json",
              responseSchema: GEMINI_ANALYSIS_SCHEMA,
              maxOutputTokens: this.config.maxOutputTokens,
              abortSignal: abortController.signal,
            },
          });
          lastErr = undefined;
          break;
        } catch (err) {
          lastErr = err;
          const errMessage = typeof err === "object" && err !== null && "message" in err ? String(err.message) : "";
          const isTransient =
            errMessage.includes("503") ||
            errMessage.includes("429") ||
            errMessage.includes("overloaded") ||
            errMessage.includes("resource has been exhausted");

          if (isTransient && attempt < maxRetries) {
            await new Promise((r) => setTimeout(r, attempt * 2000));
            continue;
          }

          if (
            (errMessage.includes("404") || errMessage.includes("no longer available")) &&
            this.config.model !== "gemini-3.6-flash"
          ) {
            try {
              response = await client.models.generateContent({
                model: "gemini-3.6-flash",
                contents: [
                  {
                    role: "user",
                    parts: [{ text: JSON.stringify(input) }],
                  },
                ],
                config: {
                  systemInstruction: SECURITY_ANALYSIS_SYSTEM_PROMPT,
                  responseMimeType: "application/json",
                  responseSchema: GEMINI_ANALYSIS_SCHEMA,
                  maxOutputTokens: this.config.maxOutputTokens,
                  abortSignal: abortController.signal,
                },
              });
              lastErr = undefined;
              break;
            } catch (fallbackErr) {
              lastErr = fallbackErr;
              break;
            }
          }
          break;
        }
      }

      if (lastErr || !response) {
        throw new AiProviderError(safeMessage(lastErr));
      }
    } finally {
      clearTimeout(timer);
    }

    const rawText = response.text;
    if (!rawText || typeof rawText !== "string" || rawText.trim() === "") {
      throw new AiProviderError("AI provider did not return an analysis response");
    }

    let parsedJson: unknown;
    try {
      parsedJson = JSON.parse(rawText);
    } catch {
      throw new AiProviderError("AI provider returned invalid JSON");
    }

    const parsed = securityAnalysisOutputSchema.safeParse(parsedJson);
    if (!parsed.success) {
      throw new AiProviderError("AI provider returned an invalid structured analysis");
    }
    return parsed.data;
  }
}
