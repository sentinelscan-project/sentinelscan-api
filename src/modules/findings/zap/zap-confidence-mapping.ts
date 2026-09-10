import type { FindingConfidence } from "../normalized-finding.js";

/**
 * ZAP's "confidence" string → SentinelScan's `FindingConfidence`.
 *
 * Centralized here, matching the pattern in `zap-severity-mapping.ts`.
 * Covers ZAP's known confidence levels, including the "False Positive"
 * label ZAP uses when a user has manually marked an alert as such in the UI
 * — that is not the same as "low confidence" (a false positive is a claim
 * the finding is *wrong*, not merely uncertain), so it is intentionally kept
 * distinct rather than folded into `"low"`. Since SentinelScan's own
 * `FindingConfidence` has no "false positive" tier, it maps to `"unknown"`
 * — never discarded, never silently reinterpreted as a real confidence
 * level.
 */
const ZAP_CONFIDENCE_TO_CONFIDENCE: Record<string, FindingConfidence> = {
  high: "high",
  medium: "medium",
  low: "low",
  "false positive": "unknown",
  "falsepositive": "unknown",
  confirmed: "high",
};

/** Documented fallback: confidence information is never invented, only ever marked unknown. */
export const FALLBACK_CONFIDENCE: FindingConfidence = "unknown";

export function mapZapConfidenceToConfidence(confidence: string | undefined): FindingConfidence {
  if (confidence === undefined) return FALLBACK_CONFIDENCE;
  return ZAP_CONFIDENCE_TO_CONFIDENCE[confidence.trim().toLowerCase()] ?? FALLBACK_CONFIDENCE;
}
