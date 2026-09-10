import type { FindingSeverity } from "../normalized-finding.js";

/**
 * ZAP's "risk" string → SentinelScan's `FindingSeverity`.
 *
 * Centralized here, and only here — nothing else in the codebase should
 * string-compare against ZAP's risk values. Matching is case-insensitive
 * since ZAP's casing has not been perfectly consistent across versions in
 * practice; keys below are lowercase, and the lookup lowercases its input.
 *
 * `critical` has no ZAP source today (ZAP's risk scale tops out at "High")
 * but stays a valid target so a future rule/tag that does distinguish a
 * critical tier has somewhere to map to without a schema change.
 */
const ZAP_RISK_TO_SEVERITY: Record<string, FindingSeverity> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
  informational: "informational",
};

/**
 * Documented, conservative fallback for a risk value ZAP has never been
 * observed to send. "Medium" — not "informational", which would risk
 * silently downplaying a real vulnerability; not "critical"/"high", which
 * would risk overstating one for what might just be an unrecognized label.
 * An unrecognized risk value is not expected in normal operation, but must
 * never crash a scan.
 */
export const FALLBACK_SEVERITY: FindingSeverity = "medium";

export function mapZapRiskToSeverity(risk: string | undefined): FindingSeverity {
  if (risk === undefined) return FALLBACK_SEVERITY;
  return ZAP_RISK_TO_SEVERITY[risk.trim().toLowerCase()] ?? FALLBACK_SEVERITY;
}
