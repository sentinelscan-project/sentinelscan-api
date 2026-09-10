import type { FindingCategory } from "./finding-category.js";

/**
 * The scanner-neutral output every normalization adapter must produce.
 *
 * `modules/findings/zap/zap-alert-normalizer.ts` is the *only* file in this
 * codebase that knows what a ZAP alert looks like; it consumes ZAP's raw
 * alert shape and produces `NormalizedFinding[]`. A future SentinelScan-native
 * scanner (or any other scanner source) would have its own adapter consuming
 * its own raw shape, but producing this exact same type — nothing downstream
 * of normalization (persistence, the API, a future AI analyst) needs to know
 * anything ZAP-specific. See the README's "Architecture Principle" section.
 *
 * Every string field here is expected to already be sanitized (redacted,
 * length-capped — see `lib/sanitize-text.ts`) by the adapter that produced
 * it; persistence does not sanitize again.
 */
export type FindingSeverity = "critical" | "high" | "medium" | "low" | "informational";
export type FindingConfidence = "high" | "medium" | "low" | "unknown";

export interface NormalizedFindingInstance {
  url: string;
  method?: string | null;
  parameter?: string | null;
  attack?: string | null;
  evidence?: string | null;
}

export interface NormalizedFinding {
  title: string;
  description: string;
  severity: FindingSeverity;
  confidence: FindingConfidence;
  category: FindingCategory;
  cweId?: number | null;
  wascId?: number | null;
  remediation?: string | null;
  /** Reference URLs, already sanitized and bounded. */
  references: string[];
  /** e.g. `"zap"`. Free text, not an enum — see `Finding.source`'s schema comment. */
  source: string;
  /** The source's own stable rule identifier, when available (never just the human-readable title). */
  sourceRuleId?: string | null;
  /** At least one — a finding with zero locations would not be a meaningful finding. */
  instances: NormalizedFindingInstance[];
}
