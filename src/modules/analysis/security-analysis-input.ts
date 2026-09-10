import type { FindingConfidence } from "../../repositories/finding.repository.js";

/**
 * The deterministic, size-bounded, re-sanitized input handed to a
 * `SecurityAnalysisModel`. Built once, by `buildSecurityAnalysisInput`
 * (`analysis-preprocessing.ts`), from already-persisted `Finding`/
 * `FindingInstance` rows — never assembled ad hoc by a provider adapter.
 *
 * Every string field here has already passed back through
 * `lib/sanitize-text.ts` (a second redaction pass — defense in depth on top
 * of Stage 5's own normalization-time sanitization) and been length-capped.
 * Nothing in this shape can carry a password, cookie, Authorization header,
 * API key, session token, or database credential — see
 * `analysis-preprocessing.ts`'s documented limits.
 */
export interface SecurityAnalysisInputInstance {
  url: string;
  method?: string | null;
  parameter?: string | null;
  attack?: string | null;
  evidence?: string | null;
}

export interface SecurityAnalysisInputFinding {
  id: string;
  title: string;
  description: string;
  severity: string;
  confidence: FindingConfidence;
  category: string;
  cweId: number | null;
  wascId: number | null;
  remediation: string | null;
  references: string[];
  instances: SecurityAnalysisInputInstance[];
}

/** Deterministic counts computed by the application — the AI receives these rather than being trusted to count findings itself. */
export interface SecurityAnalysisInputCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  informational: number;
  total: number;
}

export interface SecurityAnalysisInput {
  scan: {
    id: string;
    targetName: string;
    /** Scheme + host (+ non-default port) only — see `URL.origin`. Never the full target URL with path/query. */
    targetOrigin: string;
  };
  findingCounts: SecurityAnalysisInputCounts;
  findings: SecurityAnalysisInputFinding[];
  /** How many findings were omitted by the `MAX_FINDINGS_PER_ANALYSIS` cap — `0` when nothing was truncated. */
  truncatedFindingsCount: number;
}
