import { sanitizeFindingText, sanitizeOptionalFindingText, sanitizeReferenceList } from "../../lib/sanitize-text.js";
import { toReferenceList, type FindingCounts, type FindingWithInstances } from "../../repositories/finding.repository.js";
import type { SecurityAnalysisInput, SecurityAnalysisInputFinding, SecurityAnalysisInputInstance } from "./security-analysis-input.js";

/**
 * Explicit, documented bounds on everything sent to an AI provider. Findings
 * are already sanitized and reasonably bounded by Stage 5's own
 * normalization-time limits, but this module re-applies sanitization and its
 * own (generally tighter) limits independently — "deterministic
 * preprocessing" per the Stage 6 spec means the AI input is never simply
 * "whatever is in the database right now" with no defensive bound of its
 * own, even though today the two limit sets happen to agree in spirit.
 */
export const MAX_FINDINGS_PER_ANALYSIS = 40;
export const MAX_INSTANCES_PER_FINDING = 5;
export const MAX_TITLE_LENGTH = 300;
export const MAX_DESCRIPTION_LENGTH = 1500;
export const MAX_REMEDIATION_LENGTH = 1500;
export const MAX_URL_LENGTH = 1000;
export const MAX_PARAMETER_LENGTH = 200;
export const MAX_ATTACK_LENGTH = 500;
export const MAX_EVIDENCE_LENGTH = 500;
export const MAX_REFERENCES_PER_FINDING = 10;
export const MAX_REFERENCE_LENGTH = 300;

const SEVERITY_RANK: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  informational: 0,
};

/**
 * Deterministic ordering: highest scanner severity first, then a stable
 * tie-break on `id`. `createdAt` is deliberately not used for the primary
 * sort — Stage 5 persists every finding for a scan inside one transaction,
 * so rows from the same scan commonly share an identical `createdAt`
 * timestamp, which would make an `createdAt`-based ordering effectively
 * unstable (dependent on incidental row-return order) rather than truly
 * deterministic.
 */
function sortFindingsDeterministically(findings: FindingWithInstances[]): FindingWithInstances[] {
  return [...findings].sort((a, b) => {
    const rankDiff = (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0);
    if (rankDiff !== 0) return rankDiff;
    return a.id.localeCompare(b.id);
  });
}

function toInputInstance(instance: FindingWithInstances["instances"][number]): SecurityAnalysisInputInstance {
  return {
    url: sanitizeFindingText(instance.url, MAX_URL_LENGTH),
    method: instance.method,
    parameter: sanitizeOptionalFindingText(instance.parameter, MAX_PARAMETER_LENGTH),
    attack: sanitizeOptionalFindingText(instance.attack, MAX_ATTACK_LENGTH),
    evidence: sanitizeOptionalFindingText(instance.evidence, MAX_EVIDENCE_LENGTH),
  };
}

function toInputFinding(finding: FindingWithInstances): SecurityAnalysisInputFinding {
  return {
    id: finding.id,
    title: sanitizeFindingText(finding.title, MAX_TITLE_LENGTH),
    description: sanitizeFindingText(finding.description, MAX_DESCRIPTION_LENGTH),
    severity: finding.severity,
    confidence: finding.confidence,
    category: finding.category,
    cweId: finding.cweId,
    wascId: finding.wascId,
    remediation: sanitizeOptionalFindingText(finding.remediation, MAX_REMEDIATION_LENGTH),
    references: sanitizeReferenceList(toReferenceList(finding.references), MAX_REFERENCES_PER_FINDING, MAX_REFERENCE_LENGTH),
    instances: finding.instances.slice(0, MAX_INSTANCES_PER_FINDING).map(toInputInstance),
  };
}

/**
 * Builds the deterministic `SecurityAnalysisInput` for one scan.
 *
 * Ownership and scan-status verification happen entirely upstream, in
 * `analysis.service.ts` — this function trusts that `findings` was already
 * loaded for a scan the caller is authorized to see. It performs everything
 * else the Stage 6 spec calls "deterministic preprocessing": sanitizing
 * text fields again, bounding every list/string length, sorting findings
 * deterministically, and reporting how many findings (if any) were dropped
 * by the `MAX_FINDINGS_PER_ANALYSIS` cap so the AI's own context makes the
 * truncation visible rather than silently analyzing a partial picture.
 */
export function buildSecurityAnalysisInput(
  scan: { id: string; targetName: string; targetOrigin: string },
  findings: FindingWithInstances[],
  counts: FindingCounts,
): SecurityAnalysisInput {
  const sorted = sortFindingsDeterministically(findings);
  const bounded = sorted.slice(0, MAX_FINDINGS_PER_ANALYSIS);
  const truncatedFindingsCount = sorted.length - bounded.length;

  return {
    scan,
    findingCounts: counts,
    findings: bounded.map(toInputFinding),
    truncatedFindingsCount,
  };
}
