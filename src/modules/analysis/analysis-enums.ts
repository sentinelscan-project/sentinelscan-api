/**
 * Closed value sets shared across the analysis module — the application-layer
 * source of truth for every enum-like field on `SecurityAnalysis`,
 * `FindingAssessment`, and `FindingCorrelation`. Mirrors the pattern
 * established in `modules/findings/finding-category.ts`.
 */

export const ANALYSIS_STATUSES = ["queued", "running", "completed", "failed"] as const;
export type AnalysisStatus = (typeof ANALYSIS_STATUSES)[number];

export const OVERALL_RISK_LEVELS = ["critical", "high", "medium", "low", "informational"] as const;
export type OverallRisk = (typeof OVERALL_RISK_LEVELS)[number];

/** The AI's priority judgment — deliberately never conflated with `Finding.severity`. */
export const ASSESSMENT_PRIORITIES = ["critical", "high", "medium", "low", "informational"] as const;
export type AssessmentPriority = (typeof ASSESSMENT_PRIORITIES)[number];

export const FALSE_POSITIVE_LIKELIHOODS = ["low", "medium", "high", "unknown"] as const;
export type FalsePositiveLikelihood = (typeof FALSE_POSITIVE_LIKELIHOODS)[number];

/**
 * The same confidence scale `Finding.confidence` already uses
 * (`finding.repository.ts`'s `FindingConfidence`), reused here for the AI's
 * confidence in its own assessments/correlations — the same underlying
 * concept (confidence in a claim), applied by a different party. Kept as a
 * separately-declared list (not an import) only so this module has no
 * compile-time dependency on `repositories/finding.repository.ts`'s
 * unrelated types; the two lists must stay in sync by inspection, exactly
 * like every other cross-file enum mirror in this codebase (see
 * `repositories/scan.repository.ts`'s `ScanStatus` vs. the Prisma enum).
 */
export const ANALYSIS_CONFIDENCE_LEVELS = ["high", "medium", "low", "unknown"] as const;
export type AnalysisConfidence = (typeof ANALYSIS_CONFIDENCE_LEVELS)[number];

/**
 * A closed, controlled list of relationship types the AI may claim between
 * two findings. Deliberately not free text — the AI is never allowed to
 * invent an arbitrary relationship label. Several values are hyphenated, so
 * (matching `FindingCategory`'s reasoning) `FindingCorrelation.relationship`
 * is a plain `String` column in the database, validated against this list at
 * the application layer rather than as a Prisma enum.
 *
 * - `related` — a general, otherwise-uncategorized relationship.
 * - `duplicate-symptom` — two findings likely stem from observing the same
 *   underlying issue from different angles (not literal duplicate rows —
 *   Stage 5's normalization already dedupes those — but symptoms that read
 *   as the same root problem surfacing twice).
 * - `attack-chain` — one finding plausibly enables or extends another,
 *   *only* when the supplied evidence actually supports that chain; the
 *   prompt (`analysis-prompt.ts`) explicitly instructs the model to prefer
 *   `related` with an explanation over an unsupported `attack-chain` claim.
 * - `shared-root-cause` — both findings plausibly trace back to one
 *   underlying misconfiguration or design issue.
 * - `amplifies-risk` — one finding makes the other more severe or more
 *   easily exploitable in combination, without necessarily forming a chain.
 */
export const CORRELATION_RELATIONSHIPS = [
  "related",
  "duplicate-symptom",
  "attack-chain",
  "shared-root-cause",
  "amplifies-risk",
] as const;
export type CorrelationRelationship = (typeof CORRELATION_RELATIONSHIPS)[number];

export function isCorrelationRelationship(value: string): value is CorrelationRelationship {
  return (CORRELATION_RELATIONSHIPS as readonly string[]).includes(value);
}
