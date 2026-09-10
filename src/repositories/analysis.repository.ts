import type {
  AnalysisConfidence,
  AnalysisStatus,
  AssessmentPriority,
  FalsePositiveLikelihood,
  OverallRisk,
} from "../modules/analysis/analysis-enums.js";

/**
 * Persistence boundary for `SecurityAnalysis` and its child records
 * (`FindingAssessment`, `FindingCorrelation`). Mirrors the split established
 * by `ScanRepository`/`FindingRepository`: a bare `SecurityAnalysisRecord`
 * for lifecycle/CAS operations, and a `SecurityAnalysisWithResults` (record
 * + assessments + correlations) for anything a caller actually reads.
 *
 * `findByIdForOwner`/`findByScanIdForOwner` follow the same
 * ownership-scoped-query pattern as every other repository in this
 * codebase: ownership is enforced by the query itself (a join through
 * `SecurityAnalysis.scan.requestedById`), not fetched-then-checked.
 */

export interface SecurityAnalysisRecord {
  id: string;
  scanId: string;
  status: AnalysisStatus;
  model: string | null;
  promptVersion: string;
  overallRisk: OverallRisk | null;
  executiveSummary: string | null;
  methodologySummary: string | null;
  limitations: string | null;
  createdAt: Date;
  updatedAt: Date;
  completedAt: Date | null;
  errorMessage: string | null;
}

export interface FindingAssessmentRecord {
  id: string;
  analysisId: string;
  findingId: string;
  priority: AssessmentPriority;
  riskAssessment: string;
  confidence: AnalysisConfidence;
  reasoning: string;
  businessImpact: string | null;
  technicalImpact: string | null;
  remediationPriority: AssessmentPriority;
  falsePositiveLikelihood: FalsePositiveLikelihood;
  createdAt: Date;
  updatedAt: Date;
}

export interface FindingCorrelationRecord {
  id: string;
  analysisId: string;
  findingAId: string;
  findingBId: string;
  relationship: string;
  confidence: AnalysisConfidence;
  explanation: string;
  createdAt: Date;
}

export interface SecurityAnalysisWithResults extends SecurityAnalysisRecord {
  assessments: FindingAssessmentRecord[];
  correlations: FindingCorrelationRecord[];
}

export interface CreateAnalysisInput {
  scanId: string;
  promptVersion: string;
}

/** Fields a status transition may set alongside the new `status` itself. */
export interface TransitionAnalysisInput {
  status: AnalysisStatus;
  completedAt?: Date;
  errorMessage?: string | null;
}

export interface FindingAssessmentInput {
  findingId: string;
  priority: AssessmentPriority;
  riskAssessment: string;
  confidence: AnalysisConfidence;
  reasoning: string;
  businessImpact: string | null;
  technicalImpact: string | null;
  remediationPriority: AssessmentPriority;
  falsePositiveLikelihood: FalsePositiveLikelihood;
}

export interface FindingCorrelationInput {
  findingAId: string;
  findingBId: string;
  relationship: string;
  confidence: AnalysisConfidence;
  explanation: string;
}

/** Everything produced by a successful model run, ready to persist atomically. */
export interface CompleteAnalysisInput {
  model: string;
  overallRisk: OverallRisk;
  executiveSummary: string;
  methodologySummary: string | null;
  limitations: string | null;
  completedAt: Date;
  assessments: FindingAssessmentInput[];
  correlations: FindingCorrelationInput[];
}

export interface AnalysisRepository {
  /** Throws the underlying Prisma unique-constraint error (P2002) when `scanId` already has an analysis — see `isUniqueConstraintError`. */
  create(input: CreateAnalysisInput): Promise<SecurityAnalysisRecord>;
  /** Internal lookup with no ownership scoping — for the executor, not any route. */
  findById(id: string): Promise<SecurityAnalysisRecord | null>;
  findByIdForOwner(id: string, ownerId: string): Promise<SecurityAnalysisWithResults | null>;
  findByScanIdForOwner(scanId: string, ownerId: string): Promise<SecurityAnalysisWithResults | null>;
  /**
   * Atomic compare-and-swap, exactly like `ScanRepository.transitionStatus`:
   * applies `input` only if the row's current `status` is exactly
   * `fromStatus`. Used for `queued → running` and `running → failed`;
   * `running → completed` goes through `completeAnalysis` instead, since
   * that transition also persists child rows in the same transaction.
   */
  transitionStatus(id: string, fromStatus: AnalysisStatus, input: TransitionAnalysisInput): Promise<SecurityAnalysisRecord | null>;
  /**
   * The `running → completed` transition: guarded by the same CAS as
   * `transitionStatus`, but additionally creates every `FindingAssessment`
   * and `FindingCorrelation` row in the same short transaction. Returns
   * `null` (writing nothing) if the CAS guard didn't match — e.g. the
   * analysis was somehow no longer `running`.
   */
  completeAnalysis(id: string, data: CompleteAnalysisInput): Promise<SecurityAnalysisRecord | null>;
}

/** The only analysis shape that may cross the API boundary. No raw provider response, no internal Prisma field, ever leaks through this. */
export interface PublicFindingAssessment {
  id: string;
  findingId: string;
  priority: AssessmentPriority;
  riskAssessment: string;
  confidence: AnalysisConfidence;
  reasoning: string;
  businessImpact: string | null;
  technicalImpact: string | null;
  remediationPriority: AssessmentPriority;
  falsePositiveLikelihood: FalsePositiveLikelihood;
  createdAt: string;
  updatedAt: string;
}

export interface PublicFindingCorrelation {
  id: string;
  findingAId: string;
  findingBId: string;
  relationship: string;
  confidence: AnalysisConfidence;
  explanation: string;
  createdAt: string;
}

export interface PublicSecurityAnalysis {
  id: string;
  scanId: string;
  status: AnalysisStatus;
  model: string | null;
  promptVersion: string;
  overallRisk: OverallRisk | null;
  executiveSummary: string | null;
  methodologySummary: string | null;
  limitations: string | null;
  createdAt: string;
  updatedAt: string;
  completedAt: string | null;
  errorMessage: string | null;
  assessments: PublicFindingAssessment[];
  correlations: PublicFindingCorrelation[];
}

export function toPublicAnalysis(analysis: SecurityAnalysisWithResults): PublicSecurityAnalysis {
  return {
    id: analysis.id,
    scanId: analysis.scanId,
    status: analysis.status,
    model: analysis.model,
    promptVersion: analysis.promptVersion,
    overallRisk: analysis.overallRisk,
    executiveSummary: analysis.executiveSummary,
    methodologySummary: analysis.methodologySummary,
    limitations: analysis.limitations,
    createdAt: analysis.createdAt.toISOString(),
    updatedAt: analysis.updatedAt.toISOString(),
    completedAt: analysis.completedAt ? analysis.completedAt.toISOString() : null,
    errorMessage: analysis.errorMessage,
    assessments: analysis.assessments.map((assessment) => ({
      id: assessment.id,
      findingId: assessment.findingId,
      priority: assessment.priority,
      riskAssessment: assessment.riskAssessment,
      confidence: assessment.confidence,
      reasoning: assessment.reasoning,
      businessImpact: assessment.businessImpact,
      technicalImpact: assessment.technicalImpact,
      remediationPriority: assessment.remediationPriority,
      falsePositiveLikelihood: assessment.falsePositiveLikelihood,
      createdAt: assessment.createdAt.toISOString(),
      updatedAt: assessment.updatedAt.toISOString(),
    })),
    correlations: analysis.correlations.map((correlation) => ({
      id: correlation.id,
      findingAId: correlation.findingAId,
      findingBId: correlation.findingBId,
      relationship: correlation.relationship,
      confidence: correlation.confidence,
      explanation: correlation.explanation,
      createdAt: correlation.createdAt.toISOString(),
    })),
  };
}
