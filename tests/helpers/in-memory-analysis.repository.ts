import { randomUUID } from "node:crypto";
import type {
  AnalysisRepository,
  CompleteAnalysisInput,
  CreateAnalysisInput,
  FindingAssessmentRecord,
  FindingCorrelationRecord,
  SecurityAnalysisRecord,
  SecurityAnalysisWithResults,
  TransitionAnalysisInput,
} from "../../src/repositories/analysis.repository.js";
import type { AnalysisStatus } from "../../src/modules/analysis/analysis-enums.js";

/** Mimics Prisma's unique-constraint violation so services can be tested against it — mirrors `in-memory-target.repository.ts`. */
class UniqueConstraintError extends Error {
  readonly code = "P2002";
  constructor(target: string) {
    super(`Unique constraint failed on the fields: (\`${target}\`)`);
    this.name = "PrismaClientKnownRequestError";
  }
}

export interface InMemoryAnalysisRepository extends AnalysisRepository {
  readonly rows: Map<string, SecurityAnalysisWithResults>;
  reset(): void;
  /** Test-only: `analysisId -> ownerId` of the scan it belongs to, for `findByIdForOwner`'s join emulation — mirrors `InMemoryFindingRepository.scanOwners`. */
  analysisOwners: Map<string, string>;
  scanOwners: Map<string, string>;
}

function clone(analysis: SecurityAnalysisWithResults): SecurityAnalysisWithResults {
  return {
    ...analysis,
    assessments: analysis.assessments.map((a) => ({ ...a })),
    correlations: analysis.correlations.map((c) => ({ ...c })),
  };
}

/**
 * In-memory {@link AnalysisRepository}.
 *
 * `transitionStatus`/`completeAnalysis` reproduce the Prisma implementation's
 * compare-and-swap semantics synchronously (no `await` between the status
 * check and the write), matching `InMemoryScanRepository`'s documented
 * reasoning for why that is what makes "concurrent" CAS calls safe to test.
 */
export function createInMemoryAnalysisRepository(): InMemoryAnalysisRepository {
  const rows = new Map<string, SecurityAnalysisWithResults>();
  const scanOwners = new Map<string, string>();

  function ownerIdForScan(scanId: string): string | undefined {
    return scanOwners.get(scanId);
  }

  return {
    rows,
    scanOwners,
    analysisOwners: scanOwners,

    reset(): void {
      rows.clear();
      scanOwners.clear();
    },

    create(input: CreateAnalysisInput): Promise<SecurityAnalysisRecord> {
      for (const existing of rows.values()) {
        if (existing.scanId === input.scanId) {
          return Promise.reject(new UniqueConstraintError("scanId"));
        }
      }
      const now = new Date();
      const analysis: SecurityAnalysisWithResults = {
        id: randomUUID(),
        scanId: input.scanId,
        status: "queued",
        model: null,
        promptVersion: input.promptVersion,
        overallRisk: null,
        executiveSummary: null,
        methodologySummary: null,
        limitations: null,
        createdAt: now,
        updatedAt: now,
        completedAt: null,
        errorMessage: null,
        assessments: [],
        correlations: [],
      };
      rows.set(analysis.id, analysis);
      return Promise.resolve(clone(analysis));
    },

    findById(id: string): Promise<SecurityAnalysisRecord | null> {
      const analysis = rows.get(id);
      return Promise.resolve(analysis ? clone(analysis) : null);
    },

    findByIdForOwner(id: string, ownerId: string): Promise<SecurityAnalysisWithResults | null> {
      const analysis = rows.get(id);
      if (!analysis || ownerIdForScan(analysis.scanId) !== ownerId) {
        return Promise.resolve(null);
      }
      return Promise.resolve(clone(analysis));
    },

    findByScanIdForOwner(scanId: string, ownerId: string): Promise<SecurityAnalysisWithResults | null> {
      if (ownerIdForScan(scanId) !== ownerId) {
        return Promise.resolve(null);
      }
      for (const analysis of rows.values()) {
        if (analysis.scanId === scanId) {
          return Promise.resolve(clone(analysis));
        }
      }
      return Promise.resolve(null);
    },

    // Deliberately not `async` at the top — see `InMemoryScanRepository`'s
    // identical comment on why the read-check-write must run synchronously.
    transitionStatus(
      id: string,
      fromStatus: AnalysisStatus,
      input: TransitionAnalysisInput,
    ): Promise<SecurityAnalysisRecord | null> {
      const analysis = rows.get(id);
      if (!analysis || analysis.status !== fromStatus) {
        return Promise.resolve(null);
      }
      analysis.status = input.status;
      if (input.completedAt !== undefined) analysis.completedAt = input.completedAt;
      if (input.errorMessage !== undefined) analysis.errorMessage = input.errorMessage;
      analysis.updatedAt = new Date();
      return Promise.resolve(clone(analysis));
    },

    completeAnalysis(id: string, data: CompleteAnalysisInput): Promise<SecurityAnalysisRecord | null> {
      const analysis = rows.get(id);
      if (!analysis || analysis.status !== "running") {
        return Promise.resolve(null);
      }

      analysis.status = "completed";
      analysis.model = data.model;
      analysis.overallRisk = data.overallRisk;
      analysis.executiveSummary = data.executiveSummary;
      analysis.methodologySummary = data.methodologySummary;
      analysis.limitations = data.limitations;
      analysis.completedAt = data.completedAt;
      analysis.updatedAt = new Date();

      const now = new Date();
      analysis.assessments = data.assessments.map(
        (assessment): FindingAssessmentRecord => ({
          id: randomUUID(),
          analysisId: id,
          createdAt: now,
          updatedAt: now,
          ...assessment,
        }),
      );
      analysis.correlations = data.correlations.map(
        (correlation): FindingCorrelationRecord => ({
          id: randomUUID(),
          analysisId: id,
          createdAt: now,
          ...correlation,
        }),
      );

      return Promise.resolve(clone(analysis));
    },
  };
}
