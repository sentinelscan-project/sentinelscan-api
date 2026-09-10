import { getPrismaClient } from "../db/prisma.js";
import type {
  AnalysisRepository,
  CompleteAnalysisInput,
  CreateAnalysisInput,
  SecurityAnalysisRecord,
  SecurityAnalysisWithResults,
  TransitionAnalysisInput,
} from "./analysis.repository.js";
import type { AnalysisStatus } from "../modules/analysis/analysis-enums.js";

/** Internal signal: the `running → completed` CAS guard inside `completeAnalysis`'s transaction did not match — abort and roll back, never partially persist. */
class CompleteAnalysisCasMiss extends Error {}

/**
 * Prisma-backed {@link AnalysisRepository} used at runtime.
 *
 * `completeAnalysis` is the one method that does more than a single
 * statement: it wraps the `running → completed` CAS-guarded update together
 * with creating every `FindingAssessment`/`FindingCorrelation` row in one
 * `$transaction` — either the whole result lands, or none of it does. The
 * CAS guard uses `updateMany` (not `update`) for the same reason
 * `prisma-scan.repository.ts` does: only `updateMany` accepts an arbitrary
 * `WHERE` filter (id *and* status), which is what makes the compare-and-swap
 * possible at all.
 */
export const prismaAnalysisRepository: AnalysisRepository = {
  create(input: CreateAnalysisInput): Promise<SecurityAnalysisRecord> {
    return getPrismaClient().securityAnalysis.create({
      data: {
        scanId: input.scanId,
        promptVersion: input.promptVersion,
      },
    });
  },

  findById(id: string): Promise<SecurityAnalysisRecord | null> {
    return getPrismaClient().securityAnalysis.findUnique({ where: { id } });
  },

  findByIdForOwner(id: string, ownerId: string): Promise<SecurityAnalysisWithResults | null> {
    return getPrismaClient().securityAnalysis.findFirst({
      where: { id, scan: { requestedById: ownerId } },
      include: { assessments: true, correlations: true },
    });
  },

  findByScanIdForOwner(scanId: string, ownerId: string): Promise<SecurityAnalysisWithResults | null> {
    return getPrismaClient().securityAnalysis.findFirst({
      where: { scanId, scan: { requestedById: ownerId } },
      include: { assessments: true, correlations: true },
    });
  },

  async transitionStatus(
    id: string,
    fromStatus: AnalysisStatus,
    input: TransitionAnalysisInput,
  ): Promise<SecurityAnalysisRecord | null> {
    const prisma = getPrismaClient();
    const { count } = await prisma.securityAnalysis.updateMany({
      where: { id, status: fromStatus },
      data: input,
    });
    if (count === 0) {
      return null;
    }
    // The updateMany above already proved this id (and status) matched, so a plain findUnique by id is safe here.
    return prisma.securityAnalysis.findUnique({ where: { id } });
  },

  async completeAnalysis(id: string, data: CompleteAnalysisInput): Promise<SecurityAnalysisRecord | null> {
    const prisma = getPrismaClient();
    try {
      return await prisma.$transaction(async (tx) => {
        const { count } = await tx.securityAnalysis.updateMany({
          where: { id, status: "running" },
          data: {
            status: "completed",
            model: data.model,
            overallRisk: data.overallRisk,
            executiveSummary: data.executiveSummary,
            methodologySummary: data.methodologySummary,
            limitations: data.limitations,
            completedAt: data.completedAt,
          },
        });
        if (count === 0) {
          throw new CompleteAnalysisCasMiss();
        }

        if (data.assessments.length > 0) {
          await tx.findingAssessment.createMany({
            data: data.assessments.map((assessment) => ({ analysisId: id, ...assessment })),
          });
        }
        if (data.correlations.length > 0) {
          await tx.findingCorrelation.createMany({
            data: data.correlations.map((correlation) => ({ analysisId: id, ...correlation })),
          });
        }

        return tx.securityAnalysis.findUniqueOrThrow({ where: { id } });
      });
    } catch (err) {
      if (err instanceof CompleteAnalysisCasMiss) {
        return null;
      }
      throw err;
    }
  },
};
