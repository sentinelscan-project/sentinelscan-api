import { ConflictError, NotFoundError } from "../../lib/errors.js";
import { isUniqueConstraintError } from "../../lib/prisma-errors.js";
import type { ScanRepository } from "../../repositories/scan.repository.js";
import type { TargetRepository } from "../../repositories/target.repository.js";
import type {
  AnalysisRepository,
  CompleteAnalysisInput,
  SecurityAnalysisRecord,
  SecurityAnalysisWithResults,
} from "../../repositories/analysis.repository.js";
import type { AnalysisStatus } from "./analysis-enums.js";
import type { AnalysisExecutor } from "./analysis-executor.js";
import { SECURITY_ANALYSIS_PROMPT_VERSION } from "./analysis-prompt.js";

/**
 * The complete set of legal lifecycle transitions — mirrors
 * `scan.service.ts`'s `VALID_TRANSITIONS` exactly in spirit. `completed` and
 * `failed` are both terminal: neither has an outgoing transition, which is
 * what makes a failed analysis non-retryable in place (see the
 * `SecurityAnalysis.scanId` uniqueness-strategy doc comment in
 * `schema.prisma` for why that is a deliberate Stage 6 decision, not an
 * oversight).
 */
const VALID_TRANSITIONS: Record<AnalysisStatus, readonly AnalysisStatus[]> = {
  queued: ["running"],
  running: ["completed", "failed"],
  completed: [],
  failed: [],
};

export function isValidAnalysisTransition(from: AnalysisStatus, to: AnalysisStatus): boolean {
  return VALID_TRANSITIONS[from].includes(to);
}

function scanNotFoundError(): NotFoundError {
  return new NotFoundError("Scan not found", "SCAN_NOT_FOUND");
}

function analysisNotFoundError(): NotFoundError {
  return new NotFoundError("Analysis not found", "ANALYSIS_NOT_FOUND");
}

function scanNotCompletedError(): ConflictError {
  return new ConflictError("Scan must be completed before it can be analyzed", "SCAN_NOT_COMPLETED");
}

function analysisAlreadyExistsError(): ConflictError {
  return new ConflictError(
    "An analysis already exists for this scan. Stage 6 supports at most one analysis per scan.",
    "ANALYSIS_ALREADY_EXISTS",
  );
}

function invalidAnalysisTransitionError(from: AnalysisStatus, to: AnalysisStatus): ConflictError {
  return new ConflictError(`Analysis cannot move from '${from}' to '${to}'`, "INVALID_ANALYSIS_TRANSITION");
}

/**
 * Requests a new analysis of a completed scan the caller owns, and hands it
 * to `analysisExecutor` for execution — the same fire-and-forget shape
 * `scan.service.ts`'s `createScan` uses for `ZapScanExecutor`: a real AI
 * provider call can take tens of seconds, and `POST /scans/:scanId/analyze`
 * must return as soon as the `SecurityAnalysis` row exists, not block for
 * the model to finish.
 *
 * Ownership, scan-existence, and scan-completion are all verified before any
 * write: `scanRepository.findByIdForOwner` is itself owner-scoped, so a scan
 * belonging to someone else is indistinguishable from one that does not
 * exist. `targetRepository.findByIdForOwner` is called here (not inside the
 * executor) for the same reason `createScan` resolves the target URL at
 * request time — the executor runs as a background worker with only the
 * `ownerId`-free context it's explicitly given.
 *
 * Duplicate-analysis prevention (Stage 6's "at most one analysis per scan,
 * ever" rule) is enforced by the database's own `SecurityAnalysis.scanId`
 * unique constraint, not a separate check-then-create race: `analysisRepository.create`
 * is attempted directly, and a unique-constraint violation (P2002) is
 * translated into a clean `409 ANALYSIS_ALREADY_EXISTS` — this is what makes
 * two concurrent `POST /scans/:scanId/analyze` requests for the same scan
 * resolve safely (exactly one `create` can ever succeed).
 */
export async function requestAnalysis(
  scanRepository: ScanRepository,
  targetRepository: TargetRepository,
  analysisRepository: AnalysisRepository,
  analysisExecutor: AnalysisExecutor,
  ownerId: string,
  scanId: string,
): Promise<SecurityAnalysisRecord> {
  const scan = await scanRepository.findByIdForOwner(scanId, ownerId);
  if (!scan) {
    throw scanNotFoundError();
  }
  if (scan.status !== "completed") {
    throw scanNotCompletedError();
  }

  const target = await targetRepository.findByIdForOwner(scan.targetId, ownerId);
  if (!target) {
    // The target row itself is Restrict-protected and cannot be deleted
    // while it has scan history, so this is not expected in practice — but
    // never fabricate target metadata for the AI if it somehow happened.
    throw scanNotFoundError();
  }

  let analysis: SecurityAnalysisRecord;
  try {
    analysis = await analysisRepository.create({ scanId, promptVersion: SECURITY_ANALYSIS_PROMPT_VERSION });
  } catch (err) {
    if (isUniqueConstraintError(err)) {
      throw analysisAlreadyExistsError();
    }
    throw err;
  }

  void analysisExecutor
    .execute({
      analysisId: analysis.id,
      scanId,
      targetName: target.name,
      targetOrigin: new URL(target.url).origin,
    })
    .catch((err: unknown) => {
      console.error(
        `[AnalysisService] Unhandled error dispatching analysis execution for analysis ${analysis.id}:`,
        err instanceof Error ? err.message : "Unknown error",
      );
    });

  return analysis;
}

/** Ownership proven via the join in `findByIdForOwner` — a foreign or nonexistent analysis id is indistinguishable 404. */
export async function getAnalysis(
  analysisRepository: AnalysisRepository,
  ownerId: string,
  id: string,
): Promise<SecurityAnalysisWithResults> {
  const analysis = await analysisRepository.findByIdForOwner(id, ownerId);
  if (!analysis) {
    throw analysisNotFoundError();
  }
  return analysis;
}

/**
 * The current analysis for one scan the caller owns. Scan ownership is
 * checked first (so a foreign/nonexistent scan reports `SCAN_NOT_FOUND`,
 * consistent with `GET /scans/:scanId/findings`); a scan that exists and is
 * owned by the caller but has no analysis yet reports `ANALYSIS_NOT_FOUND` —
 * "no analysis yet" is a legitimate, common state, but this is a singular
 * sub-resource (unlike the findings list), so 404 is the correct way to
 * report its absence rather than an empty array.
 */
export async function getAnalysisForScan(
  scanRepository: ScanRepository,
  analysisRepository: AnalysisRepository,
  ownerId: string,
  scanId: string,
): Promise<SecurityAnalysisWithResults> {
  const scan = await scanRepository.findByIdForOwner(scanId, ownerId);
  if (!scan) {
    throw scanNotFoundError();
  }

  const analysis = await analysisRepository.findByScanIdForOwner(scanId, ownerId);
  if (!analysis) {
    throw analysisNotFoundError();
  }
  return analysis;
}

// ---------------------------------------------------------------------------
// Internal lifecycle functions.
//
// Nothing here is reachable through any route. They exist for
// `SecurityAnalysisExecutor` to call as execution actually progresses, and
// take an analysis `id` alone, not an `ownerId` — a worker advancing a
// dequeued analysis is not acting "as" any particular user's session, the
// same reasoning `scan.service.ts`'s internal functions document.
// ---------------------------------------------------------------------------

export async function startAnalysis(repository: AnalysisRepository, id: string): Promise<SecurityAnalysisRecord> {
  const current = await repository.findById(id);
  if (!current) {
    throw analysisNotFoundError();
  }
  if (!isValidAnalysisTransition(current.status, "running")) {
    throw invalidAnalysisTransitionError(current.status, "running");
  }
  const updated = await repository.transitionStatus(id, current.status, { status: "running" });
  if (!updated) {
    throw invalidAnalysisTransitionError(current.status, "running");
  }
  return updated;
}

export async function failAnalysis(
  repository: AnalysisRepository,
  id: string,
  errorMessage?: string,
): Promise<SecurityAnalysisRecord> {
  const current = await repository.findById(id);
  if (!current) {
    throw analysisNotFoundError();
  }
  if (!isValidAnalysisTransition(current.status, "failed")) {
    throw invalidAnalysisTransitionError(current.status, "failed");
  }
  const updated = await repository.transitionStatus(id, current.status, {
    status: "failed",
    completedAt: new Date(),
    errorMessage: errorMessage ?? null,
  });
  if (!updated) {
    throw invalidAnalysisTransitionError(current.status, "failed");
  }
  return updated;
}

/**
 * The `running → completed` transition, including every child row —
 * `AnalysisRepository.completeAnalysis` performs the CAS-guarded update and
 * the `FindingAssessment`/`FindingCorrelation` inserts inside one short
 * transaction. A `null` result means the CAS guard didn't match (the
 * analysis was no longer `running` when this ran); the executor's caller
 * treats that as an invalid-transition failure the same way `transition()`
 * does in `scan.service.ts`.
 */
export async function completeAnalysis(
  repository: AnalysisRepository,
  id: string,
  data: CompleteAnalysisInput,
): Promise<SecurityAnalysisRecord> {
  const updated = await repository.completeAnalysis(id, data);
  if (!updated) {
    throw invalidAnalysisTransitionError("running", "completed");
  }
  return updated;
}
