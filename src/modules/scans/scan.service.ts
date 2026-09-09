import { ConflictError, NotFoundError } from "../../lib/errors.js";
import type { TargetRepository } from "../../repositories/target.repository.js";
import type {
  ListScansFilters,
  ListScansResult,
  ScanRecord,
  ScanRepository,
  ScanStatus,
} from "../../repositories/scan.repository.js";
import type { ListScansQuery } from "./scan.schemas.js";

/**
 * The complete set of legal lifecycle transitions.
 *
 * `completed`, `failed` and `cancelled` are terminal: every one of them maps
 * to an empty array, so nothing can ever leave them. This table is the single
 * source of truth `isValidTransition` and every route/service function below
 * defers to — there is deliberately no second, separately-maintained list of
 * "allowed" transitions anywhere else in this module.
 */
const VALID_TRANSITIONS: Record<ScanStatus, readonly ScanStatus[]> = {
  queued: ["running", "cancelled"],
  running: ["completed", "failed", "cancelled"],
  completed: [],
  failed: [],
  cancelled: [],
};

export function isValidTransition(from: ScanStatus, to: ScanStatus): boolean {
  return VALID_TRANSITIONS[from].includes(to);
}

/**
 * Identical whether `id` does not exist at all or belongs to a different
 * user — the same non-enumerable-404 rule Stage 2 established for targets.
 */
function scanNotFoundError(): NotFoundError {
  return new NotFoundError("Scan not found", "SCAN_NOT_FOUND");
}

function targetNotFoundError(): NotFoundError {
  return new NotFoundError("Target not found", "TARGET_NOT_FOUND");
}

function targetNotActiveError(): ConflictError {
  return new ConflictError("Target must be active to start a scan", "TARGET_NOT_ACTIVE");
}

function invalidTransitionError(from: ScanStatus, to: ScanStatus): ConflictError {
  return new ConflictError(
    `Scan cannot move from '${from}' to '${to}'`,
    "INVALID_SCAN_TRANSITION",
  );
}

/**
 * Creates a queued scan against a target the caller owns.
 *
 * Ownership and the active-status check both happen before any write: the
 * target lookup is itself owner-scoped (Stage 2's `findByIdForOwner`), so a
 * target belonging to someone else is indistinguishable from one that does
 * not exist. `requestedById` is always `ownerId` — the authenticated caller
 * — never anything the request body could influence.
 */
export async function createScan(
  targetRepository: TargetRepository,
  scanRepository: ScanRepository,
  ownerId: string,
  targetId: string,
): Promise<ScanRecord> {
  const target = await targetRepository.findByIdForOwner(targetId, ownerId);
  if (!target) {
    throw targetNotFoundError();
  }
  if (target.status !== "active") {
    throw targetNotActiveError();
  }

  return scanRepository.create({ targetId, requestedById: ownerId });
}

function toRepositoryFilters(query: ListScansQuery): ListScansFilters {
  return {
    status: query.status,
    targetId: query.targetId,
    limit: query.limit,
    offset: query.offset,
  };
}

export function listScans(
  repository: ScanRepository,
  ownerId: string,
  query: ListScansQuery,
): Promise<ListScansResult> {
  return repository.listForOwner(ownerId, toRepositoryFilters(query));
}

export async function getScan(repository: ScanRepository, ownerId: string, id: string): Promise<ScanRecord> {
  const scan = await repository.findByIdForOwner(id, ownerId);
  if (!scan) {
    throw scanNotFoundError();
  }
  return scan;
}

/**
 * Shared by every transition below: read-then-compare-and-swap.
 *
 * The read exists only to produce an honest error (`SCAN_NOT_FOUND` vs.
 * `INVALID_SCAN_TRANSITION`) — it is not what makes this safe under
 * concurrency. The actual write is `repository.transitionStatus`, an atomic
 * `UPDATE ... WHERE status = <the status we just observed>`, so if two
 * requests both read `running` and race to cancel, only one `UPDATE` can
 * possibly match; the other gets back `null` and is reported as an invalid
 * transition rather than silently double-applying.
 */
async function transition(
  repository: ScanRepository,
  id: string,
  toStatus: ScanStatus,
  extra: { startedAt?: Date; completedAt?: Date; errorMessage?: string | null },
  scope: { ownerId?: string } = {},
): Promise<ScanRecord> {
  const current = scope.ownerId
    ? await repository.findByIdForOwner(id, scope.ownerId)
    : await repository.findById(id);

  if (!current) {
    throw scanNotFoundError();
  }

  if (!isValidTransition(current.status, toStatus)) {
    throw invalidTransitionError(current.status, toStatus);
  }

  const updated = await repository.transitionStatus(
    id,
    current.status,
    { status: toStatus, ...extra },
    scope.ownerId,
  );
  if (!updated) {
    // The status moved between our read and our write (a concurrent
    // transition won the race) — from the caller's point of view that is
    // still "you asked for a transition that is no longer valid".
    throw invalidTransitionError(current.status, toStatus);
  }
  return updated;
}

/**
 * User-facing cancellation. Valid from `queued` or `running` only — enforced
 * by `VALID_TRANSITIONS`, not a separate check here. `startedAt` is left
 * untouched: if the scan had already started, that timestamp is part of the
 * historical record and cancelling must not overwrite it; if it never
 * started, it stays `null`. No scanner result fields are set — there is
 * nothing to fabricate.
 */
export function cancelScan(repository: ScanRepository, ownerId: string, id: string): Promise<ScanRecord> {
  return transition(repository, id, "cancelled", { completedAt: new Date() }, { ownerId });
}

// ---------------------------------------------------------------------------
// Internal lifecycle functions.
//
// Nothing in Stage 3 calls these — no route, no background process. They
// exist for Stage 4's `ScanExecutor` implementation to call as a real scan
// actually progresses, and are exercised directly by tests in the meantime to
// prove the state machine itself is correct. They take a scan `id` alone,
// not an `ownerId`: a worker advancing a dequeued scan is not acting "as" any
// particular user's authenticated session.
// ---------------------------------------------------------------------------

export function startScan(repository: ScanRepository, id: string): Promise<ScanRecord> {
  return transition(repository, id, "running", { startedAt: new Date() });
}

export function completeScan(repository: ScanRepository, id: string): Promise<ScanRecord> {
  return transition(repository, id, "completed", { completedAt: new Date() });
}

export function failScan(
  repository: ScanRepository,
  id: string,
  errorMessage?: string,
): Promise<ScanRecord> {
  return transition(repository, id, "failed", {
    completedAt: new Date(),
    errorMessage: errorMessage ?? null,
  });
}
