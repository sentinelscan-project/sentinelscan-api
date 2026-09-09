/**
 * Persistence boundary for the `Scan` model.
 *
 * Every read scoped to a user (`findByIdForOwner`, `listForOwner`) filters by
 * `requestedById` as part of the query itself, mirroring the `TargetRepository`
 * pattern from Stage 2: ownership is enforced at the data-access layer, not by
 * fetching first and checking afterwards. `findByIdForOwner` returns `null`
 * for a scan that exists but belongs to someone else — identical to a scan
 * that does not exist at all — so a non-owner can never distinguish the two.
 *
 * `findById` (no owner) and `transitionStatus` (owner optional) exist for the
 * *internal* lifecycle — the future Stage 4 executor advances a scan by its
 * id alone, the way a background worker would, not as a particular user's
 * request. The user-facing cancel endpoint uses the same `transitionStatus`
 * but always passes `ownerId`.
 */

export type ScanStatus = "queued" | "running" | "completed" | "failed" | "cancelled";

/** A full scan row. */
export interface ScanRecord {
  id: string;
  targetId: string;
  requestedById: string;
  status: ScanStatus;
  startedAt: Date | null;
  completedAt: Date | null;
  errorMessage: string | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface CreateScanInput {
  targetId: string;
  requestedById: string;
}

export interface ListScansFilters {
  status?: ScanStatus;
  targetId?: string;
  /** Defaults and maximum are enforced by the Zod query schema, not here. */
  limit: number;
  offset: number;
}

export interface ListScansResult {
  scans: ScanRecord[];
  /** True when more rows exist beyond this page (`scans.length === limit` was hit). */
  hasMore: boolean;
}

/** Fields a status transition may set alongside the new `status` itself. */
export interface TransitionScanInput {
  status: ScanStatus;
  startedAt?: Date;
  completedAt?: Date;
  errorMessage?: string | null;
}

export interface ScanRepository {
  create(input: CreateScanInput): Promise<ScanRecord>;
  listForOwner(ownerId: string, filters: ListScansFilters): Promise<ListScansResult>;
  findByIdForOwner(id: string, ownerId: string): Promise<ScanRecord | null>;
  /** Internal lookup with no ownership scoping — for the future executor, not any route. */
  findById(id: string): Promise<ScanRecord | null>;
  /**
   * Atomic compare-and-swap: applies `input` only if the row's current
   * `status` is exactly `fromStatus` (and, when given, `ownerId` matches).
   * Returns `null` when nothing matched, which the caller cannot tell apart
   * from "the status had already changed" without a preceding read — that
   * ambiguity is exactly what makes two concurrent transitions safe: at most
   * one of them ever sees a non-null result.
   */
  transitionStatus(
    id: string,
    fromStatus: ScanStatus,
    input: TransitionScanInput,
    ownerId?: string,
  ): Promise<ScanRecord | null>;
}

/**
 * The only scan shape that may cross the API boundary.
 *
 * `requestedById` is deliberately absent, the same way `Target.ownerId` is
 * absent from `PublicTarget`: every scan returned here is already known to be
 * the caller's own.
 */
export interface PublicScan {
  id: string;
  targetId: string;
  status: ScanStatus;
  startedAt: string | null;
  completedAt: string | null;
  errorMessage: string | null;
  createdAt: string;
  updatedAt: string;
}

export function toPublicScan(scan: ScanRecord): PublicScan {
  return {
    id: scan.id,
    targetId: scan.targetId,
    status: scan.status,
    startedAt: scan.startedAt ? scan.startedAt.toISOString() : null,
    completedAt: scan.completedAt ? scan.completedAt.toISOString() : null,
    errorMessage: scan.errorMessage,
    createdAt: scan.createdAt.toISOString(),
    updatedAt: scan.updatedAt.toISOString(),
  };
}
