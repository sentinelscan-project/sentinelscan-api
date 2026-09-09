import { randomUUID } from "node:crypto";
import type {
  CreateScanInput,
  ListScansFilters,
  ListScansResult,
  ScanRecord,
  ScanRepository,
  ScanStatus,
  TransitionScanInput,
} from "../../src/repositories/scan.repository.js";

export interface InMemoryScanRepository extends ScanRepository {
  /** Direct access to stored rows, for assertions about persisted state. */
  readonly rows: Map<string, ScanRecord>;
  reset(): void;
}

/**
 * In-memory {@link ScanRepository}.
 *
 * `transitionStatus` reproduces the Prisma implementation's compare-and-swap
 * semantics: the status check and the write happen with no `await` between
 * them, so two "concurrent" calls (e.g. `Promise.all([repo.transitionStatus(...),
 * repo.transitionStatus(...)])`) can never both observe the same starting
 * status and both succeed — whichever runs its synchronous body first wins,
 * and the second sees the already-updated status and returns `null`, exactly
 * as a real `UPDATE ... WHERE status = $1` would under concurrent requests.
 */
export function createInMemoryScanRepository(): InMemoryScanRepository {
  const rows = new Map<string, ScanRecord>();

  function clone(scan: ScanRecord): ScanRecord {
    return { ...scan };
  }

  return {
    rows,

    reset(): void {
      rows.clear();
    },

    async create(input: CreateScanInput): Promise<ScanRecord> {
      const now = new Date();
      const scan: ScanRecord = {
        id: randomUUID(),
        targetId: input.targetId,
        requestedById: input.requestedById,
        status: "queued",
        startedAt: null,
        completedAt: null,
        errorMessage: null,
        createdAt: now,
        updatedAt: now,
      };
      rows.set(scan.id, scan);
      return clone(scan);
    },

    async listForOwner(ownerId: string, filters: ListScansFilters): Promise<ListScansResult> {
      const matches = [...rows.values()]
        .filter((scan) => scan.requestedById === ownerId)
        .filter((scan) => (filters.status ? scan.status === filters.status : true))
        .filter((scan) => (filters.targetId ? scan.targetId === filters.targetId : true))
        .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());

      const page = matches.slice(filters.offset, filters.offset + filters.limit);
      const hasMore = matches.length > filters.offset + filters.limit;
      return { scans: page.map(clone), hasMore };
    },

    async findByIdForOwner(id: string, ownerId: string): Promise<ScanRecord | null> {
      const scan = rows.get(id);
      if (!scan || scan.requestedById !== ownerId) {
        return null;
      }
      return clone(scan);
    },

    async findById(id: string): Promise<ScanRecord | null> {
      const scan = rows.get(id);
      return scan ? clone(scan) : null;
    },

    // Deliberately not `async` at the top: the read-check-write below must
    // execute synchronously, uninterrupted by any awaited I/O, to reproduce
    // a real atomic UPDATE ... WHERE. Returning a Promise (via
    // Promise.resolve) still satisfies the async ScanRepository interface.
    transitionStatus(
      id: string,
      fromStatus: ScanStatus,
      input: TransitionScanInput,
      ownerId?: string,
    ): Promise<ScanRecord | null> {
      const scan = rows.get(id);
      if (!scan || scan.status !== fromStatus || (ownerId !== undefined && scan.requestedById !== ownerId)) {
        return Promise.resolve(null);
      }

      scan.status = input.status;
      if (input.startedAt !== undefined) scan.startedAt = input.startedAt;
      if (input.completedAt !== undefined) scan.completedAt = input.completedAt;
      if (input.errorMessage !== undefined) scan.errorMessage = input.errorMessage;
      scan.updatedAt = new Date();

      return Promise.resolve(clone(scan));
    },
  };
}
