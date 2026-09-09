import { getPrismaClient } from "../db/prisma.js";
import type {
  CreateScanInput,
  ListScansFilters,
  ListScansResult,
  ScanRecord,
  ScanRepository,
  ScanStatus,
  TransitionScanInput,
} from "./scan.repository.js";

/**
 * Prisma-backed {@link ScanRepository} used at runtime.
 *
 * `transitionStatus` uses `updateMany` rather than `update`, the same reason
 * as `prisma-target.repository.ts`: Prisma's singular `update` only accepts a
 * unique field in `where`, but `updateMany` accepts an arbitrary filter,
 * which is what lets both `status` (the compare-and-swap guard) and
 * `ownerId` (when given) live in the WHERE clause itself. A `count` of `0`
 * means either nothing matched by id/owner, or the row's status had already
 * moved on — both cases return `null` and leave disambiguation to the
 * service layer, which reads first when it needs a specific error message.
 */
export const prismaScanRepository: ScanRepository = {
  create(input: CreateScanInput): Promise<ScanRecord> {
    return getPrismaClient().scan.create({
      data: {
        targetId: input.targetId,
        requestedById: input.requestedById,
      },
    });
  },

  async listForOwner(ownerId: string, filters: ListScansFilters): Promise<ListScansResult> {
    const where = {
      requestedById: ownerId,
      ...(filters.status ? { status: filters.status } : {}),
      ...(filters.targetId ? { targetId: filters.targetId } : {}),
    };

    const scans = await getPrismaClient().scan.findMany({
      where,
      orderBy: { createdAt: "desc" },
      take: filters.limit + 1,
      skip: filters.offset,
    });

    const hasMore = scans.length > filters.limit;
    return { scans: hasMore ? scans.slice(0, filters.limit) : scans, hasMore };
  },

  findByIdForOwner(id: string, ownerId: string): Promise<ScanRecord | null> {
    return getPrismaClient().scan.findFirst({
      where: { id, requestedById: ownerId },
    });
  },

  findById(id: string): Promise<ScanRecord | null> {
    return getPrismaClient().scan.findUnique({ where: { id } });
  },

  async transitionStatus(
    id: string,
    fromStatus: ScanStatus,
    input: TransitionScanInput,
    ownerId?: string,
  ): Promise<ScanRecord | null> {
    const prisma = getPrismaClient();
    const { count } = await prisma.scan.updateMany({
      where: {
        id,
        status: fromStatus,
        ...(ownerId ? { requestedById: ownerId } : {}),
      },
      data: input,
    });
    if (count === 0) {
      return null;
    }
    // The updateMany above already proved this id (and, when given, owner)
    // matched, so a plain findUnique by id is safe here.
    return prisma.scan.findUnique({ where: { id } });
  },
};
