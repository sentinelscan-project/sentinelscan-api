import { randomUUID } from "node:crypto";
import type {
  CreateTargetInput,
  TargetRecord,
  TargetRepository,
  UpdateTargetInput,
} from "../../src/repositories/target.repository.js";

/** Mimics Prisma's unique-constraint violation so services can be tested against it. */
class UniqueConstraintError extends Error {
  readonly code = "P2002";

  constructor(target: string) {
    super(`Unique constraint failed on the fields: (\`${target}\`)`);
    this.name = "PrismaClientKnownRequestError";
  }
}

export interface InMemoryTargetRepository extends TargetRepository {
  /** Direct access to stored rows, for assertions about persisted state. */
  readonly rows: Map<string, TargetRecord>;
  reset(): void;
}

/**
 * In-memory {@link TargetRepository}. Ownership scoping is reproduced exactly
 * as the Prisma implementation does it (filtering by `ownerId` as part of the
 * lookup, not as a check applied afterwards), so the same tests exercise both
 * without depending on a database.
 */
export function createInMemoryTargetRepository(): InMemoryTargetRepository {
  const rows = new Map<string, TargetRecord>();

  function clone(target: TargetRecord): TargetRecord {
    return { ...target };
  }

  function findDuplicate(ownerId: string, url: string, excludeId?: string): TargetRecord | undefined {
    for (const target of rows.values()) {
      if (target.ownerId === ownerId && target.url === url && target.id !== excludeId) {
        return target;
      }
    }
    return undefined;
  }

  return {
    rows,

    reset(): void {
      rows.clear();
    },

    async create(input: CreateTargetInput): Promise<TargetRecord> {
      if (findDuplicate(input.ownerId, input.url)) {
        throw new UniqueConstraintError("ownerId,url");
      }

      const now = new Date();
      const target: TargetRecord = {
        id: randomUUID(),
        ownerId: input.ownerId,
        name: input.name,
        url: input.url,
        description: input.description ?? null,
        status: "active",
        createdAt: now,
        updatedAt: now,
      };
      rows.set(target.id, target);
      return clone(target);
    },

    async listByOwner(ownerId: string): Promise<TargetRecord[]> {
      return [...rows.values()]
        .filter((target) => target.ownerId === ownerId)
        .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime())
        .map(clone);
    },

    async findByIdForOwner(id: string, ownerId: string): Promise<TargetRecord | null> {
      const target = rows.get(id);
      if (!target || target.ownerId !== ownerId) {
        return null;
      }
      return clone(target);
    },

    async updateForOwner(id: string, ownerId: string, input: UpdateTargetInput): Promise<TargetRecord | null> {
      const target = rows.get(id);
      if (!target || target.ownerId !== ownerId) {
        return null;
      }

      if (input.url !== undefined && findDuplicate(ownerId, input.url, id)) {
        throw new UniqueConstraintError("ownerId,url");
      }

      if (input.name !== undefined) target.name = input.name;
      if (input.url !== undefined) target.url = input.url;
      if (input.description !== undefined) target.description = input.description;
      if (input.status !== undefined) target.status = input.status;
      target.updatedAt = new Date();

      return clone(target);
    },

    async deleteForOwner(id: string, ownerId: string): Promise<boolean> {
      const target = rows.get(id);
      if (!target || target.ownerId !== ownerId) {
        return false;
      }
      rows.delete(id);
      return true;
    },
  };
}
