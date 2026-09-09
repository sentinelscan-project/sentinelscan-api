import { getPrismaClient } from "../db/prisma.js";
import type { CreateTargetInput, TargetRecord, TargetRepository, UpdateTargetInput } from "./target.repository.js";

/**
 * Prisma-backed {@link TargetRepository} used at runtime.
 *
 * `updateForOwner` and `deleteForOwner` use `updateMany`/`deleteMany` rather
 * than `update`/`delete`: Prisma's singular mutations only accept a unique
 * field (just `id` here) in `where`, but `updateMany`/`deleteMany` accept an
 * arbitrary filter, which is what lets `ownerId` be part of the WHERE clause
 * itself instead of a check bolted on afterwards. A `count` of `0` means the
 * row either doesn't exist or isn't owned by `ownerId` — the two are
 * indistinguishable by design (see the module-level comment on
 * {@link TargetRepository}).
 */
export const prismaTargetRepository: TargetRepository = {
  create(input: CreateTargetInput): Promise<TargetRecord> {
    return getPrismaClient().target.create({
      data: {
        ownerId: input.ownerId,
        name: input.name,
        url: input.url,
        description: input.description ?? null,
      },
    });
  },

  listByOwner(ownerId: string): Promise<TargetRecord[]> {
    return getPrismaClient().target.findMany({
      where: { ownerId },
      orderBy: { createdAt: "desc" },
    });
  },

  findByIdForOwner(id: string, ownerId: string): Promise<TargetRecord | null> {
    return getPrismaClient().target.findFirst({
      where: { id, ownerId },
    });
  },

  async updateForOwner(id: string, ownerId: string, input: UpdateTargetInput): Promise<TargetRecord | null> {
    const prisma = getPrismaClient();
    const { count } = await prisma.target.updateMany({
      where: { id, ownerId },
      data: input,
    });
    if (count === 0) {
      return null;
    }
    // The updateMany above already proved this id belongs to ownerId, so a
    // plain findUnique by id is safe here.
    return prisma.target.findUnique({ where: { id } });
  },

  async deleteForOwner(id: string, ownerId: string): Promise<boolean> {
    const { count } = await getPrismaClient().target.deleteMany({
      where: { id, ownerId },
    });
    return count > 0;
  },
};
