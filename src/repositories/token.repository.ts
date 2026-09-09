import { getPrismaClient } from "../db/prisma.js";

export interface VerificationTokenRecord {
  id: string;
  userId: string;
  tokenHash: string;
  expiresAt: Date;
  usedAt: Date | null;
  createdAt: Date;
}

export interface VerificationTokenRepository {
  create(userId: string, tokenHash: string, expiresAt: Date): Promise<VerificationTokenRecord>;
  findByTokenHash(tokenHash: string): Promise<VerificationTokenRecord | null>;
  markUsed(id: string, usedAt: Date): Promise<VerificationTokenRecord>;
  invalidateAllForUser(userId: string): Promise<void>;
  findLatestForUser(userId: string): Promise<VerificationTokenRecord | null>;
}

export const prismaVerificationTokenRepository: VerificationTokenRepository = {
  create(userId: string, tokenHash: string, expiresAt: Date): Promise<VerificationTokenRecord> {
    return getPrismaClient().emailVerificationToken.create({
      data: {
        userId,
        tokenHash,
        expiresAt,
      },
    });
  },

  findByTokenHash(tokenHash: string): Promise<VerificationTokenRecord | null> {
    return getPrismaClient().emailVerificationToken.findUnique({
      where: { tokenHash },
    });
  },

  markUsed(id: string, usedAt: Date): Promise<VerificationTokenRecord> {
    return getPrismaClient().emailVerificationToken.update({
      where: { id },
      data: { usedAt },
    });
  },

  async invalidateAllForUser(userId: string): Promise<void> {
    await getPrismaClient().emailVerificationToken.updateMany({
      where: {
        userId,
        usedAt: null,
      },
      data: {
        usedAt: new Date(),
      },
    });
  },

  findLatestForUser(userId: string): Promise<VerificationTokenRecord | null> {
    return getPrismaClient().emailVerificationToken.findFirst({
      where: { userId },
      orderBy: { createdAt: "desc" },
    });
  },
};
