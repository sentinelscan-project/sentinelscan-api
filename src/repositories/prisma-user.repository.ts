import { getPrismaClient } from "../db/prisma.js";
import type { CreateUserInput, UserRecord, UserRepository } from "./user.repository.js";

/**
 * Prisma-backed {@link UserRepository} used at runtime.
 *
 * The Prisma client is resolved per call through the lazy singleton so that
 * importing this module never opens a database connection.
 */
export const prismaUserRepository: UserRepository = {
  findById(id: string): Promise<UserRecord | null> {
    return getPrismaClient().user.findUnique({ where: { id } });
  },

  findByEmail(email: string): Promise<UserRecord | null> {
    return getPrismaClient().user.findUnique({ where: { email } });
  },

  findByGoogleId(googleId: string): Promise<UserRecord | null> {
    return getPrismaClient().user.findUnique({ where: { googleId } });
  },

  create(input: CreateUserInput): Promise<UserRecord> {
    return getPrismaClient().user.create({
      data: {
        email: input.email,
        name: input.name,
        passwordHash: input.passwordHash ?? null,
        googleId: input.googleId ?? null,
        emailVerified: input.emailVerified ?? false,
      },
    });
  },

  linkGoogleAccount(id: string, googleId: string, emailVerified: boolean): Promise<UserRecord> {
    return getPrismaClient().user.update({
      where: { id },
      data: { googleId, emailVerified },
    });
  },

  recordLogin(id: string, at: Date): Promise<UserRecord> {
    return getPrismaClient().user.update({
      where: { id },
      data: { lastLoginAt: at },
    });
  },
};
