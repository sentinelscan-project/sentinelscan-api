import { randomUUID } from "node:crypto";
import type {
  CreateUserInput,
  UserRecord,
  UserRepository,
} from "../../src/repositories/user.repository.js";

/** Mimics Prisma's unique-constraint violation so services can be tested against it. */
class UniqueConstraintError extends Error {
  readonly code = "P2002";

  constructor(target: string) {
    super(`Unique constraint failed on the fields: (\`${target}\`)`);
    this.name = "PrismaClientKnownRequestError";
  }
}

export interface InMemoryUserRepository extends UserRepository {
  /** Direct access to stored rows, for assertions about persisted state. */
  readonly rows: Map<string, UserRecord>;
  reset(): void;
}

/**
 * In-memory {@link UserRepository} used by the test suite so the API can be
 * exercised end to end without a PostgreSQL instance in CI.
 */
export function createInMemoryUserRepository(): InMemoryUserRepository {
  const rows = new Map<string, UserRecord>();

  function clone(user: UserRecord): UserRecord {
    return { ...user };
  }

  function requireUser(id: string): UserRecord {
    const user = rows.get(id);
    if (!user) {
      throw new Error(`User ${id} not found`);
    }
    return user;
  }

  return {
    rows,

    reset(): void {
      rows.clear();
    },

    async findById(id: string): Promise<UserRecord | null> {
      const user = rows.get(id);
      return user ? clone(user) : null;
    },

    async findByEmail(email: string): Promise<UserRecord | null> {
      for (const user of rows.values()) {
        if (user.email === email) {
          return clone(user);
        }
      }
      return null;
    },

    async findByGoogleId(googleId: string): Promise<UserRecord | null> {
      for (const user of rows.values()) {
        if (user.googleId === googleId) {
          return clone(user);
        }
      }
      return null;
    },

    async create(input: CreateUserInput): Promise<UserRecord> {
      for (const user of rows.values()) {
        if (user.email === input.email) {
          throw new UniqueConstraintError("email");
        }
        if (input.googleId && user.googleId === input.googleId) {
          throw new UniqueConstraintError("googleId");
        }
      }

      const now = new Date();
      const user: UserRecord = {
        id: randomUUID(),
        email: input.email,
        name: input.name,
        passwordHash: input.passwordHash ?? null,
        googleId: input.googleId ?? null,
        emailVerified: input.emailVerified ?? false,
        lastLoginAt: null,
        createdAt: now,
        updatedAt: now,
      };
      rows.set(user.id, user);
      return clone(user);
    },

    async linkGoogleAccount(id: string, googleId: string, emailVerified: boolean): Promise<UserRecord> {
      const user = requireUser(id);
      user.googleId = googleId;
      user.emailVerified = emailVerified;
      user.updatedAt = new Date();
      return clone(user);
    },

    async recordLogin(id: string, at: Date): Promise<UserRecord> {
      const user = requireUser(id);
      user.lastLoginAt = at;
      user.updatedAt = new Date();
      return clone(user);
    },
  };
}
