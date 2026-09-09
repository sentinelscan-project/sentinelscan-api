import { randomUUID } from "node:crypto";
import type {
  CreateUserInput,
  UserRecord,
  UserRepository,
} from "../../src/repositories/user.repository.js";
import type {
  VerificationTokenRecord,
  VerificationTokenRepository,
} from "../../src/repositories/token.repository.js";
import type {
  EmailResult,
  EmailService,
  SendVerificationEmailOptions,
} from "../../src/lib/email-service.js";

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

    async setEmailVerified(id: string, emailVerified: boolean): Promise<UserRecord> {
      const user = requireUser(id);
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

export interface InMemoryVerificationTokenRepository extends VerificationTokenRepository {
  readonly rows: Map<string, VerificationTokenRecord>;
  reset(): void;
}

export function createInMemoryVerificationTokenRepository(): InMemoryVerificationTokenRepository {
  const rows = new Map<string, VerificationTokenRecord>();

  function clone(token: VerificationTokenRecord): VerificationTokenRecord {
    return { ...token };
  }

  return {
    rows,

    reset(): void {
      rows.clear();
    },

    async create(userId: string, tokenHash: string, expiresAt: Date): Promise<VerificationTokenRecord> {
      for (const token of rows.values()) {
        if (token.tokenHash === tokenHash) {
          throw new UniqueConstraintError("tokenHash");
        }
      }

      const record: VerificationTokenRecord = {
        id: randomUUID(),
        userId,
        tokenHash,
        expiresAt,
        usedAt: null,
        createdAt: new Date(),
      };
      rows.set(record.id, record);
      return clone(record);
    },

    async findByTokenHash(tokenHash: string): Promise<VerificationTokenRecord | null> {
      for (const token of rows.values()) {
        if (token.tokenHash === tokenHash) {
          return clone(token);
        }
      }
      return null;
    },

    async markUsed(id: string, usedAt: Date): Promise<VerificationTokenRecord> {
      const record = rows.get(id);
      if (!record) {
        throw new Error(`Token ${id} not found`);
      }
      record.usedAt = usedAt;
      return clone(record);
    },

    async invalidateAllForUser(userId: string): Promise<void> {
      const now = new Date();
      for (const token of rows.values()) {
        if (token.userId === userId && token.usedAt === null) {
          token.usedAt = now;
        }
      }
    },

    async findLatestForUser(userId: string): Promise<VerificationTokenRecord | null> {
      let latest: VerificationTokenRecord | null = null;
      for (const token of rows.values()) {
        if (token.userId === userId) {
          if (!latest || token.createdAt.getTime() > latest.createdAt.getTime()) {
            latest = token;
          }
        }
      }
      return latest ? clone(latest) : null;
    },
  };
}

export class MockEmailService implements EmailService {
  readonly provider = "mock";
  readonly sentEmails: SendVerificationEmailOptions[] = [];

  async sendVerificationEmail(options: SendVerificationEmailOptions): Promise<EmailResult> {
    this.sentEmails.push({ ...options });
    return {
      delivered: true,
      provider: "mock",
      previewUrl: options.verificationUrl,
    };
  }

  reset(): void {
    this.sentEmails.length = 0;
  }
}
