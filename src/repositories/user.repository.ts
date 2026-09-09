/**
 * Persistence boundary for the `User` model.
 *
 * Route handlers and services depend on this interface rather than on Prisma
 * directly. That keeps the auth module testable without a live database and
 * gives later stages (targets, scans, findings, analyses, reports) an
 * established pattern to follow for their own repositories.
 */

/** A full user row, including secret material. Never send this to a client. */
export interface UserRecord {
  id: string;
  email: string;
  name: string;
  passwordHash: string | null;
  googleId: string | null;
  emailVerified: boolean;
  lastLoginAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface CreateUserInput {
  email: string;
  name: string;
  passwordHash?: string | null;
  googleId?: string | null;
  emailVerified?: boolean;
}

export interface UserRepository {
  findById(id: string): Promise<UserRecord | null>;
  findByEmail(email: string): Promise<UserRecord | null>;
  findByGoogleId(googleId: string): Promise<UserRecord | null>;
  create(input: CreateUserInput): Promise<UserRecord>;
  /** Attaches a Google identity to an existing local account. */
  linkGoogleAccount(id: string, googleId: string, emailVerified: boolean): Promise<UserRecord>;
  recordLogin(id: string, at: Date): Promise<UserRecord>;
}

/**
 * The only user shape that may cross the API boundary. Password hashes,
 * tokens and other authentication secrets are deliberately absent; callers
 * learn *whether* a credential exists, never what it is.
 */
export interface PublicUser {
  id: string;
  email: string;
  name: string;
  emailVerified: boolean;
  hasPassword: boolean;
  googleLinked: boolean;
  createdAt: string;
  updatedAt: string;
}

export function toPublicUser(user: UserRecord): PublicUser {
  return {
    id: user.id,
    email: user.email,
    name: user.name,
    emailVerified: user.emailVerified,
    hasPassword: user.passwordHash !== null,
    googleLinked: user.googleId !== null,
    createdAt: user.createdAt.toISOString(),
    updatedAt: user.updatedAt.toISOString(),
  };
}
