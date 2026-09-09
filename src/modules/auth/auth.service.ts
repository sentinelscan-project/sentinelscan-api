import { normalizeEmail } from "../../lib/email.js";
import { ConflictError, UnauthorizedError } from "../../lib/errors.js";
import { fakeVerifyPassword, hashPassword, verifyPassword } from "../../lib/password.js";
import { isUniqueConstraintError } from "../../lib/prisma-errors.js";
import type { UserRecord, UserRepository } from "../../repositories/user.repository.js";
import type { LoginBody, RegisterBody } from "./auth.schemas.js";

/** Identity claims taken from a verified Google ID token. */
export interface GoogleIdentity {
  googleId: string;
  email: string;
  name: string;
  emailVerified: boolean;
}

/**
 * Same message for every failed login, so the response never reveals whether
 * an email is registered.
 */
function invalidCredentials(): UnauthorizedError {
  return new UnauthorizedError("Invalid email or password", "INVALID_CREDENTIALS");
}

export async function registerUser(repository: UserRepository, body: RegisterBody): Promise<UserRecord> {
  const email = normalizeEmail(body.email);

  const existing = await repository.findByEmail(email);
  if (existing) {
    throw new ConflictError("An account with this email already exists", "EMAIL_ALREADY_REGISTERED");
  }

  const passwordHash = await hashPassword(body.password);

  try {
    return await repository.create({
      email,
      name: body.name,
      passwordHash,
      emailVerified: false,
    });
  } catch (error) {
    // Two concurrent registrations can both pass the check above; the unique
    // index is the real arbiter.
    if (isUniqueConstraintError(error)) {
      throw new ConflictError("An account with this email already exists", "EMAIL_ALREADY_REGISTERED");
    }
    throw error;
  }
}

export async function loginUser(repository: UserRepository, body: LoginBody): Promise<UserRecord> {
  const email = normalizeEmail(body.email);
  const user = await repository.findByEmail(email);

  // Unknown email and Google-only account both still pay the cost of a bcrypt
  // comparison, keeping login timing independent of account existence.
  if (!user || !user.passwordHash) {
    await fakeVerifyPassword(body.password);
    throw invalidCredentials();
  }

  const passwordMatches = await verifyPassword(body.password, user.passwordHash);
  if (!passwordMatches) {
    throw invalidCredentials();
  }

  return repository.recordLogin(user.id, new Date());
}

/**
 * Signs in — or provisions — the user behind a verified Google identity.
 *
 * An existing account with the same email is linked to the Google identity
 * rather than duplicated, so a user who registered locally and later signs in
 * with Google keeps one account.
 */
export async function authenticateWithGoogle(
  repository: UserRepository,
  identity: GoogleIdentity,
): Promise<UserRecord> {
  const email = normalizeEmail(identity.email);

  const byGoogleId = await repository.findByGoogleId(identity.googleId);
  if (byGoogleId) {
    return repository.recordLogin(byGoogleId.id, new Date());
  }

  const byEmail = await repository.findByEmail(email);
  if (byEmail) {
    const linked = await repository.linkGoogleAccount(
      byEmail.id,
      identity.googleId,
      byEmail.emailVerified || identity.emailVerified,
    );
    return repository.recordLogin(linked.id, new Date());
  }

  const created = await repository.create({
    email,
    name: identity.name,
    passwordHash: null,
    googleId: identity.googleId,
    emailVerified: identity.emailVerified,
  });
  return repository.recordLogin(created.id, new Date());
}
