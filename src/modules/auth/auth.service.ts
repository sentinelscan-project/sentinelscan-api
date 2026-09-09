import { randomBytes, createHash } from "node:crypto";
import { normalizeEmail } from "../../lib/email.js";
import {
  BadRequestError,
  ConflictError,
  ForbiddenError,
  TooManyRequestsError,
  UnauthorizedError,
} from "../../lib/errors.js";
import { fakeVerifyPassword, hashPassword, verifyPassword } from "../../lib/password.js";
import { isUniqueConstraintError } from "../../lib/prisma-errors.js";
import type { UserRecord, UserRepository } from "../../repositories/user.repository.js";
import type { VerificationTokenRepository } from "../../repositories/token.repository.js";
import type { EmailService } from "../../lib/email-service.js";
import { env } from "../../config.js";
import type { LoginBody, RegisterBody } from "./auth.schemas.js";

/** Token lifetime for email verification: 24 hours. */
export const VERIFICATION_TOKEN_TTL_MS = 24 * 60 * 60 * 1000;

/** Cooldown period between resend requests for the same email: 60 seconds. */
export const RESEND_COOLDOWN_MS = 60 * 1000;

/** Identity claims taken from a verified Google ID token. */
export interface GoogleIdentity {
  googleId: string;
  email: string;
  name: string;
  emailVerified: boolean;
}

/** Generates a cryptographically secure random token and its SHA-256 hash. */
export function generateVerificationToken(): { token: string; tokenHash: string } {
  const token = randomBytes(32).toString("hex");
  const tokenHash = hashVerificationToken(token);
  return { token, tokenHash };
}

/** Computes the SHA-256 hash of a verification token for safe database lookup. */
export function hashVerificationToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

/**
 * Same message for every failed login, so the response never reveals whether
 * an email is registered.
 */
function invalidCredentials(): UnauthorizedError {
  return new UnauthorizedError("Invalid email or password", "INVALID_CREDENTIALS");
}

export async function registerUser(
  userRepository: UserRepository,
  tokenRepository: VerificationTokenRepository,
  emailService: EmailService,
  body: RegisterBody,
): Promise<UserRecord> {
  const email = normalizeEmail(body.email);

  const existing = await userRepository.findByEmail(email);
  if (existing) {
    throw new ConflictError("An account with this email already exists", "EMAIL_ALREADY_REGISTERED");
  }

  const passwordHash = await hashPassword(body.password);

  let user: UserRecord;
  try {
    user = await userRepository.create({
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

  // Generate and store verification token
  const { token, tokenHash } = generateVerificationToken();
  const expiresAt = new Date(Date.now() + VERIFICATION_TOKEN_TTL_MS);
  await tokenRepository.create(user.id, tokenHash, expiresAt);

  // Send verification email
  const verificationUrl = `${env.WEB_APP_URL}/verify-email?token=${token}`;
  try {
    await emailService.sendVerificationEmail({
      to: user.email,
      name: user.name,
      token,
      verificationUrl,
    });
  } catch (err) {
    // Log delivery issue without failing account creation
    console.error("[Auth] Failed to dispatch verification email during registration:", err);
  }

  return user;
}

export async function loginUser(userRepository: UserRepository, body: LoginBody): Promise<UserRecord> {
  const email = normalizeEmail(body.email);
  const user = await userRepository.findByEmail(email);

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

  // Enforce email verification policy for local password accounts
  if (!user.emailVerified) {
    throw new ForbiddenError("Please verify your email address before signing in.", "EMAIL_NOT_VERIFIED", {
      email: user.email,
    });
  }

  return userRepository.recordLogin(user.id, new Date());
}

export async function verifyEmail(
  userRepository: UserRepository,
  tokenRepository: VerificationTokenRepository,
  token: string,
): Promise<UserRecord> {
  const tokenHash = hashVerificationToken(token);
  const record = await tokenRepository.findByTokenHash(tokenHash);

  if (!record) {
    throw new BadRequestError("Invalid verification token", "INVALID_TOKEN");
  }

  if (record.usedAt !== null) {
    throw new BadRequestError("Verification token has already been used", "TOKEN_ALREADY_USED");
  }

  if (record.expiresAt < new Date()) {
    throw new BadRequestError("Verification token has expired", "TOKEN_EXPIRED");
  }

  // Mark token as used to ensure single-use
  await tokenRepository.markUsed(record.id, new Date());

  // Mark user as verified
  const user = await userRepository.setEmailVerified(record.userId, true);

  // Record login timestamp
  return userRepository.recordLogin(user.id, new Date());
}

export async function resendVerificationEmail(
  userRepository: UserRepository,
  tokenRepository: VerificationTokenRepository,
  emailService: EmailService,
  email: string,
): Promise<{ message: string }> {
  const normalizedEmail = normalizeEmail(email);
  const user = await userRepository.findByEmail(normalizedEmail);

  // Do not leak whether an arbitrary email exists or is verified.
  const genericResponse = {
    message: "If an unverified account with that email exists, a verification link has been sent.",
  };

  if (!user || user.emailVerified) {
    return genericResponse;
  }

  // Enforce rate limiting: only allow 1 resend per cooldown window
  const latestToken = await tokenRepository.findLatestForUser(user.id);
  if (latestToken && Date.now() - latestToken.createdAt.getTime() < RESEND_COOLDOWN_MS) {
    throw new TooManyRequestsError("Please wait before requesting another verification email.", "RATE_LIMITED");
  }

  // Invalidate previous active tokens for this user
  await tokenRepository.invalidateAllForUser(user.id);

  // Generate and store new token
  const { token, tokenHash } = generateVerificationToken();
  const expiresAt = new Date(Date.now() + VERIFICATION_TOKEN_TTL_MS);
  await tokenRepository.create(user.id, tokenHash, expiresAt);

  // Dispatch new verification email
  const verificationUrl = `${env.WEB_APP_URL}/verify-email?token=${token}`;
  try {
    await emailService.sendVerificationEmail({
      to: user.email,
      name: user.name,
      token,
      verificationUrl,
    });
  } catch (err) {
    console.error("[Auth] Failed to dispatch verification email during resend:", err);
  }

  return genericResponse;
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
