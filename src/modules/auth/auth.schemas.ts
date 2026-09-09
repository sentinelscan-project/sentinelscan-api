import { z } from "zod";

/**
 * Password policy for locally authenticated accounts.
 *
 * Length does most of the work; the character-class rules exist to reject the
 * obviously weak end of the distribution without pushing users towards
 * predictable substitutions. The upper bound guards against bcrypt's 72-byte
 * truncation being reached with a long low-entropy passphrase and against
 * unbounded hashing work.
 */
export const passwordSchema = z
  .string()
  .min(10, "Password must be at least 10 characters long")
  .max(128, "Password must be at most 128 characters long")
  .regex(/[a-z]/, "Password must contain at least one lowercase letter")
  .regex(/[A-Z]/, "Password must contain at least one uppercase letter")
  .regex(/[0-9]/, "Password must contain at least one digit");

export const emailSchema = z
  .string()
  .trim()
  .min(1, "Email is required")
  .max(254, "Email must be at most 254 characters long")
  .email("Email must be a valid email address");

export const registerBodySchema = z.object({
  email: emailSchema,
  name: z.string().trim().min(1, "Name is required").max(100, "Name must be at most 100 characters long"),
  password: passwordSchema,
});

export const loginBodySchema = z.object({
  email: emailSchema,
  // Deliberately no policy check here: a wrong password must fail as invalid
  // credentials, not as a validation error that hints at the policy.
  password: z.string().min(1, "Password is required"),
});

export const verifyEmailBodySchema = z.object({
  token: z.string().trim().min(1, "Verification token is required"),
});

export const resendVerificationBodySchema = z.object({
  email: emailSchema,
});

export type RegisterBody = z.infer<typeof registerBodySchema>;
export type LoginBody = z.infer<typeof loginBodySchema>;
export type VerifyEmailBody = z.infer<typeof verifyEmailBodySchema>;
export type ResendVerificationBody = z.infer<typeof resendVerificationBodySchema>;
