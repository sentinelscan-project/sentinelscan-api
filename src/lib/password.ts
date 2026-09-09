import bcrypt from "bcryptjs";

/**
 * bcrypt work factor. 12 is a reasonable 2020s default: strong enough for
 * credential storage while keeping login latency acceptable.
 */
const BCRYPT_ROUNDS = 12;

/**
 * A pre-computed hash of a value nobody can log in with. Used to spend the same
 * amount of time verifying a password for a non-existent user as for a real
 * one, so response timing does not reveal whether an email is registered.
 */
const DUMMY_HASH = bcrypt.hashSync("sentinelscan-invalid-credential-placeholder", BCRYPT_ROUNDS);

export function hashPassword(plainPassword: string): Promise<string> {
  return bcrypt.hash(plainPassword, BCRYPT_ROUNDS);
}

export function verifyPassword(plainPassword: string, passwordHash: string): Promise<boolean> {
  return bcrypt.compare(plainPassword, passwordHash);
}

/**
 * Burns roughly one password verification worth of time without revealing
 * anything. Call this on the "user not found" / "no local password" branches of
 * login to keep timing uniform.
 */
export async function fakeVerifyPassword(plainPassword: string): Promise<void> {
  await bcrypt.compare(plainPassword, DUMMY_HASH);
}
