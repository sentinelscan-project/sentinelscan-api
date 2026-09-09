/**
 * Canonical email form used for storage and lookup, so that `User@Example.com `
 * and `user@example.com` resolve to the same account.
 */
export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}
