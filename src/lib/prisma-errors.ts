/**
 * Detects Prisma's unique-constraint violation (P2002) without importing
 * Prisma types into the service layer.
 */
export function isUniqueConstraintError(error: unknown): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    (error as { code: unknown }).code === "P2002"
  );
}
