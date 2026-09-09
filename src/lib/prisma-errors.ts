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

/**
 * Detects Prisma's foreign-key-constraint violation (P2003) — e.g. deleting a
 * `Target` that a `Scan` still references via `Restrict` — without importing
 * Prisma types into the service layer.
 */
export function isForeignKeyConstraintError(error: unknown): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    (error as { code: unknown }).code === "P2003"
  );
}
