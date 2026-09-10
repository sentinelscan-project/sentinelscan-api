/**
 * SentinelScan's security category set — a closed list, validated at the
 * application layer rather than the database's (see the comment above
 * `FindingSeverity` in `schema.prisma` for why `Finding.category` is a plain
 * `String` column instead of a Prisma `enum`: this set's hyphenated wire
 * format isn't representable as a Prisma enum value).
 *
 * Deliberately not exhaustive. Every category here is a SentinelScan-level
 * concept, independent of any one scanner's own taxonomy — see
 * `modules/findings/zap/zap-category-mapping.ts` for how ZAP's specific
 * alert/plugin identifiers land here. Anything that doesn't map cleanly is
 * `"other"`, with the scanner's own rule identifier preserved on `Finding`
 * (`sourceRuleId`) so it is never simply lost.
 */
export const FINDING_CATEGORIES = [
  "injection",
  "authentication",
  "authorization",
  "cryptography",
  "security-misconfiguration",
  "sensitive-data-exposure",
  "security-header",
  "client-side",
  "server-side",
  "information-disclosure",
  "other",
] as const;

export type FindingCategory = (typeof FINDING_CATEGORIES)[number];

export function isFindingCategory(value: string): value is FindingCategory {
  return (FINDING_CATEGORIES as readonly string[]).includes(value);
}
