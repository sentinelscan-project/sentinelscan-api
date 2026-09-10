import { z } from "zod";
import { FINDING_CATEGORIES } from "./finding-category.js";

export const findingSeveritySchema = z.enum(["critical", "high", "medium", "low", "informational"], {
  errorMap: () => ({
    message: "Severity must be one of: critical, high, medium, low, informational",
  }),
});

export const findingConfidenceSchema = z.enum(["high", "medium", "low", "unknown"], {
  errorMap: () => ({
    message: "Confidence must be one of: high, medium, low, unknown",
  }),
});

export const findingCategorySchema = z.enum(FINDING_CATEGORIES, {
  errorMap: () => ({
    message: `Category must be one of: ${FINDING_CATEGORIES.join(", ")}`,
  }),
});

/** Params for `GET /findings/:id` — mirrors `scan.schemas.ts`'s `scanIdParamsSchema`. */
export const findingIdParamsSchema = z.object({
  id: z.string().uuid("Finding id must be a valid UUID"),
});

export const DEFAULT_FINDING_LIST_LIMIT = 20;
export const MAX_FINDING_LIST_LIMIT = 100;
export const DEFAULT_FINDING_LIST_OFFSET = 0;

/** Query for `GET /scans/:scanId/findings` — same limit/offset convention as `scan.schemas.ts`. */
export const listFindingsQuerySchema = z.object({
  severity: findingSeveritySchema.optional(),
  confidence: findingConfidenceSchema.optional(),
  category: findingCategorySchema.optional(),
  /** Free text, not an enum — a new scanner source must not require a schema change. */
  source: z.string().min(1).optional(),
  limit: z.coerce.number().int().min(1).max(MAX_FINDING_LIST_LIMIT).default(DEFAULT_FINDING_LIST_LIMIT),
  offset: z.coerce.number().int().min(0).default(DEFAULT_FINDING_LIST_OFFSET),
});

export type ListFindingsQuery = z.infer<typeof listFindingsQuerySchema>;
export type FindingIdParams = z.infer<typeof findingIdParamsSchema>;
