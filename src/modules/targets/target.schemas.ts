import { z } from "zod";
import { normalizeTargetUrl } from "../../lib/url.js";

export const targetNameSchema = z
  .string()
  .trim()
  .min(1, "Name is required")
  .max(120, "Name must be at most 120 characters long");

/**
 * Validates and normalizes a target URL in one pass: `.transform` runs after
 * the length check has already passed, and reports a validation issue rather
 * than throwing when the value isn't an absolute http(s) URL. See
 * `lib/url.ts` for exactly what "normalize" means here and why other schemes
 * are rejected outright.
 */
export const targetUrlSchema = z
  .string()
  .trim()
  .min(1, "URL is required")
  .max(2048, "URL must be at most 2048 characters long")
  .transform((value, ctx) => {
    const normalized = normalizeTargetUrl(value);
    if (!normalized) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "URL must be an absolute http:// or https:// address",
      });
      return z.NEVER;
    }
    return normalized;
  });

export const targetDescriptionSchema = z
  .string()
  .trim()
  .max(1000, "Description must be at most 1000 characters long");

export const targetStatusSchema = z.enum(["active", "inactive"], {
  errorMap: () => ({ message: "Status must be either 'active' or 'inactive'" }),
});

export const createTargetBodySchema = z.object({
  name: targetNameSchema,
  url: targetUrlSchema,
  description: targetDescriptionSchema.optional(),
});

/**
 * Every field optional (a PATCH may touch just one), but `description` also
 * accepts an explicit `null` to distinguish "clear the description" from
 * "leave it alone" (simply omitting the field).
 */
export const updateTargetBodySchema = z.object({
  name: targetNameSchema.optional(),
  url: targetUrlSchema.optional(),
  description: targetDescriptionSchema.nullable().optional(),
  status: targetStatusSchema.optional(),
});

export const targetIdParamsSchema = z.object({
  id: z.string().uuid("Target id must be a valid UUID"),
});

export type CreateTargetBody = z.infer<typeof createTargetBodySchema>;
export type UpdateTargetBody = z.infer<typeof updateTargetBodySchema>;
export type TargetIdParams = z.infer<typeof targetIdParamsSchema>;
