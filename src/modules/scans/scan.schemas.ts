import { z } from "zod";

export const scanStatusSchema = z.enum(["queued", "running", "completed", "failed", "cancelled"], {
  errorMap: () => ({
    message: "Status must be one of: queued, running, completed, failed, cancelled",
  }),
});

/** Params for `POST /targets/:targetId/scans` — note the key is `targetId`,
 * not `id`, to avoid confusion with `target.schemas.ts`'s own `:id` params
 * schema when both are imported into `target.routes.ts` together. */
export const createScanParamsSchema = z.object({
  targetId: z.string().uuid("Target id must be a valid UUID"),
});

export const scanIdParamsSchema = z.object({
  id: z.string().uuid("Scan id must be a valid UUID"),
});

export const DEFAULT_SCAN_LIST_LIMIT = 20;
export const MAX_SCAN_LIST_LIMIT = 100;
export const DEFAULT_SCAN_LIST_OFFSET = 0;

/**
 * There is no established pagination convention elsewhere in this API (`GET
 * /targets` returns everything unpaged), so this establishes a plain,
 * unopinionated one: `limit`/`offset`, coerced from query-string strings,
 * with a sensible default and an upper bound so a client can't request an
 * unbounded page.
 */
export const listScansQuerySchema = z.object({
  status: scanStatusSchema.optional(),
  targetId: z.string().uuid("targetId must be a valid UUID").optional(),
  limit: z.coerce.number().int().min(1).max(MAX_SCAN_LIST_LIMIT).default(DEFAULT_SCAN_LIST_LIMIT),
  offset: z.coerce.number().int().min(0).default(DEFAULT_SCAN_LIST_OFFSET),
});

export type ListScansQuery = z.infer<typeof listScansQuerySchema>;
export type CreateScanParams = z.infer<typeof createScanParamsSchema>;
export type ScanIdParams = z.infer<typeof scanIdParamsSchema>;
