import { z } from "zod";

/** Params for `GET /analysis/:id` — mirrors `finding.schemas.ts`'s `findingIdParamsSchema`. */
export const analysisIdParamsSchema = z.object({
  id: z.string().uuid("Analysis id must be a valid UUID"),
});

export type AnalysisIdParams = z.infer<typeof analysisIdParamsSchema>;
