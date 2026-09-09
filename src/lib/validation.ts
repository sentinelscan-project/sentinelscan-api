import type { ZodError, ZodType, ZodTypeDef } from "zod";
import { ValidationError } from "./errors.js";

export interface FieldIssue {
  field: string;
  message: string;
}

export function formatZodIssues(error: ZodError): FieldIssue[] {
  return error.issues.map((issue) => ({
    field: issue.path.join(".") || "body",
    message: issue.message,
  }));
}

/**
 * Validates a request payload against a Zod schema, converting failures into a
 * 400 `ValidationError` carrying per-field messages.
 *
 * The parameter is typed `ZodType<T, ZodTypeDef, any>` rather than the more
 * obvious `ZodType<T>` (which defaults its `Input` parameter to `T` too).
 * For a schema where input and output genuinely differ — `.default()` makes
 * a field optional on input but always-present on output, same for
 * `.transform()` — that default makes TypeScript's inference try to satisfy
 * `Input === T` as well as `Output === T` and settle on the (contravariant,
 * input-shaped) intersection instead of the output type, so callers like
 * `const query = parseOrThrow(listScansQuerySchema, request.query)` would
 * silently get back a type where every defaulted field looks optional, even
 * though it never is at runtime. Fixing `Input` at `any` here removes that
 * position from consideration and leaves `T` to be inferred from `Output`
 * alone, which is what every caller actually wants.
 */
export function parseOrThrow<T>(schema: ZodType<T, ZodTypeDef, unknown>, payload: unknown): T {
  const result = schema.safeParse(payload);
  if (!result.success) {
    throw new ValidationError("Request validation failed", formatZodIssues(result.error));
  }
  return result.data;
}
