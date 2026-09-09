import type { ZodError, ZodType } from "zod";
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
 */
export function parseOrThrow<T>(schema: ZodType<T>, payload: unknown): T {
  const result = schema.safeParse(payload);
  if (!result.success) {
    throw new ValidationError("Request validation failed", formatZodIssues(result.error));
  }
  return result.data;
}
