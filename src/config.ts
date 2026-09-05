import { z } from "zod";
import dotenv from "dotenv";

dotenv.config();

const envSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  PORT: z.coerce.number().default(4000),
  DATABASE_URL: z.string().min(1, "DATABASE_URL is required"),
  ZAP_SERVICE_URL: z.string().url("ZAP_SERVICE_URL must be a valid URL"),
});

export type Env = z.infer<typeof envSchema>;

export function parseEnv(customEnv?: Record<string, string | undefined>): Env {
  const envToParse = customEnv || process.env;

  // Provide safe defaults in test mode if not explicitly set
  if (envToParse.NODE_ENV === "test") {
    envToParse.DATABASE_URL = envToParse.DATABASE_URL || "postgresql://mock:mock@localhost:5432/sentinelscan_test";
    envToParse.ZAP_SERVICE_URL = envToParse.ZAP_SERVICE_URL || "http://localhost:8080";
  }

  const result = envSchema.safeParse(envToParse);

  if (!result.success) {
    const errorDetails = result.error.issues
      .map((issue) => `  - ${issue.path.join(".")}: ${issue.message}`)
      .join("\n");
    console.error("Critical Configuration Error - Invalid Environment Variables:\n" + errorDetails);
    throw new Error("Application configuration validation failed. Check environment variables.");
  }

  return result.data;
}

export const env = parseEnv();
