import { z } from "zod";
import dotenv from "dotenv";

dotenv.config();

/**
 * Google OAuth/OIDC is optional: the API boots and serves email/password
 * authentication without it. The three variables below must be supplied
 * together — partial configuration is a misconfiguration, not a valid state.
 */
const googleOAuthSchema = z
  .object({
    GOOGLE_CLIENT_ID: z.string().min(1).optional(),
    GOOGLE_CLIENT_SECRET: z.string().min(1).optional(),
    GOOGLE_CALLBACK_URL: z.string().url("GOOGLE_CALLBACK_URL must be a valid URL").optional(),
  })
  .refine(
    (value) => {
      const provided = [value.GOOGLE_CLIENT_ID, value.GOOGLE_CLIENT_SECRET, value.GOOGLE_CALLBACK_URL].filter(
        (entry) => entry !== undefined,
      );
      return provided.length === 0 || provided.length === 3;
    },
    {
      message:
        "GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET and GOOGLE_CALLBACK_URL must all be set together, or all be omitted",
      path: ["GOOGLE_CLIENT_ID"],
    },
  );

const baseEnvSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  PORT: z.coerce.number().default(4000),
  DATABASE_URL: z.string().min(1, "DATABASE_URL is required"),
  ZAP_SERVICE_URL: z.string().url("ZAP_SERVICE_URL must be a valid URL"),
  JWT_SECRET: z.string().min(32, "JWT_SECRET must be at least 32 characters"),
  JWT_EXPIRES_IN: z.string().min(1).default("1d"),
  AUTH_COOKIE_NAME: z.string().min(1).default("sentinelscan_token"),
  WEB_APP_URL: z.string().url("WEB_APP_URL must be a valid URL").default("http://localhost:3000"),
});

const envSchema = baseEnvSchema.and(googleOAuthSchema);

export type Env = z.infer<typeof envSchema>;

export function parseEnv(customEnv?: Record<string, string | undefined>): Env {
  const envToParse = customEnv || process.env;

  // Provide safe defaults in test mode if not explicitly set
  if (envToParse.NODE_ENV === "test") {
    envToParse.DATABASE_URL = envToParse.DATABASE_URL || "postgresql://mock:mock@localhost:5432/sentinelscan_test";
    envToParse.ZAP_SERVICE_URL = envToParse.ZAP_SERVICE_URL || "http://localhost:8080";
    envToParse.JWT_SECRET = envToParse.JWT_SECRET || "test-only-jwt-secret-value-not-for-production-use";
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

/** True when every Google OAuth/OIDC variable is configured. */
export function isGoogleOAuthConfigured(config: Env = env): boolean {
  return Boolean(config.GOOGLE_CLIENT_ID && config.GOOGLE_CLIENT_SECRET && config.GOOGLE_CALLBACK_URL);
}
