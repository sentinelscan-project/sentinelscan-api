import { z } from "zod";
import dotenv from "dotenv";

dotenv.config();

const optionalNonEmptyString = z.preprocess(
  (val) => (typeof val === "string" && val.trim() === "" ? undefined : val),
  z.string().min(1).optional(),
);

const optionalUrl = z.preprocess(
  (val) => (typeof val === "string" && val.trim() === "" ? undefined : val),
  z.string().url("GOOGLE_CALLBACK_URL must be a valid URL").optional(),
);

/**
 * Google OAuth/OIDC is optional: the API boots and serves email/password
 * authentication without it. The three variables below must be supplied
 * together — partial configuration is a misconfiguration, not a valid state.
 */
const googleOAuthSchema = z
  .object({
    GOOGLE_CLIENT_ID: optionalNonEmptyString,
    GOOGLE_CLIENT_SECRET: optionalNonEmptyString,
    GOOGLE_CALLBACK_URL: optionalUrl,
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
  JWT_SECRET: z.string().min(32, "JWT_SECRET must be at least 32 characters"),
  JWT_EXPIRES_IN: z.string().min(1).default("1d"),
  AUTH_COOKIE_NAME: z.string().min(1).default("sentinelscan_token"),
  WEB_APP_URL: z.string().url("WEB_APP_URL must be a valid URL").default("http://localhost:3000"),
  // "smtp" is deliberately not an accepted value here: no SMTP transport is
  // implemented in `email-service.ts`, so accepting it would let an operator
  // configure something that silently falls back to development-mode console
  // logging instead of the real delivery they asked for.
  EMAIL_PROVIDER: z.enum(["development", "resend"]).default("development"),
  EMAIL_FROM: z.string().default("SentinelScan <noreply@sentinelscan.io>"),
  EMAIL_API_KEY: optionalNonEmptyString,
  RESEND_API_KEY: optionalNonEmptyString,

  // ---------------------------------------------------------------------
  // Stage 4: OWASP ZAP integration.
  //
  // Talks directly to the ZAP daemon over the internal Docker network (see
  // docker-compose.yml) — there is no intermediate service. `ZAP_API_KEY` is
  // optional (the compose ZAP container currently disables key auth via
  // `api.disablekey=true`) but is supported for any deployment that enables
  // it; it is only ever attached to outgoing requests server-side and is
  // never logged or sent to the browser.
  // ---------------------------------------------------------------------
  ZAP_BASE_URL: z.string().url("ZAP_BASE_URL must be a valid URL"),
  ZAP_API_KEY: optionalNonEmptyString,
  /** Per-HTTP-call timeout against the ZAP daemon. */
  ZAP_HTTP_TIMEOUT_MS: z.coerce.number().int().positive().default(10_000),
  /** Ceiling on how long the spider phase may run before it is treated as failed. */
  ZAP_CRAWL_TIMEOUT_MS: z.coerce.number().int().positive().default(5 * 60_000),
  /** Ceiling on how long the active-scan phase may run before it is treated as failed. */
  ZAP_ACTIVE_SCAN_TIMEOUT_MS: z.coerce.number().int().positive().default(30 * 60_000),
  /** Ceiling across the whole execute() call (queued → terminal), independent of the two phase timeouts above. */
  ZAP_OVERALL_SCAN_TIMEOUT_MS: z.coerce.number().int().positive().default(40 * 60_000),
  /** How often the executor polls ZAP for spider/active-scan progress. */
  ZAP_POLL_INTERVAL_MS: z.coerce.number().int().positive().default(2_000),
});

const envSchema = baseEnvSchema.and(googleOAuthSchema);

export type Env = z.infer<typeof envSchema>;

export function parseEnv(customEnv?: Record<string, string | undefined>): Env {
  const envToParse = customEnv || process.env;

  // Provide safe defaults in test mode if not explicitly set
  if (envToParse.NODE_ENV === "test") {
    envToParse.DATABASE_URL = envToParse.DATABASE_URL || "postgresql://mock:mock@localhost:5432/sentinelscan_test";
    envToParse.ZAP_BASE_URL = envToParse.ZAP_BASE_URL || "http://localhost:8090";
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
