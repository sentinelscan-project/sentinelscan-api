import path from "node:path";
import { z } from "zod";
import dotenv from "dotenv";

dotenv.config();
dotenv.config({ path: path.resolve(process.cwd(), "../.env") });

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
  ZAP_BASE_URL: z.preprocess(
    (val) => (typeof val === "string" && val.trim() !== "" ? val : process.env.ZAP_SERVICE_URL),
    z.string().url("ZAP_BASE_URL must be a valid URL"),
  ),
  /** Legacy alias from Stage 0; ZAP_BASE_URL is canonical. */
  ZAP_SERVICE_URL: optionalNonEmptyString,
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

  // ---------------------------------------------------------------------
  // Stage 6 & 7: AI Security Analyst (Google Gemini).
  //
  // Google Gemini is the AI provider (see
  // `modules/analysis/providers/gemini-security-analysis-model.ts`) — the
  // `SecurityAnalysisModel` interface exists so another provider could be
  // added later without touching anything above it. `GEMINI_API_KEY` is
  // deliberately optional so the API still boots and every other feature
  // keeps working without it — a `POST /scans/:scanId/analyze` request made
  // without one is accepted (the `SecurityAnalysis` row is created) but the
  // analysis itself finishes `failed` with a safe error message, exactly
  // like any other AI-provider failure. It is never sent to the browser and
  // never logged.
  // ---------------------------------------------------------------------
  AI_PROVIDER: z.enum(["gemini"]).default("gemini"),
  /** Which Gemini model performs security analysis. */
  AI_MODEL: z.string().min(1).default("gemini-3.6-flash"),
  GEMINI_API_KEY: optionalNonEmptyString,
  /** Per-analysis timeout for the AI provider call itself. */
  ANALYSIS_TIMEOUT_MS: z.coerce.number().int().positive().default(120_000),
  /** Ceiling on the model's own output size for one analysis. */
  ANALYSIS_MAX_OUTPUT_TOKENS: z.coerce.number().int().positive().default(8_000),
});

/**
 * Exact secret values that have appeared as a development/example/local
 * fallback somewhere in this repository (`.env.example`, `docker-compose.yml`,
 * this file's own `NODE_ENV=test` default). None of them is a secret in any
 * meaningful sense — they're all either committed to git or trivially
 * derivable from it — so accepting any of them in a real production
 * deployment would mean the signing key is effectively public.
 */
const KNOWN_INSECURE_JWT_SECRETS = new Set([
  "test-only-jwt-secret-value-not-for-production-use",
  "dev-insecure-jwt-secret-at-least-32-chars-long-for-compose",
  "replace-with-a-long-random-value-at-least-32-chars",
]);

/** Catches the common English-word placeholder patterns even if the exact string above isn't matched verbatim. */
const PLACEHOLDER_SECRET_PATTERN =
  /insecure|changeme|change-me|placeholder|example|sample|replace-with|your-secret|dev-only|dev-secret|test-secret|todo/i;

/** Substrings that only ever appear in the example/local database URLs shipped in this repo, never a real one. */
const PLACEHOLDER_DATABASE_URL_PATTERN = /ep-sample-pooler|mock:mock|neon-proxy/i;

/**
 * Production-only fail-fast checks, layered on top of the schema above via
 * `superRefine` rather than baked into the field types themselves — every
 * one of these values is a perfectly valid *shape* (a long-enough string, a
 * well-formed URL); what makes it unacceptable is specific to running with
 * `NODE_ENV=production`, so `development`/`test` deliberately skip all of
 * them (the `NODE_ENV=test` branch in `parseEnv` even relies on one of the
 * exact strings blocked here). This is what makes "reject development JWT
 * secrets / insecure placeholder values / invalid production configuration"
 * an enforced invariant rather than a documentation-only convention — the
 * process refuses to start rather than silently running insecurely.
 */
const envSchema = baseEnvSchema.and(googleOAuthSchema).superRefine((value, ctx) => {
  if (value.NODE_ENV !== "production") {
    return;
  }

  if (KNOWN_INSECURE_JWT_SECRETS.has(value.JWT_SECRET) || PLACEHOLDER_SECRET_PATTERN.test(value.JWT_SECRET)) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: ["JWT_SECRET"],
      message:
        "JWT_SECRET looks like a development/example placeholder and must not be used in production. " +
        "Generate a real secret (see .env.example) and set it in the production environment.",
    });
  }

  if (!value.WEB_APP_URL.startsWith("https://")) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: ["WEB_APP_URL"],
      message: "WEB_APP_URL must be an https:// URL in production (the deployed frontend's real origin).",
    });
  }

  if (PLACEHOLDER_DATABASE_URL_PATTERN.test(value.DATABASE_URL)) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: ["DATABASE_URL"],
      message:
        "DATABASE_URL looks like the example/local placeholder from .env.example or docker-compose.yml and must " +
        "not be used in production. Set the real Neon connection string.",
    });
  }
});

export type Env = z.infer<typeof envSchema>;

export function parseEnv(customEnv?: Record<string, string | undefined>): Env {
  const envToParse = customEnv || process.env;

  // Provide safe defaults in test mode if not explicitly set
  if (envToParse.NODE_ENV === "test") {
    envToParse.DATABASE_URL = envToParse.DATABASE_URL || "postgresql://mock:mock@localhost:5432/sentinelscan_test";
    envToParse.ZAP_BASE_URL = envToParse.ZAP_BASE_URL || "http://localhost:8090";
    envToParse.JWT_SECRET = envToParse.JWT_SECRET || "test-only-jwt-secret-value-not-for-production-use";
  }

  // Support legacy ZAP_SERVICE_URL as an alias if ZAP_BASE_URL is not set
  if (!envToParse.ZAP_BASE_URL && envToParse.ZAP_SERVICE_URL) {
    envToParse.ZAP_BASE_URL = envToParse.ZAP_SERVICE_URL;
  }

  const result = envSchema.safeParse(envToParse);

  if (!result.success) {
    const errorDetails = result.error.issues
      .map((issue) => `  - ${issue.path.join(".")}: ${issue.message}`)
      .join("\n");
    console.error("Critical Configuration Error - Invalid Environment Variables:\n" + errorDetails);
    // The specific field(s) and reason(s) are included in the thrown message
    // itself (not just the console.error above) so the failure is legible
    // from whatever actually surfaces the crash — a process manager's exit
    // reason, a platform's deploy-failure summary, a test assertion — even
    // when stdout/stderr logs aren't consulted separately.
    throw new Error(`Application configuration validation failed:\n${errorDetails}`);
  }

  // A loud warning, not a fail-fast rejection: unlike JWT_SECRET/WEB_APP_URL/
  // DATABASE_URL above, whether ZAP actually enforces this key is a fact
  // about the *separately deployed* ZAP daemon's own configuration, not
  // something this process can verify — it can only check that it has been
  // told to send one. Hard-failing boot here would also break the documented
  // local "run the production Docker image via docker-compose" verification
  // workflow, which intentionally keeps ZAP unauthenticated
  // (`api.disablekey=true`) even though nothing about that workflow is a
  // real production deployment. Never logs the key itself.
  if (result.data.NODE_ENV === "production" && !result.data.ZAP_API_KEY) {
    console.warn(
      "[Config] WARNING: ZAP_API_KEY is not set while NODE_ENV=production. " +
        "The production ZAP daemon must require API-key authentication (never api.disablekey=true) — " +
        "see the README's Production Deployment section.",
    );
  }

  return result.data;
}

export const env = parseEnv();

/** True when every Google OAuth/OIDC variable is configured. */
export function isGoogleOAuthConfigured(config: Env = env): boolean {
  return Boolean(config.GOOGLE_CLIENT_ID && config.GOOGLE_CLIENT_SECRET && config.GOOGLE_CALLBACK_URL);
}
