import { describe, it, expect } from "vitest";
import { parseEnv } from "../src/config.js";

/**
 * A fully valid production configuration — every test below mutates exactly
 * one field away from this baseline to prove that field's rejection is what
 * actually causes the failure (rather than some other, unrelated cause).
 */
function validProductionEnv(overrides: Record<string, string | undefined> = {}): Record<string, string | undefined> {
  return {
    NODE_ENV: "production",
    DATABASE_URL: "postgresql://prod_user:realpassword@ep-real-prod-pooler.us-east-2.aws.neon.tech/sentinelscan?sslmode=require",
    JWT_SECRET: "N3v3rGu3ssTh1sR4nd0mProductionSigningKeyValue==",
    WEB_APP_URL: "https://sentinelscan-web.vercel.app",
    ZAP_BASE_URL: "https://sentinelscan-zap.internal.onrender.com:8090",
    ZAP_API_KEY: "a-real-zap-api-key",
    ...overrides,
  };
}

describe("parseEnv — production fail-fast validation", () => {
  it("accepts a fully valid production configuration", () => {
    expect(() => parseEnv(validProductionEnv())).not.toThrow();
  });

  it("rejects the exact docker-compose.yml development JWT_SECRET default", () => {
    expect(() =>
      parseEnv(validProductionEnv({ JWT_SECRET: "dev-insecure-jwt-secret-at-least-32-chars-long-for-compose" })),
    ).toThrow(/JWT_SECRET/);
  });

  it("rejects the exact NODE_ENV=test JWT_SECRET fallback", () => {
    expect(() =>
      parseEnv(validProductionEnv({ JWT_SECRET: "test-only-jwt-secret-value-not-for-production-use" })),
    ).toThrow(/JWT_SECRET/);
  });

  it("rejects the exact .env.example JWT_SECRET placeholder", () => {
    expect(() =>
      parseEnv(validProductionEnv({ JWT_SECRET: "replace-with-a-long-random-value-at-least-32-chars" })),
    ).toThrow(/JWT_SECRET/);
  });

  it("rejects a JWT_SECRET that merely looks like a placeholder, even if not an exact known string", () => {
    expect(() =>
      parseEnv(validProductionEnv({ JWT_SECRET: "this-is-a-placeholder-value-change-me-please-1234" })),
    ).toThrow(/JWT_SECRET/);
  });

  it("accepts a long, random-looking JWT_SECRET with no placeholder words in it", () => {
    expect(() =>
      parseEnv(validProductionEnv({ JWT_SECRET: "xQ7mP2vL9kR4tY8wZ1nB6cF3hJ5sA0dE7gK2mN9pQ4rT" })),
    ).not.toThrow();
  });

  it("rejects a non-https WEB_APP_URL in production", () => {
    expect(() => parseEnv(validProductionEnv({ WEB_APP_URL: "http://sentinelscan-web.vercel.app" }))).toThrow(
      /WEB_APP_URL/,
    );
  });

  it("rejects the .env.example placeholder DATABASE_URL host in production", () => {
    expect(() =>
      parseEnv(
        validProductionEnv({
          DATABASE_URL: "postgresql://user:password@ep-sample-pooler.us-east-2.aws.neon.tech/sentinelscan?sslmode=require",
        }),
      ),
    ).toThrow(/DATABASE_URL/);
  });

  it("rejects the docker-compose.yml mock DATABASE_URL fallback in production", () => {
    expect(() =>
      parseEnv(validProductionEnv({ DATABASE_URL: "postgresql://mock:mock@neon-proxy:5432/sentinelscan" })),
    ).toThrow(/DATABASE_URL/);
  });

  it("does not reject any of these values outside production (development)", () => {
    expect(() =>
      parseEnv(
        validProductionEnv({
          NODE_ENV: "development",
          JWT_SECRET: "dev-insecure-jwt-secret-at-least-32-chars-long-for-compose",
          WEB_APP_URL: "http://localhost:3000",
          DATABASE_URL: "postgresql://mock:mock@neon-proxy:5432/sentinelscan",
        }),
      ),
    ).not.toThrow();
  });

  it("boots successfully in production without ZAP_API_KEY (warns, does not fail closed on this check alone)", () => {
    const withoutZapKey = validProductionEnv();
    delete withoutZapKey.ZAP_API_KEY;
    expect(() => parseEnv(withoutZapKey)).not.toThrow();
  });
});
