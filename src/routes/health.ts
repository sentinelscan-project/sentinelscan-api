import { FastifyInstance, FastifyPluginAsync } from "fastify";
import { createHmac, timingSafeEqual } from "node:crypto";
import { ForbiddenError, ServiceUnavailableError } from "../lib/errors.js";

const ZAP_DIAGNOSTIC_HEADER = "x-zap-diagnostic-secret";
const ZAP_DIAGNOSTIC_TIMEOUT_MS = 10_000;

function redactSensitiveText(value: string, apiKey: string): string {
  let result = value;
  if (apiKey) {
    result = result.split(apiKey).join("[REDACTED]");
  }
  return result
    .replace(/\b(authorization|cookie|set-cookie|proxy-authorization)\s*:\s*[^\r\n]+/gi, "$1: [REDACTED]")
    .replace(/\b((?:api[_-]?key|access[_-]?key|secret|token|bearer|password|passwd|pwd|session[_-]?id)s?)["']?\s*[:=]\s*["']?[^\s"'&,;]{3,}["']?/gi, "$1=[REDACTED]")
    .replace(/(?:https?:\/\/)[^/\s:@]+:[^@\s]+@[^\s"']+/gi, "[REDACTED_URL_CREDENTIALS]")
    .replace(/[?&](?:apikey|api_key|access_token|token|secret)=[^&#\s]+/gi, "?[REDACTED]")
    .slice(0, 4_096);
}

function redactJsonValue(value: unknown, apiKey: string): unknown {
  if (typeof value === "string") {
    return redactSensitiveText(value, apiKey);
  }
  if (Array.isArray(value)) {
    return value.map((entry) => redactJsonValue(entry, apiKey));
  }
  if (value && typeof value === "object") {
    const result: Record<string, unknown> = {};
    for (const [key, entry] of Object.entries(value)) {
      if (/^(?:api[-_]?key|apikey|password|secret|token|access[-_]?token|refresh[-_]?token|authorization|cookie|set[-_]?cookie|database[-_]?url)$/i.test(key)) {
        result[key] = "[REDACTED]";
      } else {
        result[key] = redactJsonValue(entry, apiKey);
      }
    }
    return result;
  }
  return value;
}

function sanitizeLocation(location: string | null, apiKey: string): string | null {
  if (!location) return null;
  try {
    const parsed = new URL(location);
    if (parsed.username || parsed.password) return "[REDACTED]";
    return `${parsed.protocol}//${parsed.host}${parsed.pathname}`;
  } catch {
    return redactSensitiveText(location, apiKey);
  }
}

function validateDiagnosticSecret(provided: string | undefined): boolean {
  const expected = process.env.ZAP_DIAGNOSTIC_SECRET;
  if (!expected || !provided) return false;

  const expectedDigest = createHmac("sha256", "sentinelscan-zap-diagnostic").update(expected).digest();
  const providedDigest = createHmac("sha256", "sentinelscan-zap-diagnostic").update(provided).digest();
  return timingSafeEqual(expectedDigest, providedDigest);
}

export const healthRoutes: FastifyPluginAsync = async (fastify: FastifyInstance) => {
  fastify.get("/health", async (_request, reply) => {
    return reply.status(200).send({ status: "ok" });
  });

  /**
   * Application-level ZAP connectivity check — not a proxy for ZAP's own
   * administration API, which stays entirely off this API's surface. The
   * response is intentionally minimal: whether ZAP is reachable and, if so,
   * its version. No internal network details, and no API key: `ZapClient`
   * never exposes the key it may be configured with, and this route couldn't
   * leak it even if it wanted to.
   */
  fastify.get("/health/zap", async (_request, reply) => {
    const health = await fastify.zapClient.health();
    return reply.status(health.reachable ? 200 : 503).send(health);
  });

  // TODO: REMOVE AFTER ZAP 429 DIAGNOSTICS COMPLETE. Temporary deployment
  // diagnostic only. It performs one fixed version GET and exposes no ZAP client
  // methods for scans, contexts, arbitrary URLs, or arbitrary paths.
  fastify.get("/health/zap/diagnostic", {
    preHandler: [
      fastify.authenticate,
      async (request) => {
        if (!validateDiagnosticSecret(request.headers[ZAP_DIAGNOSTIC_HEADER] as string | undefined)) {
          throw new ForbiddenError("Diagnostic authorization required", "ZAP_DIAGNOSTIC_FORBIDDEN");
        }
      },
    ],
  }, async (_request, reply) => {
    const baseUrl = process.env.ZAP_BASE_URL;
    const apiKey = process.env.ZAP_API_KEY;

    if (!baseUrl || !apiKey) {
      throw new ServiceUnavailableError("ZAP diagnostic configuration is unavailable");
    }

    let url: URL;
    try {
      url = new URL("/JSON/core/view/version/", baseUrl);
      if (!["http:", "https:"].includes(url.protocol) || url.username || url.password) {
        throw new Error("unsafe ZAP base URL");
      }
      url.search = "";
      url.searchParams.set("apikey", apiKey);
    } catch {
      throw new ServiceUnavailableError("ZAP diagnostic configuration is invalid");
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), ZAP_DIAGNOSTIC_TIMEOUT_MS);
    let response: globalThis.Response;

    try {
      response = await fetch(url, {
        method: "GET",
        redirect: "manual",
        signal: controller.signal,
      });
    } catch (error) {
      const timedOut = error instanceof Error && error.name === "AbortError";
      throw new ServiceUnavailableError(
        timedOut ? "ZAP diagnostic request timed out" : "ZAP diagnostic connection failed",
      );
    } finally {
      clearTimeout(timer);
    }

    const headerNames = [
      "server",
      "via",
      "retry-after",
      "request-id",
      "x-request-id",
      "x-correlation-id",
      "x-amzn-trace-id",
      "x-render-request-id",
      "rndr-id",
      "cf-ray",
      "traceparent",
      "date",
      "content-type",
    ] as const;

    const headers: Record<string, string> = {};
    for (const name of headerNames) {
      const value = response.headers.get(name);
      if (value) {
        headers[name] = redactSensitiveText(value, apiKey);
      }
    }

    const rawBody = await response.text();
    let body: unknown = null;
    if (rawBody) {
      try {
        body = redactJsonValue(JSON.parse(rawBody), apiKey);
      } catch {
        body = redactSensitiveText(rawBody, apiKey);
      }
      const serialized = JSON.stringify(body);
      if (serialized.includes(apiKey) ||
          /(?:https?:\/\/)[^/\s:@]+:[^@\s]+@|(?:apikey|api_key|access_token|refresh_token|authorization|cookie|set-cookie)\s*[:=]/i.test(serialized)) {
        body = "[REDACTED: credential-like data detected]";
      }
    }

    return reply.status(200).send({
      status: response.status,
      location: sanitizeLocation(response.headers.get("location"), apiKey),
      headers,
      body,
    });
  });
};
