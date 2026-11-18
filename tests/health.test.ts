import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { FastifyInstance } from "fastify";
import { buildApp } from "../src/app.js";
import { FakeZapClient } from "./helpers/fake-zap-client.js";

describe("GET /health", () => {
  let app: FastifyInstance;

  beforeAll(async () => {
    app = buildApp();
    await app.ready();
  });

  afterAll(async () => {
    await app.close();
  });

  it("should return status 200 with status ok", async () => {
    const response = await app.inject({
      method: "GET",
      url: "/health",
    });

    expect(response.statusCode).toBe(200);
    const body = JSON.parse(response.payload);
    expect(body).toEqual({ status: "ok" });
  });
});

describe("GET /health/zap", () => {
  it("returns 200 and the version when ZAP is reachable", async () => {
    const zapClient = new FakeZapClient();
    zapClient.healthResult = { reachable: true, version: "2.14.0" };
    const app = buildApp({ zapClient });
    await app.ready();

    const response = await app.inject({ method: "GET", url: "/health/zap" });

    expect(response.statusCode).toBe(200);
    expect(JSON.parse(response.payload)).toEqual({ reachable: true, version: "2.14.0" });

    await app.close();
  });

  it("returns 503 with a safe error when ZAP is unreachable", async () => {
    const zapClient = new FakeZapClient();
    zapClient.healthResult = { reachable: false, error: "ZAP request to /JSON/core/view/version/ failed: connection error" };
    const app = buildApp({ zapClient });
    await app.ready();

    const response = await app.inject({ method: "GET", url: "/health/zap" });

    expect(response.statusCode).toBe(503);
    const body = JSON.parse(response.payload);
    expect(body.reachable).toBe(false);
    expect(body.error).toBeTruthy();

    await app.close();
  });

  it("never includes an apikey or other secret in the response", async () => {
    const zapClient = new FakeZapClient();
    zapClient.healthResult = { reachable: false, error: "connection error" };
    const app = buildApp({ zapClient });
    await app.ready();

    const response = await app.inject({ method: "GET", url: "/health/zap" });

    expect(response.payload).not.toContain("apikey");
    expect(response.payload.toLowerCase()).not.toContain("api key");

    await app.close();
  });
});

describe("GET /health/zap/diagnostic", () => {
  it("requires existing authentication before the temporary secret", async () => {
    const app = buildApp();
    await app.ready();

    const response = await app.inject({
      method: "GET",
      url: "/health/zap/diagnostic",
      headers: { "x-zap-diagnostic-secret": "temporary-test-secret" },
    });

    expect(response.statusCode).toBe(401);
    await app.close();
  });

  it("does not expose the API key in the unauthenticated response", async () => {
    const previous = process.env.ZAP_API_KEY;
    process.env.ZAP_API_KEY = "must-not-appear";
    try {
      const app = buildApp();
      await app.ready();

      const response = await app.inject({
        method: "GET",
        url: "/health/zap/diagnostic",
        headers: { "x-zap-diagnostic-secret": "must-not-appear" },
      });

      expect(response.payload).not.toContain("must-not-appear");
      await app.close();
    } finally {
      if (previous === undefined) {
        delete process.env.ZAP_API_KEY;
      } else {
        process.env.ZAP_API_KEY = previous;
      }
    }
  });
});
