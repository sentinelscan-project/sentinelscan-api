import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { HttpZapClient, ZapRequestError } from "../src/lib/zap-client.js";

function jsonResponse(body: unknown, init: { ok?: boolean; status?: number } = {}): Response {
  return {
    ok: init.ok ?? true,
    status: init.status ?? 200,
    json: () => Promise.resolve(body),
  } as Response;
}

describe("HttpZapClient", () => {
  let fetchMock: ReturnType<typeof vi.fn>;
  let client: HttpZapClient;

  beforeEach(() => {
    fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    client = new HttpZapClient({ baseUrl: "http://owasp-zap:8090", apiKey: "secret-key", requestTimeoutMs: 5000 });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  describe("health()", () => {
    it("reports reachable with the version when ZAP responds", async () => {
      fetchMock.mockResolvedValue(jsonResponse({ version: "2.14.0" }));

      const result = await client.health();

      expect(result).toEqual({ reachable: true, version: "2.14.0" });
    });

    it("reports unreachable when the connection fails", async () => {
      fetchMock.mockRejectedValue(new TypeError("fetch failed"));

      const result = await client.health();

      expect(result.reachable).toBe(false);
      expect(result.error).toBeTruthy();
    });

    it("reports unreachable (as a timeout) when the request aborts", async () => {
      fetchMock.mockImplementation(() => {
        const err = new Error("The operation was aborted");
        err.name = "AbortError";
        return Promise.reject(err);
      });

      const result = await client.health();

      expect(result.reachable).toBe(false);
      expect(result.error).toContain("timed out");
    });

    it("reports unreachable on a malformed (non-JSON) response", async () => {
      fetchMock.mockResolvedValue({
        ok: true,
        status: 200,
        json: () => Promise.reject(new SyntaxError("Unexpected token")),
      });

      const result = await client.health();

      expect(result.reachable).toBe(false);
      expect(result.error).toContain("malformed");
    });

    it("reports unreachable on a non-2xx response", async () => {
      fetchMock.mockResolvedValue(jsonResponse({}, { ok: false, status: 500 }));

      const result = await client.health();

      expect(result.reachable).toBe(false);
      expect(result.error).toContain("500");
    });

    it("never includes the apikey in the error message", async () => {
      fetchMock.mockRejectedValue(new TypeError("fetch failed"));

      const result = await client.health();

      expect(result.error).not.toContain("secret-key");
    });
  });

  describe("request construction", () => {
    it("attaches the configured apikey as a query parameter", async () => {
      fetchMock.mockResolvedValue(jsonResponse({ version: "2.14.0" }));

      await client.health();

      const calledUrl = new URL(String(fetchMock.mock.calls[0][0]));
      expect(calledUrl.searchParams.get("apikey")).toBe("secret-key");
    });

    it("omits the apikey parameter when none is configured", async () => {
      const keylessClient = new HttpZapClient({ baseUrl: "http://owasp-zap:8090", requestTimeoutMs: 5000 });
      fetchMock.mockResolvedValue(jsonResponse({ version: "2.14.0" }));

      await keylessClient.health();

      const calledUrl = new URL(String(fetchMock.mock.calls[0][0]));
      expect(calledUrl.searchParams.has("apikey")).toBe(false);
    });
  });

  describe("context management", () => {
    it("createContext returns the contextId", async () => {
      fetchMock.mockResolvedValue(jsonResponse({ contextId: "2" }));

      await expect(client.createContext("sentinelscan-scan-abc")).resolves.toBe("2");
    });

    it("createContext throws when ZAP omits the contextId", async () => {
      fetchMock.mockResolvedValue(jsonResponse({}));

      await expect(client.createContext("sentinelscan-scan-abc")).rejects.toBeInstanceOf(ZapRequestError);
    });

    it("removeContext and includeInContext resolve without a return value", async () => {
      fetchMock.mockResolvedValue(jsonResponse({ Result: "OK" }));

      await expect(client.removeContext("x")).resolves.toBeUndefined();
      await expect(client.includeInContext("x", "^https://example\\.com(/.*)?$")).resolves.toBeUndefined();
    });
  });

  describe("spider", () => {
    it("startSpider returns the spider scan id", async () => {
      fetchMock.mockResolvedValue(jsonResponse({ scan: "0" }));

      await expect(client.startSpider("https://example.com/", "ctx")).resolves.toBe("0");
    });

    it("spiderStatus parses the numeric progress", async () => {
      fetchMock.mockResolvedValue(jsonResponse({ status: "45" }));

      await expect(client.spiderStatus("0")).resolves.toBe(45);
    });

    it("spiderStatus throws on a malformed status field", async () => {
      fetchMock.mockResolvedValue(jsonResponse({ status: "not-a-number" }));

      await expect(client.spiderStatus("0")).rejects.toBeInstanceOf(ZapRequestError);
    });

    it("stopSpider resolves", async () => {
      fetchMock.mockResolvedValue(jsonResponse({ Result: "OK" }));

      await expect(client.stopSpider("0")).resolves.toBeUndefined();
    });
  });

  describe("active scan", () => {
    it("startActiveScan returns the active scan id", async () => {
      fetchMock.mockResolvedValue(jsonResponse({ scan: "1" }));

      await expect(client.startActiveScan("https://example.com/", "2")).resolves.toBe("1");
    });

    it("activeScanStatus parses the numeric progress", async () => {
      fetchMock.mockResolvedValue(jsonResponse({ status: "100" }));

      await expect(client.activeScanStatus("1")).resolves.toBe(100);
    });

    it("stopActiveScan resolves", async () => {
      fetchMock.mockResolvedValue(jsonResponse({ Result: "OK" }));

      await expect(client.stopActiveScan("1")).resolves.toBeUndefined();
    });
  });

  describe("alertSummary", () => {
    it("maps ZAP's alertsSummary object into a list of { risk, count }", async () => {
      fetchMock.mockResolvedValue(
        jsonResponse({ alertsSummary: { High: 1, Medium: 3, Low: 0, Informational: 2 } }),
      );

      const summary = await client.alertSummary("https://example.com/");

      expect(summary).toEqual(
        expect.arrayContaining([
          { risk: "High", count: 1 },
          { risk: "Medium", count: 3 },
          { risk: "Low", count: 0 },
          { risk: "Informational", count: 2 },
        ]),
      );
    });

    it("returns an empty list when the response has no alertsSummary", async () => {
      fetchMock.mockResolvedValue(jsonResponse({}));

      await expect(client.alertSummary("https://example.com/")).resolves.toEqual([]);
    });
  });
});
