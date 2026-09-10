import type { Env } from "../config.js";
import { env as defaultEnv } from "../config.js";

/**
 * A clean boundary between scan orchestration (`ZapScanExecutor`) and the
 * raw OWASP ZAP HTTP API. Nothing outside this file constructs a ZAP request
 * URL or parses a ZAP response body — `ZapScanExecutor` only ever calls
 * these methods, which is what keeps it testable with a fake implementation
 * and keeps ZAP's HTTP surface from leaking into route handlers or the
 * service layer.
 */
export interface ZapHealth {
  reachable: boolean;
  /** ZAP's own version string, when reachable. */
  version?: string;
  /** A safe, non-sensitive description of the failure, when not reachable. */
  error?: string;
}

/** One risk-level bucket from ZAP's alerts summary — a count, not the alerts themselves. */
export interface ZapAlertSummary {
  risk: string;
  count: number;
}

export interface ZapClient {
  /** Verifies connectivity without side effects — used for `GET /health/zap`. */
  health(): Promise<ZapHealth>;
  /** Creates a ZAP context scoped to one scan and returns its id. */
  createContext(contextName: string): Promise<string>;
  /** Restricts a context's scope to URLs matching `regex` (see `lib/url.ts`'s `buildOriginScopeRegex`). */
  includeInContext(contextName: string, regex: string): Promise<void>;
  /** Removes a context — cleanup after a scan finishes, fails, or is cancelled. */
  removeContext(contextName: string): Promise<void>;
  /** Starts spidering `targetUrl` within `contextName`'s scope; returns the spider's scan id. */
  startSpider(targetUrl: string, contextName: string): Promise<string>;
  /** 0–100. */
  spiderStatus(scanId: string): Promise<number>;
  stopSpider(scanId: string): Promise<void>;
  /** Starts an active scan of `targetUrl` within `contextId`'s scope; returns the active scan's id. */
  startActiveScan(targetUrl: string, contextId: string): Promise<string>;
  /** 0–100. */
  activeScanStatus(scanId: string): Promise<number>;
  stopActiveScan(scanId: string): Promise<void>;
  /** Per-risk-level alert counts for everything found under `baseUrl` — a summary, not raw alert bodies. */
  alertSummary(baseUrl: string): Promise<ZapAlertSummary[]>;
}

/**
 * Thrown for any failure talking to ZAP: connection refused, timeout,
 * non-2xx response, or a response body that doesn't have the shape expected.
 * The message never includes the request URL (which may carry `apikey` as a
 * query parameter) or the response body verbatim.
 */
export class ZapRequestError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ZapRequestError";
  }
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null ? (value as Record<string, unknown>) : null;
}

function stringField(body: unknown, field: string): string | undefined {
  const value = asRecord(body)?.[field];
  return typeof value === "string" ? value : undefined;
}

export interface ZapClientConfig {
  baseUrl: string;
  apiKey?: string;
  requestTimeoutMs: number;
}

/**
 * HTTP-backed {@link ZapClient} talking to a real ZAP daemon's JSON API
 * (`/JSON/<component>/<view|action>/<name>/`) over the internal Docker
 * network — see `ZAP_BASE_URL` in `config.ts`. Every call is GET with query
 * parameters, matching how ZAP's own "action" endpoints are conventionally
 * invoked.
 */
export class HttpZapClient implements ZapClient {
  constructor(private readonly config: ZapClientConfig) {}

  private async call(path: string, params: Record<string, string> = {}): Promise<unknown> {
    const url = new URL(path, this.config.baseUrl);
    for (const [key, value] of Object.entries(params)) {
      url.searchParams.set(key, value);
    }
    if (this.config.apiKey) {
      url.searchParams.set("apikey", this.config.apiKey);
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.config.requestTimeoutMs);

    let response: Response;
    try {
      response = await fetch(url, { signal: controller.signal });
    } catch (err) {
      // Deliberately never include `url` here: it carries the apikey query
      // parameter. `path` (the ZAP endpoint name) is safe on its own.
      const timedOut = err instanceof Error && err.name === "AbortError";
      throw new ZapRequestError(
        timedOut ? `ZAP request to ${path} timed out` : `ZAP request to ${path} failed: connection error`,
      );
    } finally {
      clearTimeout(timer);
    }

    if (!response.ok) {
      throw new ZapRequestError(`ZAP returned HTTP ${response.status} for ${path}`);
    }

    let body: unknown;
    try {
      body = await response.json();
    } catch {
      throw new ZapRequestError(`ZAP returned a malformed (non-JSON) response for ${path}`);
    }
    return body;
  }

  async health(): Promise<ZapHealth> {
    try {
      const body = await this.call("/JSON/core/view/version/");
      return { reachable: true, version: stringField(body, "version") };
    } catch (err) {
      return {
        reachable: false,
        error: err instanceof Error ? err.message : "Unknown ZAP connectivity error",
      };
    }
  }

  async createContext(contextName: string): Promise<string> {
    const body = await this.call("/JSON/context/action/newContext/", { contextName });
    const contextId = stringField(body, "contextId");
    if (!contextId) {
      throw new ZapRequestError("ZAP did not return a contextId when creating a context");
    }
    return contextId;
  }

  async includeInContext(contextName: string, regex: string): Promise<void> {
    await this.call("/JSON/context/action/includeInContext/", { contextName, regex });
  }

  async removeContext(contextName: string): Promise<void> {
    await this.call("/JSON/context/action/removeContext/", { contextName });
  }

  async startSpider(targetUrl: string, contextName: string): Promise<string> {
    const body = await this.call("/JSON/spider/action/scan/", {
      url: targetUrl,
      contextName,
      recurse: "true",
    });
    const scanId = stringField(body, "scan");
    if (!scanId) {
      throw new ZapRequestError("ZAP did not return a scan id when starting the spider");
    }
    return scanId;
  }

  async spiderStatus(scanId: string): Promise<number> {
    const body = await this.call("/JSON/spider/view/status/", { scanId });
    const status = Number(stringField(body, "status"));
    if (!Number.isFinite(status)) {
      throw new ZapRequestError("ZAP returned a malformed spider status");
    }
    return status;
  }

  async stopSpider(scanId: string): Promise<void> {
    await this.call("/JSON/spider/action/stop/", { scanId });
  }

  async startActiveScan(targetUrl: string, contextId: string): Promise<string> {
    const body = await this.call("/JSON/ascan/action/scan/", {
      url: targetUrl,
      contextId,
      recurse: "true",
    });
    const scanId = stringField(body, "scan");
    if (!scanId) {
      throw new ZapRequestError("ZAP did not return a scan id when starting the active scan");
    }
    return scanId;
  }

  async activeScanStatus(scanId: string): Promise<number> {
    const body = await this.call("/JSON/ascan/view/status/", { scanId });
    const status = Number(stringField(body, "status"));
    if (!Number.isFinite(status)) {
      throw new ZapRequestError("ZAP returned a malformed active scan status");
    }
    return status;
  }

  async stopActiveScan(scanId: string): Promise<void> {
    await this.call("/JSON/ascan/action/stop/", { scanId });
  }

  async alertSummary(baseUrl: string): Promise<ZapAlertSummary[]> {
    const body = await this.call("/JSON/alert/view/alertsSummary/", { baseurl: baseUrl });
    const summary = asRecord(asRecord(body)?.alertsSummary);
    if (!summary) {
      return [];
    }
    return Object.entries(summary).map(([risk, count]) => ({
      risk,
      count: typeof count === "number" ? count : Number(count) || 0,
    }));
  }
}

export function createZapClient(config: Env = defaultEnv): ZapClient {
  return new HttpZapClient({
    baseUrl: config.ZAP_BASE_URL,
    apiKey: config.ZAP_API_KEY,
    requestTimeoutMs: config.ZAP_HTTP_TIMEOUT_MS,
  });
}

export const defaultZapClient = createZapClient();
