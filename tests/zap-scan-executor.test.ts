import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { ZapScanExecutor } from "../src/modules/scans/zap-scan-executor.js";
import { FakeZapClient } from "./helpers/fake-zap-client.js";
import { createInMemoryScanRepository, type InMemoryScanRepository } from "./helpers/in-memory-scan.repository.js";
import {
  createInMemoryFindingRepository,
  type InMemoryFindingRepository,
} from "./helpers/in-memory-finding.repository.js";
import { cancelScan } from "../src/modules/scans/scan.service.js";

const FAST_CONFIG = {
  crawlTimeoutMs: 1000,
  activeScanTimeoutMs: 1000,
  overallTimeoutMs: 5000,
  pollIntervalMs: 1,
};

let scans: InMemoryScanRepository;
let findings: InMemoryFindingRepository;
let zap: FakeZapClient;
let executor: ZapScanExecutor;

async function seedScan(targetUrl = "https://example.com/"): Promise<{ scanId: string; targetId: string; targetUrl: string }> {
  const scan = await scans.create({ targetId: "target-1", requestedById: "owner-1" });
  return { scanId: scan.id, targetId: "target-1", targetUrl };
}

beforeEach(() => {
  scans = createInMemoryScanRepository();
  findings = createInMemoryFindingRepository();
  zap = new FakeZapClient();
  executor = new ZapScanExecutor(zap, scans, findings, FAST_CONFIG);
  // The executor logs via plain console.* (see its module comment for why:
  // it runs outside any Fastify request context). Quiet that here so the
  // test run's output stays readable; nothing in this file asserts on it.
  vi.spyOn(console, "info").mockImplementation(() => undefined);
  vi.spyOn(console, "error").mockImplementation(() => undefined);
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("execution — happy path", () => {
  it("moves a queued scan through running to completed", async () => {
    const { scanId, targetId, targetUrl } = await seedScan();
    zap.spiderProgress = [30, 100];
    zap.activeScanProgress = [50, 100];

    await executor.execute({ scanId, targetId, targetUrl });

    const final = await scans.findById(scanId);
    expect(final?.status).toBe("completed");
    expect(final?.startedAt).toBeInstanceOf(Date);
    expect(final?.completedAt).toBeInstanceOf(Date);
    expect(final?.errorMessage).toBeNull();
  });

  it("starts the crawl (spider) against the target within a scan-scoped context", async () => {
    const { scanId, targetId, targetUrl } = await seedScan();

    await executor.execute({ scanId, targetId, targetUrl });

    expect(zap.startSpiderCalls).toHaveLength(1);
    expect(zap.startSpiderCalls[0].url).toBe(targetUrl);
    expect(zap.startSpiderCalls[0].contextName).toContain(scanId);
  });

  it("starts the active scan only after the crawl reaches 100", async () => {
    const { scanId, targetId, targetUrl } = await seedScan();
    zap.spiderProgress = [40, 70, 100];
    const order: string[] = [];
    zap.onSpiderStatusPoll = () => {
      order.push("spiderStatus");
    };
    const originalStartActiveScan = zap.startActiveScan.bind(zap);
    zap.startActiveScan = async (url, contextId) => {
      order.push("startActiveScan");
      return originalStartActiveScan(url, contextId);
    };

    await executor.execute({ scanId, targetId, targetUrl });

    expect(zap.startActiveScanCalls).toHaveLength(1);
    // Three spiderStatus polls (40, 70, 100) must all happen before
    // startActiveScan — proving the active scan waits for the crawl to
    // actually finish rather than starting alongside it.
    expect(order).toEqual(["spiderStatus", "spiderStatus", "spiderStatus", "startActiveScan"]);
  });

  it("fetches raw alerts and persists normalized findings before completing", async () => {
    const { scanId, targetId, targetUrl } = await seedScan();
    zap.alertsResult = [
      {
        alert: "SQL Injection",
        name: "SQL Injection",
        risk: "High",
        confidence: "Medium",
        description: "SQL injection may be possible.",
        solution: "Use parameterized queries.",
        reference: "https://example.org/sqli",
        pluginId: "40018",
        cweid: "89",
        wascid: "19",
        url: `${targetUrl}search?q=1`,
        method: "GET",
        param: "q",
        attack: "1' OR '1'='1",
        evidence: "SQL syntax error",
      },
    ];

    await executor.execute({ scanId, targetId, targetUrl });

    expect(zap.alertsCalls).toEqual([targetUrl]);
    const persisted = [...findings.rows.values()];
    expect(persisted).toHaveLength(1);
    expect(persisted[0].scanId).toBe(scanId);
    expect(persisted[0].sourceRuleId).toBe("40018");
    expect(persisted[0].severity).toBe("high");
    expect(persisted[0].instances).toHaveLength(1);
  });

  it("completes with zero findings for a clean scan", async () => {
    const { scanId, targetId, targetUrl } = await seedScan();
    zap.alertsResult = [];

    await executor.execute({ scanId, targetId, targetUrl });

    const final = await scans.findById(scanId);
    expect(final?.status).toBe("completed");
    expect([...findings.rows.values()]).toHaveLength(0);
  });

  it("scopes the ZAP context to the target's origin", async () => {
    const { scanId, targetId } = await seedScan("https://example.com/app/login");

    await executor.execute({ scanId, targetId, targetUrl: "https://example.com/app/login" });

    expect(zap.includeInContextCalls).toHaveLength(1);
    expect(zap.includeInContextCalls[0].regex).toBe("^https://example\\.com(/.*)?$");
  });

  it("removes the ZAP context after a successful run", async () => {
    const { scanId, targetId, targetUrl } = await seedScan();

    await executor.execute({ scanId, targetId, targetUrl });

    expect(zap.removeContextCalls).toEqual(zap.createContextCalls);
  });
});

describe("failure handling", () => {
  it("marks the scan failed when ZAP is unreachable (context creation fails)", async () => {
    const { scanId, targetId, targetUrl } = await seedScan();
    zap.failCreateContext = true;

    await executor.execute({ scanId, targetId, targetUrl });

    const final = await scans.findById(scanId);
    expect(final?.status).toBe("failed");
    expect(final?.errorMessage).toBeTruthy();
    expect(final?.completedAt).toBeInstanceOf(Date);
  });

  it("marks the scan failed when the crawl fails", async () => {
    const { scanId, targetId, targetUrl } = await seedScan();
    zap.failSpiderStatus = true;

    await executor.execute({ scanId, targetId, targetUrl });

    const final = await scans.findById(scanId);
    expect(final?.status).toBe("failed");
    expect(zap.startActiveScanCalls).toHaveLength(0);
  });

  it("marks the scan failed when the active scan fails", async () => {
    const { scanId, targetId, targetUrl } = await seedScan();
    zap.failActiveScanStatus = true;

    await executor.execute({ scanId, targetId, targetUrl });

    const final = await scans.findById(scanId);
    expect(final?.status).toBe("failed");
  });

  it("marks the scan failed (never completed) when finding persistence fails after a successful ZAP run", async () => {
    const { scanId, targetId, targetUrl } = await seedScan();
    zap.alertsResult = [{ alert: "XSS", name: "XSS", risk: "Medium", confidence: "High", pluginId: "40012" }];
    findings.failNextCreateMany = true;

    await executor.execute({ scanId, targetId, targetUrl });

    const final = await scans.findById(scanId);
    expect(final?.status).toBe("failed");
    expect([...findings.rows.values()]).toHaveLength(0);
  });

  it("marks the scan failed when the crawl exceeds its timeout", async () => {
    const { scanId, targetId, targetUrl } = await seedScan();
    zap.spiderProgress = [10]; // never advances
    const shortTimeoutExecutor = new ZapScanExecutor(zap, scans, findings, { ...FAST_CONFIG, crawlTimeoutMs: 10 });

    await shortTimeoutExecutor.execute({ scanId, targetId, targetUrl });

    const final = await scans.findById(scanId);
    expect(final?.status).toBe("failed");
    expect(final?.errorMessage).toContain("timeout");
    // Best-effort stop was attempted.
    expect(zap.stopSpiderCalls.length).toBeGreaterThan(0);
  });

  it("never leaks a raw internal error message into errorMessage", async () => {
    const { scanId, targetId, targetUrl } = await seedScan();
    zap.createContext = async () => {
      throw new Error("ECONNREFUSED 10.0.0.5:8090 apikey=super-secret");
    };

    await executor.execute({ scanId, targetId, targetUrl });

    const final = await scans.findById(scanId);
    expect(final?.status).toBe("failed");
    expect(final?.errorMessage).not.toContain("super-secret");
    expect(final?.errorMessage).not.toContain("10.0.0.5");
  });

  it("does not remove a ZAP context that was never created", async () => {
    const { scanId, targetId, targetUrl } = await seedScan();
    zap.failCreateContext = true;

    await executor.execute({ scanId, targetId, targetUrl });

    expect(zap.removeContextCalls).toHaveLength(0);
  });
});

describe("target safety", () => {
  it("fails the scan without making any ZAP calls for an unsafe target", async () => {
    const { scanId, targetId } = await seedScan();

    await executor.execute({ scanId, targetId, targetUrl: "http://127.0.0.1/" });

    const final = await scans.findById(scanId);
    expect(final?.status).toBe("failed");
    expect(zap.createContextCalls).toHaveLength(0);
    expect(zap.startSpiderCalls).toHaveLength(0);
  });
});

describe("cancellation", () => {
  it("does nothing when the scan was already cancelled before execution started", async () => {
    const { scanId, targetId, targetUrl } = await seedScan();
    await cancelScan(scans, "owner-1", scanId);

    await executor.execute({ scanId, targetId, targetUrl });

    const final = await scans.findById(scanId);
    expect(final?.status).toBe("cancelled");
    expect(zap.createContextCalls).toHaveLength(0);
  });

  it("stops the crawl and marks cancelled when cancelled mid-crawl", async () => {
    const { scanId, targetId, targetUrl } = await seedScan();
    zap.spiderProgress = [20, 20, 20, 20, 20];
    let polls = 0;
    zap.onSpiderStatusPoll = async () => {
      polls += 1;
      if (polls === 2) {
        await cancelScan(scans, "owner-1", scanId);
      }
    };

    await executor.execute({ scanId, targetId, targetUrl });

    const final = await scans.findById(scanId);
    expect(final?.status).toBe("cancelled");
    expect(zap.stopSpiderCalls.length).toBeGreaterThan(0);
    expect(zap.startActiveScanCalls).toHaveLength(0);
  });

  it("stops the active scan and marks cancelled when cancelled mid-active-scan", async () => {
    const { scanId, targetId, targetUrl } = await seedScan();
    zap.activeScanProgress = [20, 20, 20, 20];
    let polls = 0;
    zap.onActiveScanStatusPoll = async () => {
      polls += 1;
      if (polls === 2) {
        await cancelScan(scans, "owner-1", scanId);
      }
    };

    await executor.execute({ scanId, targetId, targetUrl });

    const final = await scans.findById(scanId);
    expect(final?.status).toBe("cancelled");
    expect(zap.stopActiveScanCalls.length).toBeGreaterThan(0);
  });

  it("cancellation racing with the final completion never overwrites 'cancelled' with 'completed'", async () => {
    const { scanId, targetId, targetUrl } = await seedScan();
    zap.onAlertSummary = async () => {
      // Simulate the cancel request landing in the exact instant between the
      // active scan finishing and this executor recording completion.
      await cancelScan(scans, "owner-1", scanId);
    };

    await executor.execute({ scanId, targetId, targetUrl });

    const final = await scans.findById(scanId);
    expect(final?.status).toBe("cancelled");
  });

  it("still removes the ZAP context when cancelled mid-crawl (cleanup runs on every path)", async () => {
    const { scanId, targetId, targetUrl } = await seedScan();
    zap.spiderProgress = [20, 20, 20, 20, 20];
    let polls = 0;
    zap.onSpiderStatusPoll = async () => {
      polls += 1;
      if (polls === 1) {
        await cancelScan(scans, "owner-1", scanId);
      }
    };

    await executor.execute({ scanId, targetId, targetUrl });

    expect(zap.createContextCalls).toHaveLength(1);
    expect(zap.removeContextCalls).toEqual(zap.createContextCalls);
  });
});

describe("isolation & concurrency", () => {
  it("gives each scan its own uniquely named ZAP context", async () => {
    const first = await seedScan();
    const second = await seedScan();

    await executor.execute({ scanId: first.scanId, targetId: first.targetId, targetUrl: first.targetUrl });
    await executor.execute({ scanId: second.scanId, targetId: second.targetId, targetUrl: second.targetUrl });

    expect(zap.createContextCalls).toHaveLength(2);
    expect(new Set(zap.createContextCalls).size).toBe(2);
    expect(zap.createContextCalls[0]).toContain(first.scanId);
    expect(zap.createContextCalls[1]).toContain(second.scanId);
  });

  it("serializes concurrent execute() calls to at most one in-flight ZAP interaction", async () => {
    const first = await seedScan();
    const second = await seedScan();
    const order: string[] = [];

    const originalCreateContext = zap.createContext.bind(zap);
    zap.createContext = async (name: string) => {
      order.push(`start:${name}`);
      const result = await originalCreateContext(name);
      order.push(`created:${name}`);
      return result;
    };
    const originalRemoveContext = zap.removeContext.bind(zap);
    zap.removeContext = async (name: string) => {
      order.push(`removed:${name}`);
      return originalRemoveContext(name);
    };

    await Promise.all([
      executor.execute({ scanId: first.scanId, targetId: first.targetId, targetUrl: first.targetUrl }),
      executor.execute({ scanId: second.scanId, targetId: second.targetId, targetUrl: second.targetUrl }),
    ]);

    // The first scan's context must be fully created AND removed before the
    // second scan's context creation ever starts — proving serialization,
    // not just that both eventually ran.
    const firstCreatedIndex = order.indexOf(`created:sentinelscan-scan-${first.scanId}`);
    const firstRemovedIndex = order.indexOf(`removed:sentinelscan-scan-${first.scanId}`);
    const secondStartIndex = order.indexOf(`start:sentinelscan-scan-${second.scanId}`);
    expect(firstCreatedIndex).toBeLessThan(firstRemovedIndex);
    expect(firstRemovedIndex).toBeLessThan(secondStartIndex);
  });
});
