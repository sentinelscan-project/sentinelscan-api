import { vi } from "vitest";
import { ZapRequestError, type ZapAlertSummary, type ZapClient, type ZapHealth } from "../../src/lib/zap-client.js";

/**
 * A hand-written `ZapClient` test double with fully controllable, synchronous
 * behavior — no real HTTP, no real timing. Progress is driven by queues
 * (`spiderProgress`/`activeScanProgress`): each status call shifts the next
 * value off the front, repeating the last value once the queue is drained,
 * so a test can script "45, then 100" or "always 50" (to force a timeout)
 * without depending on wall-clock time.
 *
 * Any status() call can also carry a side effect (`onSpiderStatusPoll`, etc.)
 * — that is how the cancellation-racing-completion tests simulate "the user
 * cancels at exactly this moment" deterministically.
 */
export class FakeZapClient implements ZapClient {
  readonly createContextCalls: string[] = [];
  readonly includeInContextCalls: Array<{ contextName: string; regex: string }> = [];
  readonly removeContextCalls: string[] = [];
  readonly startSpiderCalls: Array<{ url: string; contextName: string }> = [];
  readonly stopSpiderCalls: string[] = [];
  readonly startActiveScanCalls: Array<{ url: string; contextId: string }> = [];
  readonly stopActiveScanCalls: string[] = [];
  readonly alertSummaryCalls: string[] = [];

  healthResult: ZapHealth = { reachable: true, version: "fake-2.14.0" };

  spiderProgress: number[] = [100];
  activeScanProgress: number[] = [100];
  alertSummaryResult: ZapAlertSummary[] = [{ risk: "Medium", count: 1 }];

  failCreateContext = false;
  failStartSpider = false;
  failStartActiveScan = false;
  failSpiderStatus = false;
  failActiveScanStatus = false;

  onSpiderStatusPoll?: () => void | Promise<void>;
  onActiveScanStatusPoll?: () => void | Promise<void>;
  onAlertSummary?: () => void | Promise<void>;

  private nextId = 0;

  health = vi.fn(async (): Promise<ZapHealth> => this.healthResult);

  async createContext(contextName: string): Promise<string> {
    this.createContextCalls.push(contextName);
    if (this.failCreateContext) {
      throw new ZapRequestError("ZAP is unreachable");
    }
    return `ctx-${contextName}`;
  }

  async includeInContext(contextName: string, regex: string): Promise<void> {
    this.includeInContextCalls.push({ contextName, regex });
  }

  async removeContext(contextName: string): Promise<void> {
    this.removeContextCalls.push(contextName);
  }

  async startSpider(url: string, contextName: string): Promise<string> {
    this.startSpiderCalls.push({ url, contextName });
    if (this.failStartSpider) {
      throw new ZapRequestError("Failed to start spider");
    }
    this.nextId += 1;
    return `spider-${this.nextId}`;
  }

  async spiderStatus(_scanId: string): Promise<number> {
    if (this.onSpiderStatusPoll) await this.onSpiderStatusPoll();
    if (this.failSpiderStatus) {
      throw new ZapRequestError("Spider status check failed");
    }
    return this.spiderProgress.length > 1 ? (this.spiderProgress.shift() as number) : this.spiderProgress[0];
  }

  async stopSpider(scanId: string): Promise<void> {
    this.stopSpiderCalls.push(scanId);
  }

  async startActiveScan(url: string, contextId: string): Promise<string> {
    this.startActiveScanCalls.push({ url, contextId });
    if (this.failStartActiveScan) {
      throw new ZapRequestError("Failed to start active scan");
    }
    this.nextId += 1;
    return `ascan-${this.nextId}`;
  }

  async activeScanStatus(_scanId: string): Promise<number> {
    if (this.onActiveScanStatusPoll) await this.onActiveScanStatusPoll();
    if (this.failActiveScanStatus) {
      throw new ZapRequestError("Active scan status check failed");
    }
    return this.activeScanProgress.length > 1
      ? (this.activeScanProgress.shift() as number)
      : this.activeScanProgress[0];
  }

  async stopActiveScan(scanId: string): Promise<void> {
    this.stopActiveScanCalls.push(scanId);
  }

  async alertSummary(baseUrl: string): Promise<ZapAlertSummary[]> {
    this.alertSummaryCalls.push(baseUrl);
    if (this.onAlertSummary) await this.onAlertSummary();
    return this.alertSummaryResult;
  }
}
