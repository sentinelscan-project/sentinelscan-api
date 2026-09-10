import type { ScanExecutionContext, ScanExecutor } from "./scan-executor.js";
import type { ScanRepository } from "../../repositories/scan.repository.js";
import { ZapRequestError, type ZapClient } from "../../lib/zap-client.js";
import { assertTargetIsSafeToScan, TargetSafetyViolation } from "../../lib/target-safety.js";
import { buildOriginScopeRegex } from "../../lib/url.js";
import { completeScan, failScan, startScan } from "./scan.service.js";

export interface ZapScanExecutorConfig {
  crawlTimeoutMs: number;
  activeScanTimeoutMs: number;
  /** A ceiling across the whole execution, independent of the two phase timeouts above. */
  overallTimeoutMs: number;
  pollIntervalMs: number;
}

/** Internal signal: execution stopped because the scan was cancelled underneath it. */
class ScanCancelledSignal extends Error {}

/** Internal signal: a phase (or the whole scan) exceeded its configured timeout. */
class ScanPhaseTimeoutError extends Error {}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * A minimal in-process mutex limiting ZAP execution to one scan at a time.
 *
 * ZAP is a single shared daemon; running two scans through it concurrently
 * risks their spider state, active-scan state, session cookies, or scope
 * bleeding into each other. Rather than pretend the current implementation
 * isolates concurrent ZAP scans safely, this serializes them — a
 * concurrency limit of 1, correctness over throughput, exactly as this stage
 * calls for. See the README's "Concurrency & Isolation" section.
 */
class Mutex {
  private tail: Promise<void> = Promise.resolve();

  run<T>(fn: () => Promise<T>): Promise<T> {
    const result = this.tail.then(fn);
    this.tail = result.then(
      () => undefined,
      () => undefined,
    );
    return result;
  }
}

function safeMessage(err: unknown): string {
  if (err instanceof TargetSafetyViolation) return err.message;
  if (err instanceof ScanPhaseTimeoutError) return err.message;
  if (err instanceof ZapRequestError) return err.message;
  // Anything else is an error we did not author the message for — do not
  // surface it verbatim (it could contain unexpected internal detail); a
  // generic message is still useful and never leaks anything.
  return "An unexpected error occurred during scan execution";
}

/**
 * The real Stage 4 executor: `Scan` → target-safety check → scoped ZAP
 * context → spider → active scan → raw result summary → terminal state.
 *
 * Every lifecycle transition goes through `scan.service.ts`'s existing
 * atomic compare-and-swap functions (`startScan`/`completeScan`/`failScan`)
 * — this class never writes `Scan.status` directly. That is what makes the
 * "ZAP finishes at the same moment the user cancels" race safe without any
 * extra locking here: if `POST /scans/:id/cancel` wins the race, this
 * executor's later `completeScan` call simply fails its own CAS (the row is
 * no longer `running`) and is treated as "already terminal, nothing to do" —
 * never as an error, and never by overwriting `cancelled`.
 */
export class ZapScanExecutor implements ScanExecutor {
  private readonly mutex = new Mutex();

  constructor(
    private readonly zapClient: ZapClient,
    private readonly scanRepository: ScanRepository,
    private readonly config: ZapScanExecutorConfig,
  ) {}

  execute(context: ScanExecutionContext): Promise<void> {
    return this.mutex.run(() => this.runExclusive(context));
  }

  private async runExclusive(context: ScanExecutionContext): Promise<void> {
    const { scanId, targetId, targetUrl } = context;
    const zapContextName = `sentinelscan-scan-${scanId}`;
    const overallDeadline = Date.now() + this.config.overallTimeoutMs;

    console.info(`[ScanExecutor] execution starting scanId=${scanId} targetId=${targetId}`);

    try {
      await startScan(this.scanRepository, scanId);
    } catch {
      // Something already moved this scan out of "queued" — most likely it
      // was cancelled while waiting its turn on the mutex. Nothing to run.
      console.info(`[ScanExecutor] scanId=${scanId} left 'queued' before execution began; nothing to do`);
      return;
    }

    let zapContextCreated = false;

    try {
      await assertTargetIsSafeToScan(targetUrl);
      await this.throwIfCancelled(scanId);

      const contextId = await this.zapClient.createContext(zapContextName);
      zapContextCreated = true;
      await this.zapClient.includeInContext(zapContextName, buildOriginScopeRegex(targetUrl));

      await this.throwIfCancelled(scanId);
      console.info(`[ScanExecutor] scanId=${scanId} crawl started`);
      const spiderId = await this.zapClient.startSpider(targetUrl, zapContextName);
      await this.pollUntilComplete({
        scanId,
        phase: "crawl",
        timeoutMs: Math.min(this.config.crawlTimeoutMs, Math.max(0, overallDeadline - Date.now())),
        status: () => this.zapClient.spiderStatus(spiderId),
        onStop: () => this.zapClient.stopSpider(spiderId),
      });
      console.info(`[ScanExecutor] scanId=${scanId} crawl completed`);

      await this.throwIfCancelled(scanId);
      console.info(`[ScanExecutor] scanId=${scanId} active scan started`);
      const activeScanId = await this.zapClient.startActiveScan(targetUrl, contextId);
      await this.pollUntilComplete({
        scanId,
        phase: "active scan",
        timeoutMs: Math.min(this.config.activeScanTimeoutMs, Math.max(0, overallDeadline - Date.now())),
        status: () => this.zapClient.activeScanStatus(activeScanId),
        onStop: () => this.zapClient.stopActiveScan(activeScanId),
      });
      console.info(`[ScanExecutor] scanId=${scanId} active scan completed`);

      // Stage 4 proves the pipeline end to end; it does not persist findings.
      // A per-risk-level count is a safe, useful thing to log — never the
      // full alert bodies (which can contain response snippets/evidence).
      const summary = await this.zapClient.alertSummary(targetUrl);
      const summaryText = summary.length > 0 ? summary.map((s) => `${s.risk}=${s.count}`).join(", ") : "none";
      console.info(`[ScanExecutor] scanId=${scanId} raw results collected (${summaryText})`);

      await completeScan(this.scanRepository, scanId);
      console.info(`[ScanExecutor] scanId=${scanId} completed`);
    } catch (err) {
      await this.handleFailure(scanId, err);
    } finally {
      if (zapContextCreated) {
        try {
          await this.zapClient.removeContext(zapContextName);
        } catch (cleanupErr) {
          console.error(`[ScanExecutor] scanId=${scanId} failed to remove ZAP context during cleanup: ${safeMessage(cleanupErr)}`);
        }
      }
    }
  }

  private async throwIfCancelled(scanId: string): Promise<void> {
    const current = await this.scanRepository.findById(scanId);
    if (current?.status === "cancelled") {
      throw new ScanCancelledSignal();
    }
  }

  /**
   * Polls `status()` until it reaches 100, checking for cancellation on
   * every iteration. On cancellation or timeout, `onStop()` is invoked
   * best-effort (ZAP does not guarantee immediate termination; a failure to
   * stop it is logged and otherwise ignored, never escalated) before this
   * throws, so the caller unwinds through the same failure/cleanup path
   * either way.
   */
  private async pollUntilComplete(opts: {
    scanId: string;
    phase: string;
    timeoutMs: number;
    status: () => Promise<number>;
    onStop: () => Promise<void>;
  }): Promise<void> {
    const deadline = Date.now() + opts.timeoutMs;

    for (;;) {
      const current = await this.scanRepository.findById(opts.scanId);
      if (current?.status === "cancelled") {
        await opts.onStop().catch(() => undefined);
        throw new ScanCancelledSignal();
      }

      const progress = await opts.status();
      if (progress >= 100) {
        return;
      }

      if (Date.now() > deadline) {
        await opts.onStop().catch(() => undefined);
        throw new ScanPhaseTimeoutError(`Scan ${opts.phase} exceeded its timeout`);
      }

      await sleep(this.config.pollIntervalMs);
    }
  }

  private async handleFailure(scanId: string, err: unknown): Promise<void> {
    if (err instanceof ScanCancelledSignal) {
      console.info(`[ScanExecutor] scanId=${scanId} cancelled during execution`);
      return;
    }

    const message = safeMessage(err);
    console.error(`[ScanExecutor] scanId=${scanId} failed: ${message}`);

    try {
      await failScan(this.scanRepository, scanId, message);
    } catch {
      // Most likely: the scan was cancelled in the same instant this
      // failure was being recorded. The atomic CAS in `failScan` correctly
      // refuses to overwrite that terminal state — expected, not an error.
      console.info(`[ScanExecutor] scanId=${scanId} could not be marked failed (already terminal)`);
    }
  }
}
