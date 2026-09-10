import type { ScanExecutionContext, ScanExecutor } from "../../src/modules/scans/scan-executor.js";

/**
 * A `ScanExecutor` that does nothing.
 *
 * `createScan` (`scan.service.ts`) fires the configured executor in the
 * background on every scan creation. Stage 3's and Stage 4's route/service
 * tests care about orchestration — creation, listing, ownership, the
 * lifecycle state machine itself — not about ZAP, so they inject this
 * instead of the real `ZapScanExecutor`: it records what it was called with
 * (useful for asserting the wiring is correct) and otherwise leaves every
 * scan exactly as `createScan` left it (`status: "queued"`), so Stage 3's
 * assertions about a freshly created scan stay deterministic instead of
 * racing a background executor that would otherwise try to reach a real ZAP
 * daemon and mutate scan state out from under the test.
 */
export class NoOpScanExecutor implements ScanExecutor {
  readonly calls: ScanExecutionContext[] = [];

  execute(context: ScanExecutionContext): Promise<void> {
    this.calls.push(context);
    return Promise.resolve();
  }

  reset(): void {
    this.calls.length = 0;
  }
}
