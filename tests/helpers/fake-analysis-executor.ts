import type { AnalysisExecutionContext, AnalysisExecutor } from "../../src/modules/analysis/analysis-executor.js";

/**
 * An `AnalysisExecutor` that does nothing — mirrors `NoOpScanExecutor`'s
 * role for `ScanExecutor`. `requestAnalysis` (`analysis.service.ts`) fires
 * the configured executor in the background on every analysis request;
 * API-level tests care about the request/authorization/duplicate-prevention
 * behavior, not about a real (or even fake-but-active) AI provider call, so
 * they inject this instead — it records what it was called with and leaves
 * the `SecurityAnalysis` row exactly as `requestAnalysis` left it
 * (`status: "queued"`).
 */
export class NoOpAnalysisExecutor implements AnalysisExecutor {
  readonly calls: AnalysisExecutionContext[] = [];

  execute(context: AnalysisExecutionContext): Promise<void> {
    this.calls.push(context);
    return Promise.resolve();
  }

  reset(): void {
    this.calls.length = 0;
  }
}
