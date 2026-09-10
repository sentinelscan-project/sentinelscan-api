/**
 * The boundary between analysis orchestration (`analysis.service.ts`) and
 * actually running one — mirrors `modules/scans/scan-executor.ts`'s role for
 * scans.
 */
export interface AnalysisExecutionContext {
  analysisId: string;
  scanId: string;
  /** Captured at request time (the caller already looked up the scan's target while proving ownership) rather than re-fetched by the executor — see `SecurityAnalysisExecutor`'s module comment. */
  targetName: string;
  targetOrigin: string;
}

/**
 * A real implementation calls `startAnalysis`/`completeAnalysis`/`failAnalysis`
 * (`analysis.service.ts`) as execution actually progresses — this interface
 * only describes "run the analysis", nothing about how the resulting status
 * transitions are recorded.
 */
export interface AnalysisExecutor {
  execute(context: AnalysisExecutionContext): Promise<void>;
}
