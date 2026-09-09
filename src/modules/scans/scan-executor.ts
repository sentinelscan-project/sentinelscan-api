/**
 * The boundary between scan orchestration (this stage) and actually running a
 * scan (Stage 4).
 *
 * Nothing in Stage 3 calls a `ScanExecutor`. A scan created via `POST
 * /targets/:targetId/scans` is persisted with `status: "queued"` and stays
 * there — there is no background process, queue consumer, or timer anywhere
 * in this codebase that advances it. This interface exists purely so Stage 4
 * has a concrete shape to implement against (with OWASP ZAP) without Stage 3
 * needing to guess at ZAP's API.
 */

export interface ScanExecutionContext {
  scanId: string;
  targetId: string;
  /** The target's normalized root URL, for whatever Stage 4's executor scans. */
  targetUrl: string;
}

/**
 * Implemented in Stage 4. A real implementation is expected to call
 * `startScan`/`completeScan`/`failScan` (`scan.service.ts`) as execution
 * actually progresses — this interface only describes "run the scan",
 * nothing about how the resulting status transitions are recorded.
 */
export interface ScanExecutor {
  execute(context: ScanExecutionContext): Promise<void>;
}

/**
 * A deliberately inert placeholder implementation.
 *
 * It exists only to document, in code, that Stage 3 ships no working
 * executor — and to give anything that might be tempted to wire one up today
 * a loud failure instead of a quiet lie. `execute` always throws rather than
 * resolving: a scan must never be reported as having run, partially or
 * otherwise, when nothing actually scanned the target. This class is not
 * registered on the Fastify instance and no route calls it.
 */
export class NotImplementedScanExecutor implements ScanExecutor {
  execute(_context: ScanExecutionContext): Promise<void> {
    return Promise.reject(
      new Error(
        "No scan executor is implemented yet. OWASP ZAP integration arrives in Stage 4; " +
          "until then, scans are created and stay 'queued' with no execution mechanism.",
      ),
    );
  }
}
