import { NotFoundError } from "../../lib/errors.js";
import type { ScanRepository } from "../../repositories/scan.repository.js";
import type {
  FindingCounts,
  FindingRepository,
  FindingWithInstances,
  ListFindingsFilters,
} from "../../repositories/finding.repository.js";
import type { ListFindingsQuery } from "./finding.schemas.js";

/** Identical whether `id` does not exist at all or belongs to a different user — same rule as `scan.service.ts`. */
function scanNotFoundError(): NotFoundError {
  return new NotFoundError("Scan not found", "SCAN_NOT_FOUND");
}

function findingNotFoundError(): NotFoundError {
  return new NotFoundError("Finding not found", "FINDING_NOT_FOUND");
}

function toRepositoryFilters(query: ListFindingsQuery): ListFindingsFilters {
  return {
    severity: query.severity,
    confidence: query.confidence,
    category: query.category,
    source: query.source,
    limit: query.limit,
    offset: query.offset,
  };
}

export interface ListFindingsForScanResult {
  findings: FindingWithInstances[];
  hasMore: boolean;
  counts: FindingCounts;
}

/**
 * Findings for one scan, scoped to `ownerId`.
 *
 * Ownership is proven exactly once, via `scanRepository.findByIdForOwner` —
 * the same ownership-scoped lookup `scan.service.ts`'s `getScan` uses — and
 * only afterwards does this read from `findingRepository`, by `scanId` alone
 * (no redundant owner filter on the findings query itself; see the doc
 * comment on `FindingRepository`). A scan that doesn't exist and one that
 * belongs to someone else are indistinguishable: both raise the same
 * `SCAN_NOT_FOUND`.
 *
 * `counts` is always the scan's unfiltered severity breakdown (derived from
 * the persisted `Finding` rows, never from ZAP's own alert-summary log),
 * regardless of any `severity`/`confidence`/`category`/`source` filter
 * applied to `findings` itself.
 */
export async function listFindingsForScan(
  scanRepository: ScanRepository,
  findingRepository: FindingRepository,
  ownerId: string,
  scanId: string,
  query: ListFindingsQuery,
): Promise<ListFindingsForScanResult> {
  const scan = await scanRepository.findByIdForOwner(scanId, ownerId);
  if (!scan) {
    throw scanNotFoundError();
  }

  const [{ findings, hasMore }, counts] = await Promise.all([
    findingRepository.listForScan(scanId, toRepositoryFilters(query)),
    findingRepository.countsForScan(scanId),
  ]);

  return { findings, hasMore, counts };
}

/**
 * One finding by id, scoped to `ownerId` via a join through its scan's
 * `requestedById` (`FindingRepository.findByIdForOwner`) — there is no
 * scanId in this URL to pre-validate ownership through, unlike
 * `listFindingsForScan` above.
 */
export async function getFinding(
  findingRepository: FindingRepository,
  ownerId: string,
  id: string,
): Promise<FindingWithInstances> {
  const finding = await findingRepository.findByIdForOwner(id, ownerId);
  if (!finding) {
    throw findingNotFoundError();
  }
  return finding;
}
