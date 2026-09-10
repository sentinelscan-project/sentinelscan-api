import type {
  FindingCategory as FindingCategoryType,
} from "../modules/findings/finding-category.js";
import type { NormalizedFinding } from "../modules/findings/normalized-finding.js";

/**
 * Persistence boundary for `Finding`/`FindingInstance`.
 *
 * `findByIdForOwner` follows the ownership-scoped-query pattern established
 * in Stage 2/3 (`TargetRepository`/`ScanRepository`): ownership is enforced
 * as part of the query itself (a join through `Finding.scan.requestedById`),
 * not fetched-then-checked. `listForScan`/`countsForScan` take an already-
 * verified `scanId` instead — `finding.service.ts` proves the caller owns
 * that scan (via `ScanRepository.findByIdForOwner`, reusing Stage 3's own
 * ownership check) before ever calling them, so a second ownership filter on
 * the findings query itself would be redundant.
 */

export type FindingSeverity = "critical" | "high" | "medium" | "low" | "informational";
export type FindingConfidence = "high" | "medium" | "low" | "unknown";
export type FindingCategory = FindingCategoryType;

export interface FindingInstanceRecord {
  id: string;
  findingId: string;
  url: string;
  method: string | null;
  parameter: string | null;
  attack: string | null;
  evidence: string | null;
  createdAt: Date;
}

export interface FindingRecord {
  id: string;
  scanId: string;
  title: string;
  description: string;
  severity: FindingSeverity;
  confidence: FindingConfidence;
  category: string;
  cweId: number | null;
  wascId: number | null;
  remediation: string | null;
  references: unknown;
  source: string;
  sourceRuleId: string | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface FindingWithInstances extends FindingRecord {
  instances: FindingInstanceRecord[];
}

export interface ListFindingsFilters {
  severity?: FindingSeverity;
  confidence?: FindingConfidence;
  category?: string;
  source?: string;
  limit: number;
  offset: number;
}

export interface ListFindingsResult {
  findings: FindingWithInstances[];
  hasMore: boolean;
}

/** Counts derived from persisted findings — never trusted from anywhere else (e.g. ZAP's own alert summary). */
export interface FindingCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  informational: number;
  total: number;
}

export interface FindingRepository {
  /**
   * Atomically persists every finding (and its instances) produced for one
   * scan. All-or-nothing: if any row fails to write, nothing for this call
   * is committed. Never called twice for the same `scanId` in normal
   * operation (each scan executes, and is normalized/persisted, exactly
   * once), so the `(scanId, source, sourceRuleId)` uniqueness this relies on
   * is not a concurrency guard so much as a defensive, documented invariant
   * — see the README's "Deduplication Strategy" section.
   */
  createMany(scanId: string, findings: NormalizedFinding[]): Promise<FindingWithInstances[]>;
  listForScan(scanId: string, filters: ListFindingsFilters): Promise<ListFindingsResult>;
  findByIdForOwner(id: string, ownerId: string): Promise<FindingWithInstances | null>;
  /** Unfiltered — always the scan's full severity breakdown, regardless of any list filter in use. */
  countsForScan(scanId: string): Promise<FindingCounts>;
}

/**
 * The only finding shape that may cross the API boundary. No raw scanner
 * response, no internal Prisma field ever leaks through this.
 */
export interface PublicFindingInstance {
  id: string;
  url: string;
  method: string | null;
  parameter: string | null;
  attack: string | null;
  evidence: string | null;
  createdAt: string;
}

export interface PublicFinding {
  id: string;
  scanId: string;
  title: string;
  description: string;
  severity: FindingSeverity;
  confidence: FindingConfidence;
  category: string;
  cweId: number | null;
  wascId: number | null;
  remediation: string | null;
  references: string[];
  source: string;
  sourceRuleId: string | null;
  createdAt: string;
  updatedAt: string;
  instances: PublicFindingInstance[];
}

/** Exported for reuse by `modules/analysis/` — the same `Finding.references` JSON shape feeds AI analysis input. */
export function toReferenceList(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.filter((entry): entry is string => typeof entry === "string");
}

export function toPublicFinding(finding: FindingWithInstances): PublicFinding {
  return {
    id: finding.id,
    scanId: finding.scanId,
    title: finding.title,
    description: finding.description,
    severity: finding.severity,
    confidence: finding.confidence,
    category: finding.category,
    cweId: finding.cweId,
    wascId: finding.wascId,
    remediation: finding.remediation,
    references: toReferenceList(finding.references),
    source: finding.source,
    sourceRuleId: finding.sourceRuleId,
    createdAt: finding.createdAt.toISOString(),
    updatedAt: finding.updatedAt.toISOString(),
    instances: finding.instances.map((instance) => ({
      id: instance.id,
      url: instance.url,
      method: instance.method,
      parameter: instance.parameter,
      attack: instance.attack,
      evidence: instance.evidence,
      createdAt: instance.createdAt.toISOString(),
    })),
  };
}
