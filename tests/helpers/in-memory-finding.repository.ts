import { randomUUID } from "node:crypto";
import type { NormalizedFinding } from "../../src/modules/findings/normalized-finding.js";
import type {
  FindingCounts,
  FindingInstanceRecord,
  FindingRecord,
  FindingRepository,
  FindingWithInstances,
  ListFindingsFilters,
  ListFindingsResult,
} from "../../src/repositories/finding.repository.js";

export interface InMemoryFindingRepository extends FindingRepository {
  readonly rows: Map<string, FindingWithInstances>;
  reset(): void;
  /** Test-only hook: makes the next `createMany` call reject, to exercise persistence-failure paths. */
  failNextCreateMany: boolean;
  /** Test-only: `scanId`s a caller's `Scan` is known to own, for `findByIdForOwner`'s join emulation. */
  scanOwners: Map<string, string>;
}

function clone(finding: FindingWithInstances): FindingWithInstances {
  return { ...finding, instances: finding.instances.map((instance) => ({ ...instance })) };
}

/**
 * In-memory {@link FindingRepository}.
 *
 * `findByIdForOwner` emulates the real Prisma implementation's join through
 * `Finding.scan.requestedById` using `scanOwners` (a test-populated map of
 * `scanId -> ownerId`) rather than actually joining anything — tests that
 * exercise findings authorization populate this the same way they'd seed a
 * scan row in `InMemoryScanRepository`.
 */
export function createInMemoryFindingRepository(): InMemoryFindingRepository {
  const rows = new Map<string, FindingWithInstances>();
  const scanOwners = new Map<string, string>();
  const state = {
    failNextCreateMany: false,
  };

  return {
    rows,
    scanOwners,

    get failNextCreateMany(): boolean {
      return state.failNextCreateMany;
    },
    set failNextCreateMany(value: boolean) {
      state.failNextCreateMany = value;
    },

    reset(): void {
      rows.clear();
      scanOwners.clear();
      state.failNextCreateMany = false;
    },

    async createMany(scanId: string, findings: NormalizedFinding[]): Promise<FindingWithInstances[]> {
      if (state.failNextCreateMany) {
        state.failNextCreateMany = false;
        throw new Error("Simulated finding persistence failure");
      }

      const now = new Date();
      const created: FindingWithInstances[] = findings.map((finding) => {
        const record: FindingRecord = {
          id: randomUUID(),
          scanId,
          title: finding.title,
          description: finding.description,
          severity: finding.severity,
          confidence: finding.confidence,
          category: finding.category,
          cweId: finding.cweId ?? null,
          wascId: finding.wascId ?? null,
          remediation: finding.remediation ?? null,
          references: finding.references,
          source: finding.source,
          sourceRuleId: finding.sourceRuleId ?? null,
          createdAt: now,
          updatedAt: now,
        };
        const instances: FindingInstanceRecord[] = finding.instances.map((instance) => ({
          id: randomUUID(),
          findingId: record.id,
          url: instance.url,
          method: instance.method ?? null,
          parameter: instance.parameter ?? null,
          attack: instance.attack ?? null,
          evidence: instance.evidence ?? null,
          createdAt: now,
        }));
        return { ...record, instances };
      });

      for (const finding of created) {
        rows.set(finding.id, finding);
      }
      return created.map(clone);
    },

    async listForScan(scanId: string, filters: ListFindingsFilters): Promise<ListFindingsResult> {
      const matches = [...rows.values()]
        .filter((finding) => finding.scanId === scanId)
        .filter((finding) => (filters.severity ? finding.severity === filters.severity : true))
        .filter((finding) => (filters.confidence ? finding.confidence === filters.confidence : true))
        .filter((finding) => (filters.category ? finding.category === filters.category : true))
        .filter((finding) => (filters.source ? finding.source === filters.source : true))
        .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());

      const page = matches.slice(filters.offset, filters.offset + filters.limit);
      const hasMore = matches.length > filters.offset + filters.limit;
      return { findings: page.map(clone), hasMore };
    },

    async findByIdForOwner(id: string, ownerId: string): Promise<FindingWithInstances | null> {
      const finding = rows.get(id);
      if (!finding) return null;
      if (scanOwners.get(finding.scanId) !== ownerId) return null;
      return clone(finding);
    },

    async countsForScan(scanId: string): Promise<FindingCounts> {
      const counts: FindingCounts = { critical: 0, high: 0, medium: 0, low: 0, informational: 0, total: 0 };
      for (const finding of rows.values()) {
        if (finding.scanId !== scanId) continue;
        counts[finding.severity] += 1;
        counts.total += 1;
      }
      return counts;
    },
  };
}
