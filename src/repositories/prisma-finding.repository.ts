import { getPrismaClient } from "../db/prisma.js";
import type { NormalizedFinding } from "../modules/findings/normalized-finding.js";
import type {
  FindingCounts,
  FindingRepository,
  FindingWithInstances,
  ListFindingsFilters,
  ListFindingsResult,
} from "./finding.repository.js";

const EMPTY_COUNTS: FindingCounts = {
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
  informational: 0,
  total: 0,
};

/**
 * Prisma-backed {@link FindingRepository} used at runtime.
 *
 * `createMany` wraps the finding + instance writes for an entire scan in one
 * `$transaction`: either every `Finding`/`FindingInstance` row for the scan
 * lands, or none does. This is deliberately the *only* thing the transaction
 * covers — ZAP execution happens well before this is ever called, and the
 * scan's own `completed`/`failed` transition (via `ScanRepository.transitionStatus`,
 * a separate atomic compare-and-swap) happens strictly after, in
 * `ZapScanExecutor`, once this promise has resolved. See the README's
 * "Persistence Lifecycle" section.
 */
export const prismaFindingRepository: FindingRepository = {
  async createMany(scanId: string, findings: NormalizedFinding[]): Promise<FindingWithInstances[]> {
    if (findings.length === 0) {
      return [];
    }

    const prisma = getPrismaClient();
    return prisma.$transaction(
      findings.map((finding) =>
        prisma.finding.create({
          data: {
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
            instances: {
              create: finding.instances.map((instance) => ({
                url: instance.url,
                method: instance.method ?? null,
                parameter: instance.parameter ?? null,
                attack: instance.attack ?? null,
                evidence: instance.evidence ?? null,
              })),
            },
          },
          include: { instances: true },
        }),
      ),
    );
  },

  async listForScan(scanId: string, filters: ListFindingsFilters): Promise<ListFindingsResult> {
    const where = {
      scanId,
      ...(filters.severity ? { severity: filters.severity } : {}),
      ...(filters.confidence ? { confidence: filters.confidence } : {}),
      ...(filters.category ? { category: filters.category } : {}),
      ...(filters.source ? { source: filters.source } : {}),
    };

    const findings = await getPrismaClient().finding.findMany({
      where,
      include: { instances: true },
      orderBy: { createdAt: "desc" },
      take: filters.limit + 1,
      skip: filters.offset,
    });

    const hasMore = findings.length > filters.limit;
    return { findings: hasMore ? findings.slice(0, filters.limit) : findings, hasMore };
  },

  findByIdForOwner(id: string, ownerId: string): Promise<FindingWithInstances | null> {
    return getPrismaClient().finding.findFirst({
      where: { id, scan: { requestedById: ownerId } },
      include: { instances: true },
    });
  },

  async countsForScan(scanId: string): Promise<FindingCounts> {
    const grouped = await getPrismaClient().finding.groupBy({
      by: ["severity"],
      where: { scanId },
      _count: { _all: true },
    });

    const counts = { ...EMPTY_COUNTS };
    for (const row of grouped) {
      counts[row.severity] = row._count._all;
      counts.total += row._count._all;
    }
    return counts;
  },
};
