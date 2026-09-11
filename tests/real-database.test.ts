import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { getPrismaClient, disconnectPrisma } from "../src/db/prisma.js";
import { prismaUserRepository } from "../src/repositories/prisma-user.repository.js";
import { prismaVerificationTokenRepository } from "../src/repositories/token.repository.js";
import { prismaTargetRepository } from "../src/repositories/prisma-target.repository.js";
import { prismaScanRepository } from "../src/repositories/prisma-scan.repository.js";
import { prismaFindingRepository } from "../src/repositories/prisma-finding.repository.js";
import { prismaAnalysisRepository } from "../src/repositories/prisma-analysis.repository.js";
import type { NormalizedFinding } from "../src/modules/findings/normalized-finding.js";
import type { SecurityAnalysisOutput } from "../src/modules/analysis/security-analysis-output.schema.js";
import { startScan, completeScan } from "../src/modules/scans/scan.service.js";

const TEST_DB_URL =
  process.env.TEST_DATABASE_URL ||
  (process.env.DATABASE_URL && !process.env.DATABASE_URL.includes("ep-sample-pooler")
    ? process.env.DATABASE_URL
    : "postgresql://postgres:postgres@localhost:54322/sentinelscan_e2e");

describe("Stage 8: Real Database Lifecycle Verification", () => {
  let isDbAvailable = false;
  const originalDbUrl = process.env.DATABASE_URL;

  beforeAll(async () => {
    process.env.DATABASE_URL = TEST_DB_URL;
    try {
      const prisma = getPrismaClient();
      await prisma.$queryRaw`SELECT 1`;
      isDbAvailable = true;
    } catch (err) {
      console.warn(`[Stage 8 Real Database] Database unavailable at ${TEST_DB_URL}:`, err);
      isDbAvailable = false;
    }
  });

  afterAll(async () => {
    await disconnectPrisma();
    if (originalDbUrl) {
      process.env.DATABASE_URL = originalDbUrl;
    }
  });

  it("verifies the full database lifecycle using real PostgreSQL and Prisma schema", async () => {
    if (!isDbAvailable) {
      console.warn("[Stage 8 Real Database] SKIPPED — PostgreSQL database not reachable");
      return;
    }

    const prisma = getPrismaClient();

    // 1. Create User
    const testEmail = `stage8-analyst-${Date.now()}@sentinelscan.example.com`;
    const user = await prismaUserRepository.create({
      email: testEmail,
      name: "Stage 8 Analyst",
      passwordHash: "$2b$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ012",
    });
    expect(user.id).toBeDefined();
    expect(user.email).toBe(testEmail);
    expect(user.emailVerified).toBe(false);

    // 2. Verification Token
    const tokenHash = `token-hash-${Date.now()}-${Math.random().toString(36).slice(2)}`;
    const token = await prismaVerificationTokenRepository.create(
      user.id,
      tokenHash,
      new Date(Date.now() + 3600_000),
    );
    expect(token.id).toBeDefined();
    expect(token.userId).toBe(user.id);

    // Verify User Email
    const verifiedUser = await prismaUserRepository.setEmailVerified(user.id, true);
    expect(verifiedUser?.emailVerified).toBe(true);

    // 3. Create Target
    const target = await prismaTargetRepository.create({
      name: "Staging E2E Target",
      url: "https://staging.example.com",
      description: "Real database integration verification target",
      ownerId: user.id,
    });
    expect(target.id).toBeDefined();
    expect(target.ownerId).toBe(user.id);

    // 4. Create Scan & Lifecycle Transitions
    const scan = await prismaScanRepository.create({
      targetId: target.id,
      requestedById: user.id,
    });
    expect(scan.id).toBeDefined();
    expect(scan.status).toBe("queued");

    const startedScan = await startScan(prismaScanRepository, scan.id);
    expect(startedScan.status).toBe("running");

    // 5. Persist Normalized Findings with Instances
    const normalizedFindings: NormalizedFinding[] = [
      {
        title: "Cross Site Scripting (Reflected)",
        description: "Reflected XSS occurs when user input is returned without sanitization.",
        severity: "high",
        confidence: "high",
        category: "client-side",
        cweId: 79,
        wascId: 8,
        remediation: "Apply context-aware contextual encoding.",
        references: ["https://owasp.org/www-community/attacks/xss/"],
        source: "zap",
        sourceRuleId: "40012",
        instances: [
          {
            url: "https://staging.example.com/search?q=test",
            method: "GET",
            parameter: "q",
            attack: "<script>alert(1)</script>",
            evidence: "<script>alert(1)</script>",
          },
        ],
      },
      {
        title: "Missing Anti-clickjacking Header",
        description: "X-Frame-Options or Content-Security-Policy frame-ancestors is missing.",
        severity: "medium",
        confidence: "medium",
        category: "security-header",
        cweId: 1021,
        wascId: 15,
        remediation: "Set X-Frame-Options: DENY or CSP frame-ancestors 'none'.",
        references: ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"],
        source: "zap",
        sourceRuleId: "10020",
        instances: [
          {
            url: "https://staging.example.com/",
            method: "GET",
            parameter: undefined,
            attack: undefined,
            evidence: undefined,
          },
        ],
      },
    ];

    const persistedFindings = await prismaFindingRepository.createMany(scan.id, normalizedFindings);
    expect(persistedFindings.length).toBe(2);

    const xssFinding = persistedFindings.find((f) => f.title === "Cross Site Scripting (Reflected)");
    const clickjackFinding = persistedFindings.find((f) => f.title === "Missing Anti-clickjacking Header");
    expect(xssFinding).toBeDefined();
    expect(clickjackFinding).toBeDefined();
    expect(xssFinding!.instances.length).toBe(1);
    expect(xssFinding!.instances[0].evidence).toBe("<script>alert(1)</script>");

    // Complete Scan
    const completedScan = await completeScan(prismaScanRepository, scan.id);
    expect(completedScan.status).toBe("completed");

    // Verify Counts & Ownership Listing
    const counts = await prismaFindingRepository.countsForScan(scan.id);
    expect(counts.total).toBe(2);
    expect(counts.high).toBe(1);
    expect(counts.medium).toBe(1);

    const ownerFinding = await prismaFindingRepository.findByIdForOwner(xssFinding!.id, user.id);
    expect(ownerFinding).not.toBeNull();
    expect(ownerFinding?.id).toBe(xssFinding!.id);

    // 6. Persist Security Analysis, Assessments, and Correlations
    const analysisOutput: SecurityAnalysisOutput = {
      overallRisk: "high",
      executiveSummary: "Assessment identified reflected XSS which can lead to session hijacking.",
      methodologySummary: "Correlated scanner findings with threat analysis.",
      keyRisks: ["Reflected XSS combined with a missing anti-clickjacking header"],
      findingAssessments: [
        {
          findingId: xssFinding!.id,
          priority: "high",
          riskAssessment: "Exploitation allows script execution in victim browser context.",
          confidence: "high",
          reasoning: "Payload reflects verbatim in response.",
          businessImpact: "Reputational damage and potential account compromise.",
          technicalImpact: "Arbitrary script execution, DOM access.",
          remediationPriority: "high",
          falsePositiveLikelihood: "low",
        },
        {
          findingId: clickjackFinding!.id,
          priority: "medium",
          riskAssessment: "Site can be framed by malicious third party.",
          confidence: "high",
          reasoning: "Response lacks X-Frame-Options header.",
          businessImpact: "User deception via framing.",
          technicalImpact: "UI redressing attack.",
          remediationPriority: "medium",
          falsePositiveLikelihood: "low",
        },
      ],
      correlations: [
        {
          findingAId: xssFinding!.id,
          findingBId: clickjackFinding!.id,
          relationship: "amplifies-risk",
          confidence: "medium",
          explanation: "Combining framing with reflected input increases susceptibility to social engineering.",
        },
      ],
      remediationPriorities: [
        "Implement context-sensitive output encoding for the search query parameter",
        "Add Content-Security-Policy frame-ancestors directive",
      ],
      limitations: [],
    };

    const createdAnalysis = await prismaAnalysisRepository.create({
      scanId: scan.id,
      promptVersion: "1.0.0",
    });
    expect(createdAnalysis.id).toBeDefined();
    expect(createdAnalysis.status).toBe("queued");

    await prismaAnalysisRepository.transitionStatus(createdAnalysis.id, "queued", {
      status: "running",
    });

    const completedAnalysis = await prismaAnalysisRepository.completeAnalysis(createdAnalysis.id, {
      model: "gemini-2.5-flash",
      overallRisk: analysisOutput.overallRisk,
      executiveSummary: analysisOutput.executiveSummary,
      methodologySummary: analysisOutput.methodologySummary ?? null,
      limitations: null,
      completedAt: new Date(),
      assessments: analysisOutput.findingAssessments.map((a) => ({
        findingId: a.findingId,
        priority: a.priority,
        riskAssessment: a.riskAssessment,
        confidence: a.confidence,
        reasoning: a.reasoning,
        businessImpact: a.businessImpact ?? null,
        technicalImpact: a.technicalImpact ?? null,
        remediationPriority: a.remediationPriority,
        falsePositiveLikelihood: a.falsePositiveLikelihood,
      })),
      correlations: (analysisOutput.correlations ?? []).map((c) => ({
        findingAId: c.findingAId,
        findingBId: c.findingBId,
        relationship: c.relationship,
        confidence: c.confidence,
        explanation: c.explanation,
      })),
    });
    expect(completedAnalysis).not.toBeNull();
    expect(completedAnalysis?.status).toBe("completed");

    const analysisWithResults = await prismaAnalysisRepository.findByIdForOwner(createdAnalysis.id, user.id);
    expect(analysisWithResults).not.toBeNull();
    expect(analysisWithResults?.assessments.length).toBe(2);
    expect(analysisWithResults?.correlations.length).toBe(1);
    expect(analysisWithResults?.correlations[0].findingAId).toBe(xssFinding!.id);
    expect(analysisWithResults?.correlations[0].findingBId).toBe(clickjackFinding!.id);

    // 7. Verify Audit Trail Preservation (onDelete: Restrict)
    // Deleting target directly MUST fail with a foreign key constraint violation
    // because scans_targetId_fkey is onDelete: Restrict by architectural design.
    await expect(prisma.target.delete({ where: { id: target.id } })).rejects.toThrow();

    // 8. Clean up in reverse dependency order to leave the database clean
    // Deleting securityAnalysis cascades to assessments and correlations
    await prisma.securityAnalysis.delete({ where: { id: createdAnalysis.id } });
    await prisma.findingInstance.deleteMany({ where: { finding: { scanId: scan.id } } });
    await prisma.finding.deleteMany({ where: { scanId: scan.id } });
    await prisma.scan.delete({ where: { id: scan.id } });
    await prisma.target.delete({ where: { id: target.id } });
    await prisma.emailVerificationToken.deleteMany({ where: { userId: user.id } });
    await prisma.user.delete({ where: { id: user.id } });
  });
});
