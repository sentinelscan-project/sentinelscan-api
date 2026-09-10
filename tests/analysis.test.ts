import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";
import { FastifyInstance } from "fastify";
import { buildApp } from "../src/app.js";
import {
  createInMemoryUserRepository,
  createInMemoryVerificationTokenRepository,
  MockEmailService,
  type InMemoryUserRepository,
  type InMemoryVerificationTokenRepository,
} from "./helpers/in-memory-user.repository.js";
import {
  createInMemoryTargetRepository,
  type InMemoryTargetRepository,
} from "./helpers/in-memory-target.repository.js";
import {
  createInMemoryScanRepository,
  type InMemoryScanRepository,
} from "./helpers/in-memory-scan.repository.js";
import {
  createInMemoryFindingRepository,
  type InMemoryFindingRepository,
} from "./helpers/in-memory-finding.repository.js";
import {
  createInMemoryAnalysisRepository,
  type InMemoryAnalysisRepository,
} from "./helpers/in-memory-analysis.repository.js";
import { NoOpScanExecutor } from "./helpers/fake-scan-executor.js";
import { NoOpAnalysisExecutor } from "./helpers/fake-analysis-executor.js";
import type { NormalizedFinding } from "../src/modules/findings/normalized-finding.js";
import type { ScanRecord } from "../src/repositories/scan.repository.js";

const AUTH_COOKIE = "sentinelscan_token";

let app: FastifyInstance;
let users: InMemoryUserRepository;
let tokens: InMemoryVerificationTokenRepository;
let emailService: MockEmailService;
let targets: InMemoryTargetRepository;
let scans: InMemoryScanRepository;
let findings: InMemoryFindingRepository;
let analyses: InMemoryAnalysisRepository;
let scanExecutor: NoOpScanExecutor;
let analysisExecutor: NoOpAnalysisExecutor;

function cookieValue(response: { cookies: Array<Record<string, unknown>> }, name: string): string | undefined {
  const cookie = response.cookies.find((entry) => entry.name === name);
  return cookie ? String(cookie.value) : undefined;
}

function authedRequest(method: "GET" | "POST", url: string, cookie?: string) {
  return app.inject({
    method,
    url,
    ...(cookie ? { cookies: { [AUTH_COOKIE]: cookie } } : {}),
  });
}

interface Owner {
  cookie: string;
  ownerId: string;
  targetId: string;
}

async function registerOwner(email: string): Promise<Owner> {
  await app.inject({
    method: "POST",
    url: "/auth/register",
    payload: { email, name: "Analysis Requester", password: "Str0ngPassphrase" },
  });
  const sent = emailService.sentEmails[emailService.sentEmails.length - 1];
  if (!sent || sent.to !== email) {
    throw new Error(`No verification email was sent to ${email}`);
  }
  const verifyRes = await app.inject({
    method: "POST",
    url: "/auth/verify-email",
    payload: { token: sent.token },
  });
  const cookie = cookieValue(verifyRes, AUTH_COOKIE);
  if (!cookie) {
    throw new Error(`verification did not set an authentication cookie for ${email}`);
  }

  const created = await app.inject({
    method: "POST",
    url: "/targets",
    cookies: { [AUTH_COOKIE]: cookie },
    payload: { name: `Target for ${email}`, url: "https://staging.acme.example.com" },
  });
  const targetId = JSON.parse(created.payload).target.id as string;

  return { cookie, ownerId: [...targets.rows.values()].find((t) => t.id === targetId)!.ownerId, targetId };
}

function sampleFinding(overrides: Partial<NormalizedFinding> = {}): NormalizedFinding {
  return {
    title: "Cross Site Scripting (Reflected)",
    description: "Reflected XSS was detected.",
    severity: "high",
    confidence: "medium",
    category: "client-side",
    cweId: 79,
    wascId: 8,
    remediation: "Encode output.",
    references: ["https://owasp.org/xss"],
    source: "zap",
    sourceRuleId: "40012",
    instances: [{ url: "https://staging.acme.example.com/search?q=1", method: "GET", parameter: "q" }],
    ...overrides,
  };
}

/** Creates a scan for `owner` and forces it directly to `completed` (bypassing real ZAP execution — test-only convenience). */
async function seedCompletedScan(owner: Owner, normalizedFindings: NormalizedFinding[] = [sampleFinding()]): Promise<ScanRecord> {
  const scan = await scans.create({ targetId: owner.targetId, requestedById: owner.ownerId });
  const row = scans.rows.get(scan.id)!;
  row.status = "completed";
  row.startedAt = new Date();
  row.completedAt = new Date();
  analyses.scanOwners.set(scan.id, owner.ownerId);
  if (normalizedFindings.length > 0) {
    await findings.createMany(scan.id, normalizedFindings);
  }
  return row;
}

async function seedQueuedScan(owner: Owner): Promise<ScanRecord> {
  const scan = await scans.create({ targetId: owner.targetId, requestedById: owner.ownerId });
  analyses.scanOwners.set(scan.id, owner.ownerId);
  return scan;
}

beforeAll(async () => {
  users = createInMemoryUserRepository();
  tokens = createInMemoryVerificationTokenRepository();
  emailService = new MockEmailService();
  targets = createInMemoryTargetRepository();
  scans = createInMemoryScanRepository();
  findings = createInMemoryFindingRepository();
  analyses = createInMemoryAnalysisRepository();
  scanExecutor = new NoOpScanExecutor();
  analysisExecutor = new NoOpAnalysisExecutor();
  app = buildApp({
    userRepository: users,
    tokenRepository: tokens,
    emailService,
    targetRepository: targets,
    scanRepository: scans,
    findingRepository: findings,
    analysisRepository: analyses,
    scanExecutor,
    analysisExecutor,
  });
  await app.ready();
});

beforeEach(() => {
  users.reset();
  tokens.reset();
  emailService.reset();
  targets.reset();
  scans.reset();
  findings.reset();
  analyses.reset();
  scanExecutor.reset();
  analysisExecutor.reset();
});

afterAll(async () => {
  await app.close();
});

describe("POST /scans/:scanId/analyze — authentication", () => {
  it("rejects an unauthenticated request with 401", async () => {
    const response = await app.inject({ method: "POST", url: "/scans/00000000-0000-0000-0000-000000000000/analyze" });
    expect(response.statusCode).toBe(401);
  });
});

describe("POST /scans/:scanId/analyze — authorization", () => {
  it("returns an indistinguishable 404 for another user's scan and a nonexistent one", async () => {
    const owner = await registerOwner("analyze-owner-1@example.com");
    const other = await registerOwner("analyze-other-1@example.com");
    const scan = await seedCompletedScan(owner);

    const foreignResponse = await authedRequest("POST", `/scans/${scan.id}/analyze`, other.cookie);
    const nonexistentResponse = await authedRequest(
      "POST",
      "/scans/00000000-0000-0000-0000-000000000000/analyze",
      other.cookie,
    );

    expect(foreignResponse.statusCode).toBe(404);
    expect(nonexistentResponse.statusCode).toBe(404);
    expect(JSON.parse(foreignResponse.payload)).toEqual(JSON.parse(nonexistentResponse.payload));
  });
});

describe("POST /scans/:scanId/analyze — scan status", () => {
  it("rejects analysis of a scan that has not completed with 409 SCAN_NOT_COMPLETED", async () => {
    const owner = await registerOwner("analyze-queued@example.com");
    const scan = await seedQueuedScan(owner);

    const response = await authedRequest("POST", `/scans/${scan.id}/analyze`, owner.cookie);

    expect(response.statusCode).toBe(409);
    expect(JSON.parse(response.payload).code).toBe("SCAN_NOT_COMPLETED");
  });
});

describe("POST /scans/:scanId/analyze — success", () => {
  it("creates a queued SecurityAnalysis and dispatches the executor", async () => {
    const owner = await registerOwner("analyze-success@example.com");
    const scan = await seedCompletedScan(owner);

    const response = await authedRequest("POST", `/scans/${scan.id}/analyze`, owner.cookie);

    expect(response.statusCode).toBe(202);
    const body = JSON.parse(response.payload);
    expect(body.analysis.scanId).toBe(scan.id);
    expect(body.analysis.status).toBe("queued");
    expect(body.analysis.promptVersion).toBe("1.0");
    expect(analysisExecutor.calls).toHaveLength(1);
    expect(analysisExecutor.calls[0].scanId).toBe(scan.id);
    expect(analysisExecutor.calls[0].targetOrigin).toBe("https://staging.acme.example.com");
  });

  it("never exposes provider API keys or internal fields in the response", async () => {
    const owner = await registerOwner("analyze-no-leak@example.com");
    const scan = await seedCompletedScan(owner);

    const response = await authedRequest("POST", `/scans/${scan.id}/analyze`, owner.cookie);
    const body = JSON.parse(response.payload);

    expect(JSON.stringify(body)).not.toMatch(/apikey|api_key|sk-ant/i);
  });
});

describe("POST /scans/:scanId/analyze — duplicate prevention", () => {
  it("rejects a second analyze request for the same scan with 409 ANALYSIS_ALREADY_EXISTS", async () => {
    const owner = await registerOwner("analyze-duplicate@example.com");
    const scan = await seedCompletedScan(owner);

    const first = await authedRequest("POST", `/scans/${scan.id}/analyze`, owner.cookie);
    const second = await authedRequest("POST", `/scans/${scan.id}/analyze`, owner.cookie);

    expect(first.statusCode).toBe(202);
    expect(second.statusCode).toBe(409);
    expect(JSON.parse(second.payload).code).toBe("ANALYSIS_ALREADY_EXISTS");
    expect(analysisExecutor.calls).toHaveLength(1);
  });
});

describe("GET /scans/:scanId/analysis", () => {
  it("rejects an unauthenticated request with 401", async () => {
    const response = await app.inject({ method: "GET", url: "/scans/00000000-0000-0000-0000-000000000000/analysis" });
    expect(response.statusCode).toBe(401);
  });

  it("returns 404 ANALYSIS_NOT_FOUND for a completed scan with no analysis requested yet", async () => {
    const owner = await registerOwner("no-analysis-yet@example.com");
    const scan = await seedCompletedScan(owner);

    const response = await authedRequest("GET", `/scans/${scan.id}/analysis`, owner.cookie);

    expect(response.statusCode).toBe(404);
    expect(JSON.parse(response.payload).code).toBe("ANALYSIS_NOT_FOUND");
  });

  it("returns an indistinguishable 404 for another user's scan and a nonexistent one", async () => {
    const owner = await registerOwner("scan-analysis-owner@example.com");
    const other = await registerOwner("scan-analysis-other@example.com");
    const scan = await seedCompletedScan(owner);
    await authedRequest("POST", `/scans/${scan.id}/analyze`, owner.cookie);

    const foreignResponse = await authedRequest("GET", `/scans/${scan.id}/analysis`, other.cookie);
    const nonexistentResponse = await authedRequest(
      "GET",
      "/scans/00000000-0000-0000-0000-000000000000/analysis",
      other.cookie,
    );

    expect(foreignResponse.statusCode).toBe(404);
    expect(nonexistentResponse.statusCode).toBe(404);
    expect(JSON.parse(foreignResponse.payload)).toEqual(JSON.parse(nonexistentResponse.payload));
  });

  it("returns the analysis with its assessments/correlations once completed", async () => {
    const owner = await registerOwner("completed-analysis@example.com");
    const scan = await seedCompletedScan(owner);
    const created = await analyses.create({ scanId: scan.id, promptVersion: "1.0" });
    await analyses.transitionStatus(created.id, "queued", { status: "running" });
    const findingId = [...findings.rows.values()][0].id;
    await analyses.completeAnalysis(created.id, {
      model: "claude-sonnet-5",
      overallRisk: "high",
      executiveSummary: "One high-severity finding requires attention.",
      methodologySummary: null,
      limitations: null,
      completedAt: new Date(),
      assessments: [
        {
          findingId,
          priority: "high",
          riskAssessment: "Exploitable.",
          confidence: "high",
          reasoning: "Clear evidence.",
          businessImpact: null,
          technicalImpact: null,
          remediationPriority: "high",
          falsePositiveLikelihood: "low",
        },
      ],
      correlations: [],
    });

    const response = await authedRequest("GET", `/scans/${scan.id}/analysis`, owner.cookie);

    expect(response.statusCode).toBe(200);
    const body = JSON.parse(response.payload);
    expect(body.analysis.status).toBe("completed");
    expect(body.analysis.overallRisk).toBe("high");
    expect(body.analysis.assessments).toHaveLength(1);
    expect(body.analysis.assessments[0].findingId).toBe(findingId);
  });
});

describe("GET /analysis/:id", () => {
  it("rejects an unauthenticated request with 401", async () => {
    const response = await app.inject({ method: "GET", url: "/analysis/00000000-0000-0000-0000-000000000000" });
    expect(response.statusCode).toBe(401);
  });

  it("returns the analysis when the caller owns its scan", async () => {
    const owner = await registerOwner("analysis-detail@example.com");
    const scan = await seedCompletedScan(owner);
    const created = await analyses.create({ scanId: scan.id, promptVersion: "1.0" });

    const response = await authedRequest("GET", `/analysis/${created.id}`, owner.cookie);

    expect(response.statusCode).toBe(200);
    expect(JSON.parse(response.payload).analysis.id).toBe(created.id);
  });

  it("returns an indistinguishable 404 for another user's analysis and a nonexistent one", async () => {
    const owner = await registerOwner("analysis-detail-owner@example.com");
    const other = await registerOwner("analysis-detail-other@example.com");
    const scan = await seedCompletedScan(owner);
    const created = await analyses.create({ scanId: scan.id, promptVersion: "1.0" });

    const foreignResponse = await authedRequest("GET", `/analysis/${created.id}`, other.cookie);
    const nonexistentResponse = await authedRequest(
      "GET",
      "/analysis/00000000-0000-0000-0000-000000000000",
      other.cookie,
    );

    expect(foreignResponse.statusCode).toBe(404);
    expect(nonexistentResponse.statusCode).toBe(404);
    expect(JSON.parse(foreignResponse.payload)).toEqual(JSON.parse(nonexistentResponse.payload));
  });
});
