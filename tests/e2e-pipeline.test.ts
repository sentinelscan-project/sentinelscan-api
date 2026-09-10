import { describe, it, expect, beforeAll, afterAll } from "vitest";
import type { FastifyInstance } from "fastify";
import { buildApp } from "../src/app.js";
import {
  createInMemoryUserRepository,
  createInMemoryVerificationTokenRepository,
  MockEmailService,
} from "./helpers/in-memory-user.repository.js";
import { createInMemoryTargetRepository } from "./helpers/in-memory-target.repository.js";
import { createInMemoryScanRepository } from "./helpers/in-memory-scan.repository.js";
import { createInMemoryFindingRepository } from "./helpers/in-memory-finding.repository.js";
import { createInMemoryAnalysisRepository } from "./helpers/in-memory-analysis.repository.js";
import { ZapScanExecutor } from "../src/modules/scans/zap-scan-executor.js";
import { FakeZapClient } from "./helpers/fake-zap-client.js";
import { SecurityAnalysisExecutor } from "../src/modules/analysis/security-analysis-executor.js";
import { FakeSecurityAnalysisModel } from "./helpers/fake-security-analysis-model.js";
import type { ZapRawAlert } from "../src/modules/findings/zap/zap-alert.js";

const AUTH_COOKIE = "sentinelscan_token";

describe("Stage 8: Full End-to-End Pipeline Integration", () => {
  let app: FastifyInstance;
  let fakeZap: FakeZapClient;
  let fakeAiModel: FakeSecurityAnalysisModel;

  const users = createInMemoryUserRepository();
  const tokens = createInMemoryVerificationTokenRepository();
  const emailService = new MockEmailService();
  const targets = createInMemoryTargetRepository();
  const scans = createInMemoryScanRepository();
  const findings = createInMemoryFindingRepository();
  const analyses = createInMemoryAnalysisRepository();

  beforeAll(() => {
    fakeZap = new FakeZapClient();
    fakeAiModel = new FakeSecurityAnalysisModel();

    const scanExecutor = new ZapScanExecutor(fakeZap, scans, findings, {
      crawlTimeoutMs: 5000,
      activeScanTimeoutMs: 5000,
      overallTimeoutMs: 10000,
      pollIntervalMs: 1,
    });

    const analysisExecutor = new SecurityAnalysisExecutor(fakeAiModel, analyses, findings, {
      modelName: "gemini-2.5-flash",
    });

    app = buildApp({
      userRepository: users,
      tokenRepository: tokens,
      emailService,
      targetRepository: targets,
      scanRepository: scans,
      findingRepository: findings,
      analysisRepository: analyses,
      zapClient: fakeZap,
      scanExecutor,
      analysisModel: fakeAiModel,
      analysisExecutor,
    });
  });

  afterAll(async () => {
    await app.close();
  });

  function getCookie(response: { cookies: Array<Record<string, unknown>> }): string {
    const entry = response.cookies.find((c) => c.name === AUTH_COOKIE);
    return entry ? String(entry.value) : "";
  }

  it("executes the entire assessment lifecycle from auth to target, scan, ZAP, findings, and AI analysis", async () => {
    // -------------------------------------------------------------------------
    // Step 1: User Registration, Verification, and Login
    // -------------------------------------------------------------------------
    const registerRes = await app.inject({
      method: "POST",
      url: "/auth/register",
      payload: {
        email: "alice@security.example.com",
        password: "ValidPassw0rd!123",
        name: "Alice SecOps",
      },
    });
    expect(registerRes.statusCode).toBe(201);

    const sentEmail = emailService.sentEmails.find((m) => m.to === "alice@security.example.com");
    expect(sentEmail).toBeDefined();
    const verificationToken = sentEmail!.token;

    const verifyRes = await app.inject({
      method: "POST",
      url: "/auth/verify-email",
      payload: { token: verificationToken },
    });
    expect(verifyRes.statusCode).toBe(200);

    const loginRes = await app.inject({
      method: "POST",
      url: "/auth/login",
      payload: {
        email: "alice@security.example.com",
        password: "ValidPassw0rd!123",
      },
    });
    expect(loginRes.statusCode).toBe(200);
    const aliceCookie = getCookie(loginRes);
    expect(aliceCookie).toBeTruthy();

    const meRes = await app.inject({
      method: "GET",
      url: "/auth/me",
      cookies: { [AUTH_COOKIE]: aliceCookie },
    });
    expect(meRes.statusCode).toBe(200);
    const aliceUser = meRes.json().user;
    expect(aliceUser.email).toBe("alice@security.example.com");

    // -------------------------------------------------------------------------
    // Step 2: Target Creation
    // -------------------------------------------------------------------------
    const createTargetRes = await app.inject({
      method: "POST",
      url: "/targets",
      cookies: { [AUTH_COOKIE]: aliceCookie },
      payload: {
        name: "E2E Assessment Target",
        url: "https://example.com",
        description: "Authorized staging target for vulnerability assessment",
      },
    });
    expect(createTargetRes.statusCode).toBe(201);
    const target = createTargetRes.json().target;
    expect(target.id).toBeDefined();
    expect(target.status).toBe("active");

    // -------------------------------------------------------------------------
    // Step 3: Scan Creation
    // -------------------------------------------------------------------------
    // Configure Fake ZAP to return realistic raw alerts upon completion
    fakeZap.spiderProgress = [50, 100];
    fakeZap.activeScanProgress = [50, 100];
    const sampleZapAlerts: ZapRawAlert[] = [
      {
        pluginId: "40012",
        alertRef: "40012-1",
        alert: "Cross Site Scripting (Reflected)",
        name: "Cross Site Scripting (Reflected)",
        risk: "High",
        confidence: "High",
        url: "https://example.com/search?query=test",
        uri: "https://example.com/search?query=test",
        param: "query",
        attack: "<script>alert(1)</script>",
        evidence: "<script>alert(1)</script>",
        description: "A reflected cross-site scripting attack occurs when...",
        solution: "Context-sensitive output encoding should be applied.",
        reference: "https://owasp.org/www-community/attacks/xss/",
        cweid: "79",
        wascid: "8",
        sourceid: "3",
        other: "",
      },
      {
        pluginId: "10021",
        alertRef: "10021-1",
        alert: "X-Content-Type-Options Header Missing",
        name: "X-Content-Type-Options Header Missing",
        risk: "Low",
        confidence: "Medium",
        url: "https://example.com",
        uri: "https://example.com",
        param: "",
        attack: "",
        evidence: "",
        description: "The anti-MIME-sniffing header is not present on the response.",
        solution: "Add X-Content-Type-Options: nosniff to all responses.",
        reference: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
        cweid: "16",
        wascid: "15",
        sourceid: "3",
        other: "",
      },
    ];
    fakeZap.alertsResult = sampleZapAlerts;

    const startScanRes = await app.inject({
      method: "POST",
      url: `/targets/${target.id}/scans`,
      cookies: { [AUTH_COOKIE]: aliceCookie },
    });
    expect(startScanRes.statusCode).toBe(201);
    const scan = startScanRes.json().scan;
    expect(scan.id).toBeDefined();
    expect(scan.status).toBe("queued");
    findings.scanOwners.set(scan.id, aliceUser.id);
    analyses.scanOwners.set(scan.id, aliceUser.id);

    // Wait for async executor to run through spider, active scan, and alert normalization
    let completedScan = await scans.findById(scan.id);
    let attempts = 0;
    while (completedScan?.status !== "completed" && attempts < 50) {
      await new Promise((resolve) => setTimeout(resolve, 50));
      completedScan = await scans.findById(scan.id);
      attempts++;
    }
    expect(completedScan?.status).toBe("completed");
    expect(completedScan?.startedAt).toBeInstanceOf(Date);
    expect(completedScan?.completedAt).toBeInstanceOf(Date);
    expect(completedScan?.errorMessage).toBeNull();

    // -------------------------------------------------------------------------
    // Step 4: Finding Normalization & Retrieval
    // -------------------------------------------------------------------------
    const findingsRes = await app.inject({
      method: "GET",
      url: `/scans/${scan.id}/findings`,
      cookies: { [AUTH_COOKIE]: aliceCookie },
    });
    expect(findingsRes.statusCode).toBe(200);
    const findingsList = findingsRes.json().findings;
    expect(findingsList.length).toBe(2);

    const xssFinding = findingsList.find((f: { title: string }) => f.title === "Cross Site Scripting (Reflected)");
    expect(xssFinding).toBeDefined();
    expect(xssFinding.severity).toBe("high");
    expect(xssFinding.confidence).toBe("high");
    expect(xssFinding.cweId).toBe(79);
    expect(xssFinding.wascId).toBe(8);
    expect(xssFinding.instances.length).toBe(1);
    expect(xssFinding.instances[0].parameter).toBe("query");
    expect(xssFinding.instances[0].evidence).toBe("<script>alert(1)</script>");

    const singleFindingRes = await app.inject({
      method: "GET",
      url: `/findings/${xssFinding.id}`,
      cookies: { [AUTH_COOKIE]: aliceCookie },
    });
    expect(singleFindingRes.statusCode).toBe(200);
    expect(singleFindingRes.json().finding.id).toBe(xssFinding.id);

    // -------------------------------------------------------------------------
    // Step 5: AI Security Analysis Request & Execution
    // -------------------------------------------------------------------------
    // Configure AI model double to return structured output referencing actual findings
    fakeAiModel.result = {
      overallRisk: "high",
      executiveSummary: "Assessment of the target identified reflected XSS permitting cross-site script execution.",
      methodologySummary: "DAST analysis evaluated against OWASP standards.",
      keyRisks: ["Reflected script execution in client browser context"],
      findingAssessments: [
        {
          findingId: xssFinding.id,
          priority: "high",
          riskAssessment: "High potential risk if administrative users are tricked into clicking a crafted query link.",
          confidence: "high",
          reasoning: "Payload reflects verbatim in the query parameter without output encoding.",
          businessImpact: "Session hijacking or credential theft.",
          technicalImpact: "Arbitrary script execution within victim session.",
          remediationPriority: "high",
          falsePositiveLikelihood: "low",
        },
      ],
      correlations: [],
      remediationPriorities: ["Implement context-sensitive output encoding"],
      limitations: ["Automated DAST reflection analysis without backend source code access"],
    };

    const analyzeRes = await app.inject({
      method: "POST",
      url: `/scans/${scan.id}/analyze`,
      cookies: { [AUTH_COOKIE]: aliceCookie },
    });
    expect(analyzeRes.statusCode).toBe(202);
    const analysisRecord = analyzeRes.json().analysis;
    expect(analysisRecord.id).toBeDefined();

    // Wait for analysis executor to complete
    let completedAnalysis = await analyses.findById(analysisRecord.id);
    attempts = 0;
    while (completedAnalysis?.status !== "completed" && attempts < 50) {
      await new Promise((resolve) => setTimeout(resolve, 50));
      completedAnalysis = await analyses.findById(analysisRecord.id);
      attempts++;
    }
    expect(completedAnalysis?.status).toBe("completed");
    expect(completedAnalysis?.overallRisk).toBe("high");
    expect(completedAnalysis?.executiveSummary).toContain("reflected XSS");
    expect(completedAnalysis?.assessments.length).toBe(1);
    expect(completedAnalysis?.assessments[0].findingId).toBe(xssFinding.id);
    expect(completedAnalysis?.assessments[0].priority).toBe("high");

    // Verify retrieval via GET /scans/:scanId/analysis
    const getAnalysisRes = await app.inject({
      method: "GET",
      url: `/scans/${scan.id}/analysis`,
      cookies: { [AUTH_COOKIE]: aliceCookie },
    });
    expect(getAnalysisRes.statusCode).toBe(200);
    const retrievedAnalysis = getAnalysisRes.json().analysis;
    expect(retrievedAnalysis.id).toBe(analysisRecord.id);
    expect(retrievedAnalysis.overallRisk).toBe("high");
    expect(retrievedAnalysis.assessments.length).toBe(1);

    // -------------------------------------------------------------------------
    // Step 6: Verify Duplicate Prevention (409 Conflict)
    // -------------------------------------------------------------------------
    const duplicateAnalyzeRes = await app.inject({
      method: "POST",
      url: `/scans/${scan.id}/analyze`,
      cookies: { [AUTH_COOKIE]: aliceCookie },
    });
    expect(duplicateAnalyzeRes.statusCode).toBe(409);

    // -------------------------------------------------------------------------
    // Step 7: Verify Cross-User Isolation
    // -------------------------------------------------------------------------
    // Register Bob
    const bobReg = await app.inject({
      method: "POST",
      url: "/auth/register",
      payload: {
        email: "bob@security.example.com",
        password: "ValidPassw0rd!456",
        name: "Bob Auditor",
      },
    });
    expect(bobReg.statusCode).toBe(201);
    const bobEmail = emailService.sentEmails.find((m) => m.to === "bob@security.example.com");
    const bobToken = bobEmail!.token;
    await app.inject({
      method: "POST",
      url: "/auth/verify-email",
      payload: { token: bobToken },
    });
    const bobLogin = await app.inject({
      method: "POST",
      url: "/auth/login",
      payload: {
        email: "bob@security.example.com",
        password: "ValidPassw0rd!456",
      },
    });
    const bobCookie = getCookie(bobLogin);

    // Bob cannot access Alice's target
    const bobTargetRes = await app.inject({
      method: "GET",
      url: `/targets/${target.id}`,
      cookies: { [AUTH_COOKIE]: bobCookie },
    });
    expect(bobTargetRes.statusCode).toBe(404);

    // Bob cannot access Alice's scan
    const bobScanRes = await app.inject({
      method: "GET",
      url: `/scans/${scan.id}`,
      cookies: { [AUTH_COOKIE]: bobCookie },
    });
    expect(bobScanRes.statusCode).toBe(404);

    // Bob cannot access Alice's findings
    const bobFindingsRes = await app.inject({
      method: "GET",
      url: `/scans/${scan.id}/findings`,
      cookies: { [AUTH_COOKIE]: bobCookie },
    });
    expect(bobFindingsRes.statusCode).toBe(404);

    // Bob cannot access Alice's finding detail
    const bobFindingDetailRes = await app.inject({
      method: "GET",
      url: `/findings/${xssFinding.id}`,
      cookies: { [AUTH_COOKIE]: bobCookie },
    });
    expect(bobFindingDetailRes.statusCode).toBe(404);

    // Bob cannot trigger analysis on Alice's scan
    const bobAnalyzeRes = await app.inject({
      method: "POST",
      url: `/scans/${scan.id}/analyze`,
      cookies: { [AUTH_COOKIE]: bobCookie },
    });
    expect(bobAnalyzeRes.statusCode).toBe(404);

    // Bob cannot get Alice's analysis
    const bobGetAnalysisRes = await app.inject({
      method: "GET",
      url: `/scans/${scan.id}/analysis`,
      cookies: { [AUTH_COOKIE]: bobCookie },
    });
    expect(bobGetAnalysisRes.statusCode).toBe(404);
  });
});
