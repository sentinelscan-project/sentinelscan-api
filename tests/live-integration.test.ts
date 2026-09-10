import { describe, it, expect } from "vitest";
import { GeminiSecurityAnalysisModel } from "../src/modules/analysis/providers/gemini-security-analysis-model.js";
import { HttpZapClient } from "../src/lib/zap-client.js";
import { AiProviderError } from "../src/modules/analysis/security-analysis-model.js";
import type { SecurityAnalysisInput } from "../src/modules/analysis/security-analysis-input.js";
import { assertTargetIsSafeToScan, TargetSafetyViolation } from "../src/lib/target-safety.js";
import { buildApp } from "../src/app.js";
import { getPrismaClient } from "../src/db/prisma.js";

const AUTH_COOKIE = "sentinelscan_token";

describe("Stage 8: Live Integration & System Verification", () => {
  const zapUrl = process.env.ZAP_BASE_URL || "http://localhost:8090";
  const zapApiKey = process.env.ZAP_API_KEY?.trim();
  const geminiApiKey = process.env.GEMINI_API_KEY?.trim();
  const liveTargetUrl = process.env.LIVE_TARGET_URL?.trim();

  describe("1. Target Safety & SSRF Prevention (Fail-Closed Boundary)", () => {
    it("rejects loopback addresses", async () => {
      await expect(assertTargetIsSafeToScan("http://127.0.0.1:8080")).rejects.toThrow(TargetSafetyViolation);
      await expect(assertTargetIsSafeToScan("http://localhost:8090")).rejects.toThrow(TargetSafetyViolation);
    });

    it("rejects RFC1918 private network addresses", async () => {
      await expect(assertTargetIsSafeToScan("http://10.0.0.1")).rejects.toThrow(TargetSafetyViolation);
      await expect(assertTargetIsSafeToScan("http://172.16.0.1")).rejects.toThrow(TargetSafetyViolation);
      await expect(assertTargetIsSafeToScan("http://192.168.1.1")).rejects.toThrow(TargetSafetyViolation);
    });

    it("rejects cloud metadata link-local addresses", async () => {
      await expect(assertTargetIsSafeToScan("http://169.254.169.254/latest/meta-data/")).rejects.toThrow(
        TargetSafetyViolation,
      );
    });
  });

  describe("2. OWASP ZAP Live Daemon Reachability", () => {
    it("evaluates live ZAP daemon reachability over configured ZAP_BASE_URL", async () => {
      const client = new HttpZapClient({
        baseUrl: zapUrl,
        apiKey: zapApiKey,
        requestTimeoutMs: 3000,
      });
      const health = await client.health();

      if (health.reachable) {
        expect(health.version).toBeDefined();
        console.info(`[Stage 8 ZAP Validation] PASSED: ZAP daemon reachable on ${zapUrl}, version=${health.version}`);
      } else {
        console.warn(
          `[Stage 8 ZAP Validation] BLOCKED: ZAP daemon is not reachable on ${zapUrl}. (In Docker, ZAP listens on internal network sentinelscan-net:8090 without host port mapping by security policy).`,
        );
      }
    });
  });

  describe("3. Gemini AI Provider Live Verification", () => {
    if (geminiApiKey) {
      it("executes a live Gemini analysis request and returns structured schema-valid assessment", async () => {
        const model = new GeminiSecurityAnalysisModel({
          apiKey: geminiApiKey,
          model: "gemini-2.5-flash",
          timeoutMs: 30000,
          maxOutputTokens: 4000,
        });

        const input: SecurityAnalysisInput = {
          target: {
            url: "https://example.com",
            name: "Live Integration Target",
          },
          scan: {
            id: "live-test-scan-001",
            findingsCount: 1,
            findingsTruncated: 0,
          },
          findings: [
            {
              id: "f-001",
              title: "Cross Site Scripting (Reflected)",
              severity: "high",
              confidence: "high",
              category: "xss",
              cweId: 79,
              wascId: 8,
              remediation: "Context-sensitive output encoding should be applied.",
              instances: [
                {
                  url: "https://example.com/search?q=test",
                  method: "GET",
                  parameter: "q",
                  attack: "<script>alert(1)</script>",
                  evidence: "<script>alert(1)</script>",
                },
              ],
            },
          ],
        };

        const result = await model.analyzeSecurityFindings(input);
        expect(result).toBeDefined();
        expect(["critical", "high", "medium", "low", "informational"]).toContain(result.overallRisk);
        expect(result.summary.length).toBeGreaterThan(10);
        expect(result.findingAssessments.length).toBe(1);
        expect(result.findingAssessments[0].findingId).toBe("f-001");
        expect(["critical", "high", "medium", "low", "informational"]).toContain(
          result.findingAssessments[0].aiPriority,
        );
      });
    } else {
      it("safely handles absence of GEMINI_API_KEY (fail-close with AiProviderError)", async () => {
        const model = new GeminiSecurityAnalysisModel({
          apiKey: undefined,
          model: "gemini-2.5-flash",
          timeoutMs: 1000,
        });

        const input: SecurityAnalysisInput = {
          target: { url: "https://example.com", name: "Example" },
          scan: { id: "test", findingsCount: 0, findingsTruncated: 0 },
          findings: [],
        };

        await expect(model.analyzeSecurityFindings(input)).rejects.toThrow(AiProviderError);
        console.warn(
          "[Stage 8 Gemini Validation] BLOCKED: GEMINI_API_KEY is not set in environment. Provider fails closed safely as expected.",
        );
      });
    }
  });

  describe("4. End-to-End Pipeline Execution (Real Application Stack)", () => {
    it("reports the explicit configuration required before the full live test can run", () => {
      if (!liveTargetUrl) {
        console.warn(
          "[Stage 8 Pipeline] BLOCKED: LIVE_TARGET_URL is not configured. The full test is skipped; it will not invent or scan a third-party target.",
        );
      }
      if (!geminiApiKey) {
        console.warn(
          "[Stage 8 Pipeline] BLOCKED: GEMINI_API_KEY is not configured. The full test is skipped because Gemini persistence is part of the Stage 8 acceptance path.",
        );
      }
    });

    // This is intentionally skipped, rather than reported as passed, until the
    // operator supplies both secrets/configuration inputs.  In particular, a
    // scan-only run is not allowed to masquerade as the full Stage 8 path.
    it.skipIf(!liveTargetUrl || !geminiApiKey)("executes the real scan -> findings -> Gemini persistence flow", async () => {
      const zapClient = new HttpZapClient({
        baseUrl: zapUrl,
        apiKey: zapApiKey,
        requestTimeoutMs: 3000,
      });
      const zapHealth = await zapClient.health();

      expect(zapHealth.reachable, `ZAP must be reachable at ${zapUrl} for the live Stage 8 test`).toBe(true);

      // If all prerequisites exist, execute via real Fastify application with real database and real ZAP
      const app = buildApp();
      await app.ready();

      const prisma = getPrismaClient();
      let testUserId: string | undefined;
      let targetId: string | undefined;
      let scanId: string | undefined;
      let analysisId: string | undefined;

      try {
        // Step A: Target safety assertion
        await assertTargetIsSafeToScan(liveTargetUrl);

        // Step B: Authenticated user registration & session via real API
        const email = `live-e2e-${Date.now()}@sentinelscan.local`;
        const regRes = await app.inject({
          method: "POST",
          url: "/auth/register",
          payload: { email, password: "ValidPassword123!", name: "Live Tester" },
        });
        expect(regRes.statusCode).toBe(201);

        // Fetch user from DB to verify directly
        const dbUser = await prisma.user.findUnique({ where: { email } });
        expect(dbUser).not.toBeNull();
        testUserId = dbUser!.id;

        await prisma.user.update({
          where: { id: testUserId },
          data: { emailVerified: true },
        });

        const loginRes = await app.inject({
          method: "POST",
          url: "/auth/login",
          payload: { email, password: "ValidPassword123!" },
        });
        expect(loginRes.statusCode).toBe(200);
        const cookie = loginRes.cookies.find((c) => c.name === AUTH_COOKIE)?.value;
        expect(cookie).toBeTruthy();

        // Step C: Create target
        const targetRes = await app.inject({
          method: "POST",
          url: "/targets",
          cookies: { [AUTH_COOKIE]: cookie! },
          payload: { name: "Authorized Live Target", url: liveTargetUrl },
        });
        expect(targetRes.statusCode).toBe(201);
        targetId = targetRes.json().target.id;

        // Step D: Create scan (triggers real ZapScanExecutor asynchronously)
        const scanRes = await app.inject({
          method: "POST",
          url: `/targets/${targetId}/scans`,
          cookies: { [AUTH_COOKIE]: cookie! },
        });
        expect(scanRes.statusCode).toBe(201);
        scanId = scanRes.json().scan.id;

        console.info(`[Stage 8 Pipeline] Scan queued scanId=${scanId}; awaiting completion...`);

        // Step E: Poll until completed or timeout
        let status = "queued";
        const start = Date.now();
        const maxWaitMs = 180_000; // 3 minutes maximum for live assessment
        while (Date.now() - start < maxWaitMs) {
          await new Promise((r) => setTimeout(r, 2000));
          const checkRes = await app.inject({
            method: "GET",
            url: `/scans/${scanId}`,
            cookies: { [AUTH_COOKIE]: cookie! },
          });
          status = checkRes.json().scan.status;
          if (status === "completed" || status === "failed") break;
        }

        expect(status).toBe("completed");

        // Step F: Retrieve normalized findings
        const findingsRes = await app.inject({
          method: "GET",
          url: `/scans/${scanId}/findings`,
          cookies: { [AUTH_COOKIE]: cookie! },
        });
        expect(findingsRes.statusCode).toBe(200);
        const findings = findingsRes.json().findings;
        const persistedFindings = await prisma.finding.findMany({
          where: { scanId },
          include: { instances: true },
        });
        expect(persistedFindings).toHaveLength(findings.length);
        expect(findingsRes.json().counts.total).toBe(persistedFindings.length);
        console.info(`[Stage 8 Pipeline] Scan completed with ${findings.length} findings.`);

        // Step G: Trigger and verify real Gemini analysis plus persisted result.
        const analyzeRes = await app.inject({
          method: "POST",
          url: `/scans/${scanId}/analyze`,
          cookies: { [AUTH_COOKIE]: cookie! },
        });
        expect(analyzeRes.statusCode).toBe(202);
        analysisId = analyzeRes.json().analysis.id;

        let analysisStatus = "queued";
        let analysisPayload: { analysis?: { id?: string; status?: string } } | undefined;
        const aiStart = Date.now();
        while (Date.now() - aiStart < 60_000) {
          await new Promise((r) => setTimeout(r, 2000));
          const analysisCheck = await app.inject({
            method: "GET",
            url: `/scans/${scanId}/analysis`,
            cookies: { [AUTH_COOKIE]: cookie! },
          });
          expect(analysisCheck.statusCode).toBe(200);
          analysisPayload = analysisCheck.json();
          analysisStatus = analysisPayload.analysis?.status ?? "unknown";
          if (analysisStatus === "completed" || analysisStatus === "failed") break;
        }

        expect(analysisStatus).toBe("completed");
        expect(analysisPayload?.analysis?.id).toBe(analysisId);
        const persistedAnalysis = await prisma.securityAnalysis.findUnique({
          where: { id: analysisId },
          include: { assessments: true, correlations: true },
        });
        expect(persistedAnalysis?.status).toBe("completed");
        expect(persistedAnalysis?.executiveSummary).toBeTruthy();
        expect(persistedAnalysis?.model).toBeTruthy();
        console.info("[Stage 8 Pipeline] Gemini AI Security Analysis completed and persisted successfully.");
      } finally {
        // Step H: Clean up test records in reverse order
        if (analysisId) {
          await prisma.securityAnalysis.delete({ where: { id: analysisId } }).catch(() => undefined);
        }
        if (scanId) {
          await prisma.findingInstance.deleteMany({ where: { finding: { scanId } } }).catch(() => undefined);
          await prisma.finding.deleteMany({ where: { scanId } }).catch(() => undefined);
          await prisma.scan.delete({ where: { id: scanId } }).catch(() => undefined);
        }
        if (targetId) {
          await prisma.target.delete({ where: { id: targetId } }).catch(() => undefined);
        }
        if (testUserId) {
          await prisma.emailVerificationToken.deleteMany({ where: { userId: testUserId } }).catch(() => undefined);
          await prisma.user.delete({ where: { id: testUserId } }).catch(() => undefined);
        }
        await app.close();
      }
    });
  });
});
