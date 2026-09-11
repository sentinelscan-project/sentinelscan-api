import { describe, it, expect } from "vitest";
import dotenv from "dotenv";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { GeminiSecurityAnalysisModel } from "../src/modules/analysis/providers/gemini-security-analysis-model.js";
import { HttpZapClient } from "../src/lib/zap-client.js";
import { AiProviderError } from "../src/modules/analysis/security-analysis-model.js";
import type { SecurityAnalysisInput } from "../src/modules/analysis/security-analysis-input.js";
import { assertTargetIsSafeToScan, TargetSafetyViolation } from "../src/lib/target-safety.js";
import { buildApp } from "../src/app.js";
import { getPrismaClient } from "../src/db/prisma.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
dotenv.config({ path: path.resolve(__dirname, "../../.env"), override: true });
dotenv.config();

const AUTH_COOKIE = "sentinelscan_token";

describe("Stage 8: Live Integration & System Verification", () => {
  const zapUrl = process.env.ZAP_BASE_URL || "http://localhost:8090";
  const zapApiKey = process.env.ZAP_API_KEY?.trim();
  const geminiApiKey = process.env.GEMINI_API_KEY?.trim();
  const liveTargetUrl = process.env.LIVE_TARGET_URL?.trim();
  /**
   * The full live pipeline (section 4 below) performs a real ZAP scan
   * against `liveTargetUrl` and a real Gemini analysis call. Gating it on
   * `liveTargetUrl`/`geminiApiKey` alone is not enough: those two secrets
   * may simply be sitting in a developer's local `.env` for unrelated
   * reasons (e.g. testing the Gemini adapter directly), and a plain `npm
   * test` must never initiate a real external scan just because they happen
   * to be present. `RUN_LIVE_INTEGRATION_TEST=true` is a separate, explicit
   * opt-in a developer sets only when they intend to run this specific
   * live-test mode — see the README's "Opt-in local live-test access"
   * section for the full invocation.
   */
  const liveIntegrationTestEnabled = process.env.RUN_LIVE_INTEGRATION_TEST === "true";

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
    // Same reasoning as section 4's `liveIntegrationTestEnabled` gate: this
    // branch makes a real, billed, rate-limited network call to Gemini.
    // `GEMINI_API_KEY` alone being present in a developer's `.env` (e.g. for
    // unrelated local work) must not be enough to trigger it on every plain
    // `npm test` — that makes the suite flaky against Gemini's own rate
    // limits/availability for a check nobody explicitly asked to run.
    if (liveIntegrationTestEnabled && geminiApiKey) {
      it("executes a live Gemini analysis request and returns structured schema-valid assessment", async () => {
        const model = new GeminiSecurityAnalysisModel({
          apiKey: geminiApiKey,
          model: process.env.AI_MODEL || "gemini-3.6-flash",
          timeoutMs: 30000,
          maxOutputTokens: 4000,
        });

        const input: SecurityAnalysisInput = {
          scan: {
            id: "live-test-scan-001",
            targetName: "Live Integration Target",
            targetOrigin: "https://example.com",
          },
          findingCounts: { critical: 0, high: 1, medium: 0, low: 0, informational: 0, total: 1 },
          truncatedFindingsCount: 0,
          findings: [
            {
              id: "a0000000-0000-0000-0000-000000000001",
              title: "Cross Site Scripting (Reflected)",
              description: "A reflected cross-site scripting vulnerability was identified in the search query parameter.",
              severity: "high",
              confidence: "high",
              category: "client-side",
              cweId: 79,
              wascId: 8,
              remediation: "Context-sensitive output encoding should be applied.",
              references: ["https://owasp.org/www-community/attacks/xss/"],
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
        expect(result.executiveSummary.length).toBeGreaterThan(10);
        expect(result.findingAssessments).toHaveLength(1);
        const [assessment] = result.findingAssessments;
        expect(assessment?.findingId).toBe("a0000000-0000-0000-0000-000000000001");
        expect(["critical", "high", "medium", "low", "informational"]).toContain(assessment?.priority);
      }, 30_000);
    } else {
      it("safely handles absence of GEMINI_API_KEY (fail-close with AiProviderError)", async () => {
        const model = new GeminiSecurityAnalysisModel({
          apiKey: undefined,
          model: "gemini-2.5-flash",
          timeoutMs: 1000,
        });

        const input: SecurityAnalysisInput = {
          scan: { id: "test", targetName: "Example", targetOrigin: "https://example.com" },
          findingCounts: { critical: 0, high: 0, medium: 0, low: 0, informational: 0, total: 0 },
          truncatedFindingsCount: 0,
          findings: [],
        };

        await expect(model.analyzeSecurityFindings(input)).rejects.toThrow(AiProviderError);
        console.warn(
          geminiApiKey
            ? "[Stage 8 Gemini Validation] BLOCKED: GEMINI_API_KEY is set, but RUN_LIVE_INTEGRATION_TEST is not 'true', so the real live Gemini call is skipped by default. Running the fail-close check instead. Provider fails closed safely as expected."
            : "[Stage 8 Gemini Validation] BLOCKED: GEMINI_API_KEY is not set in environment. Provider fails closed safely as expected.",
        );
      });
    }
  });

  describe("4. End-to-End Pipeline Execution (Real Application Stack)", () => {
    it("reports the explicit configuration required before the full live test can run", () => {
      if (!liveIntegrationTestEnabled) {
        console.warn(
          "[Stage 8 Pipeline] BLOCKED: RUN_LIVE_INTEGRATION_TEST is not set to 'true'. The full test is skipped by default, " +
            "even when LIVE_TARGET_URL/GEMINI_API_KEY happen to be configured — a normal `npm test` must never initiate a " +
            "real external scan merely because those secrets are present. Set RUN_LIVE_INTEGRATION_TEST=true to opt in explicitly.",
        );
      }
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

    // This test runs only when explicitly opted into (RUN_LIVE_INTEGRATION_TEST=true)
    // AND the authorized target and Gemini key are configured. All three are
    // required — the opt-in flag alone, without real prerequisites, must not
    // make this silently "pass" without ever exercising the pipeline.
    it.skipIf(!liveIntegrationTestEnabled || !liveTargetUrl || !geminiApiKey)(
      "executes the real scan -> findings -> Gemini persistence flow",
      async () => {
        const zapClient = new HttpZapClient({
          baseUrl: zapUrl,
          apiKey: zapApiKey,
          requestTimeoutMs: 5000,
        });
        const zapHealth = await zapClient.health();

        expect(zapHealth.reachable, `ZAP must be reachable at ${zapUrl} for the live Stage 8 test`).toBe(true);

        // If all prerequisites exist, execute via real Fastify application with real database and real ZAP
        const app = buildApp({
          analysisModel: new GeminiSecurityAnalysisModel({
            apiKey: geminiApiKey,
            model: process.env.AI_MODEL || "gemini-3.6-flash",
            timeoutMs: 60_000,
            maxOutputTokens: 4000,
          }),
        });
        await app.ready();

        const prisma = getPrismaClient();
        let testUserId: string | undefined;
        let targetId: string | undefined;
        let scanId: string | undefined;
        let analysisId: string | undefined;

        try {
          // Narrows `liveTargetUrl` from `string | undefined` to `string` for
          // TypeScript — this branch only ever runs when `it.skipIf` above
          // already proved `liveIntegrationTestEnabled`, `liveTargetUrl`, and
          // `geminiApiKey` are all set, but that runtime gate isn't visible
          // to the type checker.
          if (!liveTargetUrl) {
            throw new Error(
              "Unreachable: gated by it.skipIf(!liveIntegrationTestEnabled || !liveTargetUrl || !geminiApiKey)",
            );
          }

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

          console.info(`[Stage 8 Pipeline] Scan queued scanId=${scanId}; awaiting real ZAP spider + active scan...`);

          // Step E: Poll until completed or failed or timeout
          let status = "queued";
          const start = Date.now();
          const maxWaitMs = 600_000; // 10 minutes maximum for real live assessment
          let lastProgressLog = 0;

          while (Date.now() - start < maxWaitMs) {
            await new Promise((r) => setTimeout(r, 4000));
            const checkRes = await app.inject({
              method: "GET",
              url: `/scans/${scanId}`,
              cookies: { [AUTH_COOKIE]: cookie! },
            });
            status = checkRes.json()?.scan?.status ?? "unknown";

            if (Date.now() - lastProgressLog > 15_000) {
              lastProgressLog = Date.now();
              console.info(`[Stage 8 Pipeline] Polling scanId=${scanId}, current status=${status} (${Math.round((Date.now() - start) / 1000)}s elapsed)`);
            }

            if (status === "completed" || status === "failed") break;
          }

          const durationSec = Math.round((Date.now() - start) / 1000);
          console.info(`[Stage 8 Pipeline] Scan reached terminal status='${status}' in ${durationSec}s`);
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

          const severityDist: Record<string, number> = {};
          const confidenceDist: Record<string, number> = {};
          let totalInstances = 0;
          for (const f of persistedFindings) {
            severityDist[f.severity] = (severityDist[f.severity] || 0) + 1;
            confidenceDist[f.confidence] = (confidenceDist[f.confidence] || 0) + 1;
            totalInstances += f.instances.length;
          }

          console.info(`[Stage 8 Pipeline] Normalized findings retrieved: ${findings.length}`);
          console.info(`[Stage 8 Pipeline] Persisted Finding records: ${persistedFindings.length}, FindingInstance records: ${totalInstances}`);
          console.info(`[Stage 8 Pipeline] Severity distribution: ${JSON.stringify(severityDist)}`);
          console.info(`[Stage 8 Pipeline] Confidence distribution: ${JSON.stringify(confidenceDist)}`);

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
          while (Date.now() - aiStart < 90_000) {
            await new Promise((r) => setTimeout(r, 3000));
            const analysisCheck = await app.inject({
              method: "GET",
              url: `/scans/${scanId}/analysis`,
              cookies: { [AUTH_COOKIE]: cookie! },
            });
            expect(analysisCheck.statusCode).toBe(200);
            analysisPayload = analysisCheck.json();
            analysisStatus = analysisPayload?.analysis?.status ?? "unknown";
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

          console.info(`[Stage 8 Pipeline] Gemini AI Security Analysis status=${analysisStatus}`);
          console.info(`[Stage 8 Pipeline] AI Overall Risk: ${persistedAnalysis?.overallRisk}`);
          console.info(`[Stage 8 Pipeline] AI Model: ${persistedAnalysis?.model}`);
          console.info(`[Stage 8 Pipeline] Persisted FindingAssessment records: ${persistedAnalysis?.assessments.length}`);
          console.info(`[Stage 8 Pipeline] Persisted FindingCorrelation records: ${persistedAnalysis?.correlations.length}`);

          // Step H: Ownership isolation verification
          const unauthScanRes = await app.inject({
            method: "GET",
            url: `/scans/${scanId}`,
          });
          expect(unauthScanRes.statusCode).toBe(401);

          const unauthFindingsRes = await app.inject({
            method: "GET",
            url: `/scans/${scanId}/findings`,
          });
          expect(unauthFindingsRes.statusCode).toBe(401);

          const unauthAnalysisRes = await app.inject({
            method: "GET",
            url: `/scans/${scanId}/analysis`,
          });
          expect(unauthAnalysisRes.statusCode).toBe(401);
        } finally {
          // Clean up test records in reverse dependency order
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
      },
      660_000, // 11-minute vitest timeout for real live scan
    );
  });
});
