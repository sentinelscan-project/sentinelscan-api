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
import { NoOpScanExecutor } from "./helpers/fake-scan-executor.js";
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
let scanExecutor: NoOpScanExecutor;

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

/** Registers and verifies a fresh user, then registers one target for them. Returns everything a test needs to seed scans/findings for that owner. */
async function registerOwner(email: string): Promise<Owner> {
  await app.inject({
    method: "POST",
    url: "/auth/register",
    payload: { email, name: "Finding Viewer", password: "Str0ngPassphrase" },
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

/** Creates a scan for `owner` and persists `normalizedFindings` against it. */
async function seedScanWithFindings(owner: Owner, normalizedFindings: NormalizedFinding[]): Promise<ScanRecord> {
  const scan = await scans.create({ targetId: owner.targetId, requestedById: owner.ownerId });
  findings.scanOwners.set(scan.id, owner.ownerId);
  await findings.createMany(scan.id, normalizedFindings);
  return scan;
}

beforeAll(async () => {
  users = createInMemoryUserRepository();
  tokens = createInMemoryVerificationTokenRepository();
  emailService = new MockEmailService();
  targets = createInMemoryTargetRepository();
  scans = createInMemoryScanRepository();
  findings = createInMemoryFindingRepository();
  scanExecutor = new NoOpScanExecutor();
  app = buildApp({
    userRepository: users,
    tokenRepository: tokens,
    emailService,
    targetRepository: targets,
    scanRepository: scans,
    findingRepository: findings,
    scanExecutor,
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
  scanExecutor.reset();
});

afterAll(async () => {
  await app.close();
});

describe("GET /scans/:scanId/findings — authentication", () => {
  it("rejects an unauthenticated request with 401", async () => {
    const response = await app.inject({ method: "GET", url: "/scans/00000000-0000-0000-0000-000000000000/findings" });
    expect(response.statusCode).toBe(401);
  });
});

describe("GET /scans/:scanId/findings — authorization", () => {
  it("returns the owner's findings for their own scan, with unfiltered counts", async () => {
    const owner = await registerOwner("owner-findings-1@example.com");
    const scan = await seedScanWithFindings(owner, [sampleFinding()]);

    const response = await authedRequest("GET", `/scans/${scan.id}/findings`, owner.cookie);

    expect(response.statusCode).toBe(200);
    const body = JSON.parse(response.payload);
    expect(body.findings).toHaveLength(1);
    expect(body.findings[0].title).toBe("Cross Site Scripting (Reflected)");
    expect(body.findings[0].scanId).toBe(scan.id);
    expect(body.findings[0].instances).toHaveLength(1);
    expect(body.counts).toEqual({ critical: 0, high: 1, medium: 0, low: 0, informational: 0, total: 1 });
  });

  it("returns an indistinguishable 404 for another user's scan and a nonexistent one", async () => {
    const owner = await registerOwner("owner-findings-2@example.com");
    const other = await registerOwner("other-findings-2@example.com");
    const scan = await seedScanWithFindings(owner, [sampleFinding()]);

    const ownedResponse = await authedRequest("GET", `/scans/${scan.id}/findings`, owner.cookie);
    const foreignResponse = await authedRequest("GET", `/scans/${scan.id}/findings`, other.cookie);
    const nonexistentResponse = await authedRequest(
      "GET",
      "/scans/00000000-0000-0000-0000-000000000000/findings",
      other.cookie,
    );

    expect(ownedResponse.statusCode).toBe(200);
    expect(foreignResponse.statusCode).toBe(404);
    expect(nonexistentResponse.statusCode).toBe(404);
    expect(JSON.parse(foreignResponse.payload)).toEqual(JSON.parse(nonexistentResponse.payload));
  });
});

describe("GET /scans/:scanId/findings — filtering, counts, pagination", () => {
  it("filters by severity/confidence/category/source while counts stay the full unfiltered breakdown", async () => {
    const owner = await registerOwner("filter-findings@example.com");
    const scan = await seedScanWithFindings(owner, [
      sampleFinding({ severity: "high", category: "client-side", sourceRuleId: "40012" }),
      sampleFinding({
        severity: "low",
        confidence: "low",
        category: "security-header",
        sourceRuleId: "10020",
        title: "X-Frame-Options Header Not Set",
      }),
      sampleFinding({
        severity: "informational",
        category: "information-disclosure",
        sourceRuleId: "10037",
        title: "Server Leaks Version Information",
      }),
    ]);

    const severityFiltered = await authedRequest("GET", `/scans/${scan.id}/findings?severity=high`, owner.cookie);
    const severityBody = JSON.parse(severityFiltered.payload);
    expect(severityBody.findings).toHaveLength(1);
    expect(severityBody.findings[0].severity).toBe("high");
    expect(severityBody.counts).toEqual({ critical: 0, high: 1, medium: 0, low: 1, informational: 1, total: 3 });

    const confidenceFiltered = await authedRequest("GET", `/scans/${scan.id}/findings?confidence=low`, owner.cookie);
    expect(JSON.parse(confidenceFiltered.payload).findings).toHaveLength(1);

    const categoryFiltered = await authedRequest(
      "GET",
      `/scans/${scan.id}/findings?category=security-header`,
      owner.cookie,
    );
    expect(JSON.parse(categoryFiltered.payload).findings).toHaveLength(1);

    const sourceFiltered = await authedRequest("GET", `/scans/${scan.id}/findings?source=zap`, owner.cookie);
    expect(JSON.parse(sourceFiltered.payload).findings).toHaveLength(3);
  });

  it("paginates with limit/offset and reports hasMore", async () => {
    const owner = await registerOwner("paginate-findings@example.com");
    const scan = await seedScanWithFindings(
      owner,
      Array.from({ length: 5 }, (_, i) => sampleFinding({ sourceRuleId: `rule-${i}`, title: `Finding ${i}` })),
    );

    const firstPage = await authedRequest("GET", `/scans/${scan.id}/findings?limit=2&offset=0`, owner.cookie);
    const firstBody = JSON.parse(firstPage.payload);
    expect(firstBody.findings).toHaveLength(2);
    expect(firstBody.hasMore).toBe(true);

    const lastPage = await authedRequest("GET", `/scans/${scan.id}/findings?limit=2&offset=4`, owner.cookie);
    const lastBody = JSON.parse(lastPage.payload);
    expect(lastBody.findings).toHaveLength(1);
    expect(lastBody.hasMore).toBe(false);
  });

  it("returns an empty list with zero counts for a scan with no findings", async () => {
    const owner = await registerOwner("empty-findings@example.com");
    const scan = await seedScanWithFindings(owner, []);

    const response = await authedRequest("GET", `/scans/${scan.id}/findings`, owner.cookie);
    const body = JSON.parse(response.payload);
    expect(body.findings).toEqual([]);
    expect(body.counts).toEqual({ critical: 0, high: 0, medium: 0, low: 0, informational: 0, total: 0 });
  });
});

describe("GET /findings/:id", () => {
  it("rejects an unauthenticated request with 401", async () => {
    const response = await app.inject({ method: "GET", url: "/findings/00000000-0000-0000-0000-000000000000" });
    expect(response.statusCode).toBe(401);
  });

  it("returns the finding with instances when the caller owns its scan", async () => {
    const owner = await registerOwner("finding-detail@example.com");
    const scan = await seedScanWithFindings(owner, [
      sampleFinding({
        instances: [
          { url: "https://staging.acme.example.com/a", method: "GET", parameter: "q" },
          { url: "https://staging.acme.example.com/b", method: "POST", parameter: "name" },
        ],
      }),
    ]);
    const created = [...findings.rows.values()].find((f) => f.scanId === scan.id)!;

    const response = await authedRequest("GET", `/findings/${created.id}`, owner.cookie);
    expect(response.statusCode).toBe(200);
    const body = JSON.parse(response.payload);
    expect(body.finding.id).toBe(created.id);
    expect(body.finding.instances).toHaveLength(2);
    expect(body.finding.cweId).toBe(79);
    expect(body.finding.references).toEqual(["https://owasp.org/xss"]);
    // Never leaks internal/Prisma-only fields.
    expect(body.finding.requestedById).toBeUndefined();
  });

  it("returns an indistinguishable 404 for another user's finding and a nonexistent one", async () => {
    const owner = await registerOwner("finding-owner@example.com");
    const other = await registerOwner("finding-other@example.com");
    const scan = await seedScanWithFindings(owner, [sampleFinding()]);
    const created = [...findings.rows.values()].find((f) => f.scanId === scan.id)!;

    const foreignResponse = await authedRequest("GET", `/findings/${created.id}`, other.cookie);
    const nonexistentResponse = await authedRequest(
      "GET",
      "/findings/00000000-0000-0000-0000-000000000000",
      other.cookie,
    );

    expect(foreignResponse.statusCode).toBe(404);
    expect(nonexistentResponse.statusCode).toBe(404);
    expect(JSON.parse(foreignResponse.payload)).toEqual(JSON.parse(nonexistentResponse.payload));
  });
});
