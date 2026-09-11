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
import { NoOpScanExecutor } from "./helpers/fake-scan-executor.js";
import { cancelScan, completeScan, failScan, startScan } from "../src/modules/scans/scan.service.js";

const AUTH_COOKIE = "sentinelscan_token";

let app: FastifyInstance;
let users: InMemoryUserRepository;
let tokens: InMemoryVerificationTokenRepository;
let emailService: MockEmailService;
let targets: InMemoryTargetRepository;
let scans: InMemoryScanRepository;
let scanExecutor: NoOpScanExecutor;

function cookieValue(response: { cookies: Array<Record<string, unknown>> }, name: string): string | undefined {
  const cookie = response.cookies.find((entry) => entry.name === name);
  return cookie ? String(cookie.value) : undefined;
}

/** Registers a fresh verified user and returns their session cookie value. */
async function createSession(email: string): Promise<string> {
  await app.inject({
    method: "POST",
    url: "/auth/register",
    payload: { email, name: "Scan Requester", password: "Str0ngPassphrase" },
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
  const token = cookieValue(verifyRes, AUTH_COOKIE);
  if (!token) {
    throw new Error(`verification did not set an authentication cookie for ${email}`);
  }
  return token;
}

function authedRequest(
  method: "GET" | "POST" | "PATCH" | "DELETE",
  url: string,
  cookie: string,
  payload?: Record<string, unknown>,
) {
  return app.inject({
    method,
    url,
    cookies: { [AUTH_COOKIE]: cookie },
    payload,
  });
}

async function createTarget(cookie: string, overrides: Record<string, unknown> = {}): Promise<string> {
  const response = await authedRequest("POST", "/targets", cookie, {
    name: "Acme Staging",
    url: "https://staging.acme.example.com",
    ...overrides,
  });
  return JSON.parse(response.payload).target.id;
}

async function createScanViaApi(cookie: string, targetId: string) {
  return authedRequest("POST", `/targets/${targetId}/scans`, cookie, {});
}

beforeAll(async () => {
  users = createInMemoryUserRepository();
  tokens = createInMemoryVerificationTokenRepository();
  emailService = new MockEmailService();
  targets = createInMemoryTargetRepository();
  scans = createInMemoryScanRepository();
  scanExecutor = new NoOpScanExecutor();
  app = buildApp({
    userRepository: users,
    tokenRepository: tokens,
    emailService,
    targetRepository: targets,
    scanRepository: scans,
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
  scanExecutor.reset();
});

afterAll(async () => {
  await app.close();
});

describe("Authentication", () => {
  it("rejects an unauthenticated POST /targets/:targetId/scans with 401", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/targets/00000000-0000-0000-0000-000000000000/scans",
    });

    expect(response.statusCode).toBe(401);
    expect(scans.rows.size).toBe(0);
  });

  it("rejects an unauthenticated GET /scans with 401", async () => {
    const response = await app.inject({ method: "GET", url: "/scans" });

    expect(response.statusCode).toBe(401);
  });

  it("rejects an unauthenticated GET /scans/:id with 401", async () => {
    const response = await app.inject({
      method: "GET",
      url: "/scans/00000000-0000-0000-0000-000000000000",
    });

    expect(response.statusCode).toBe(401);
  });

  it("rejects an unauthenticated POST /scans/:id/cancel with 401", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/scans/00000000-0000-0000-0000-000000000000/cancel",
    });

    expect(response.statusCode).toBe(401);
  });
});

describe("POST /targets/:targetId/scans — creation", () => {
  it("creates a queued scan for the caller's own active target", async () => {
    const session = await createSession("owner-a@example.com");
    const targetId = await createTarget(session);

    const response = await createScanViaApi(session, targetId);

    expect(response.statusCode).toBe(201);
    const body = JSON.parse(response.payload);
    expect(body.scan).toMatchObject({
      targetId,
      status: "queued",
      startedAt: null,
      completedAt: null,
      errorMessage: null,
    });
    expect(typeof body.scan.id).toBe("string");
    expect(typeof body.scan.createdAt).toBe("string");
    expect(body.scan).not.toHaveProperty("requestedById");
  });

  it("derives requestedById from the authenticated session, not the client", async () => {
    const session = await createSession("owner-a@example.com");
    const targetId = await createTarget(session);
    const owner = await users.findByEmail("owner-a@example.com");

    const response = await createScanViaApi(session, targetId);

    const scanId = JSON.parse(response.payload).scan.id;
    const stored = scans.rows.get(scanId);
    expect(stored?.requestedById).toBe(owner?.id);
  });

  it("hands the new scan to the configured ScanExecutor", async () => {
    const session = await createSession("owner-a@example.com");
    const targetId = await createTarget(session);

    const response = await createScanViaApi(session, targetId);
    const scanId = JSON.parse(response.payload).scan.id;

    // The executor runs in the background (fire-and-forget); give it a tick
    // to be invoked before asserting on it.
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(scanExecutor.calls).toHaveLength(1);
    expect(scanExecutor.calls[0]).toMatchObject({ scanId, targetId, targetUrl: "https://staging.acme.example.com/" });
  });

  it("passes the persisted Target.url to the executor, never process.env.LIVE_TARGET_URL", async () => {
    // LIVE_TARGET_URL is a live-integration-test-only variable (see
    // tests/live-integration.test.ts); it is not part of the application's
    // env schema (src/config.ts) and createScan/ZapScanExecutor never read
    // it. Setting it here to a deliberately different, decoy value and
    // asserting the executor still receives the target's own URL proves
    // that production scan execution is wired to Scan → Target → Target.url
    // and not to this environment variable.
    const previous = process.env.LIVE_TARGET_URL;
    process.env.LIVE_TARGET_URL = "https://decoy-should-never-be-used.example.com";

    try {
      const session = await createSession("owner-live-target-check@example.com");
      const targetId = await createTarget(session, { url: "https://app-under-test.example.com" });

      const response = await createScanViaApi(session, targetId);
      const scanId = JSON.parse(response.payload).scan.id;

      await new Promise((resolve) => setTimeout(resolve, 0));

      const call = scanExecutor.calls.find((entry) => entry.scanId === scanId);
      expect(call).toMatchObject({
        targetId,
        targetUrl: "https://app-under-test.example.com/",
      });
      expect(call?.targetUrl).not.toContain("decoy-should-never-be-used");
      expect(call?.targetUrl).not.toBe(process.env.LIVE_TARGET_URL);
    } finally {
      if (previous === undefined) {
        delete process.env.LIVE_TARGET_URL;
      } else {
        process.env.LIVE_TARGET_URL = previous;
      }
    }
  });

  it("ignores a client-supplied requestedById, status, startedAt and completedAt", async () => {
    const session = await createSession("owner-a@example.com");
    const targetId = await createTarget(session);
    const owner = await users.findByEmail("owner-a@example.com");

    const response = await authedRequest("POST", `/targets/${targetId}/scans`, session, {
      requestedById: "11111111-1111-1111-1111-111111111111",
      status: "completed",
      startedAt: "2020-01-01T00:00:00.000Z",
      completedAt: "2020-01-01T00:00:00.000Z",
    });

    expect(response.statusCode).toBe(201);
    const body = JSON.parse(response.payload);
    expect(body.scan.status).toBe("queued");
    expect(body.scan.startedAt).toBeNull();
    expect(body.scan.completedAt).toBeNull();

    const stored = scans.rows.get(body.scan.id);
    expect(stored?.requestedById).toBe(owner?.id);
    expect(stored?.status).toBe("queued");
  });

  it("rejects scanning an inactive target with 409", async () => {
    const session = await createSession("owner-a@example.com");
    const targetId = await createTarget(session);
    await authedRequest("PATCH", `/targets/${targetId}`, session, { status: "inactive" });

    const response = await createScanViaApi(session, targetId);

    expect(response.statusCode).toBe(409);
    expect(JSON.parse(response.payload).code).toBe("TARGET_NOT_ACTIVE");
    expect(scans.rows.size).toBe(0);
  });

  it("rejects a nonexistent target with 404", async () => {
    const session = await createSession("owner-a@example.com");

    const response = await createScanViaApi(session, "00000000-0000-0000-0000-000000000000");

    expect(response.statusCode).toBe(404);
    expect(JSON.parse(response.payload).code).toBe("TARGET_NOT_FOUND");
  });

  it("rejects another user's target with the same indistinguishable 404", async () => {
    const sessionA = await createSession("owner-a@example.com");
    const sessionB = await createSession("owner-b@example.com");
    const targetB = await createTarget(sessionB);

    const foreignRes = await createScanViaApi(sessionA, targetB);
    const missingRes = await createScanViaApi(sessionA, "00000000-0000-0000-0000-000000000000");

    expect(foreignRes.statusCode).toBe(404);
    expect(foreignRes.statusCode).toBe(missingRes.statusCode);
    expect(JSON.parse(foreignRes.payload)).toEqual(JSON.parse(missingRes.payload));
    expect(scans.rows.size).toBe(0);
  });

  it("rejects a malformed target id with 400", async () => {
    const session = await createSession("owner-a@example.com");

    const response = await createScanViaApi(session, "not-a-uuid");

    expect(response.statusCode).toBe(400);
    expect(JSON.parse(response.payload).code).toBe("VALIDATION_ERROR");
  });
});

describe("GET /scans — listing and isolation", () => {
  it("returns only the authenticated user's scans", async () => {
    const sessionA = await createSession("owner-a@example.com");
    const sessionB = await createSession("owner-b@example.com");
    const targetA = await createTarget(sessionA);
    const targetB = await createTarget(sessionB, { url: "https://other.example.com" });
    await createScanViaApi(sessionA, targetA);
    await createScanViaApi(sessionB, targetB);

    const response = await authedRequest("GET", "/scans", sessionA);

    expect(response.statusCode).toBe(200);
    const body = JSON.parse(response.payload);
    expect(body.scans).toHaveLength(1);
    expect(body.scans[0].targetId).toBe(targetA);
  });

  it("returns an empty list for a user with no scans", async () => {
    const session = await createSession("owner-a@example.com");

    const response = await authedRequest("GET", "/scans", session);

    expect(response.statusCode).toBe(200);
    expect(JSON.parse(response.payload).scans).toEqual([]);
  });

  it("filters by status", async () => {
    const session = await createSession("owner-a@example.com");
    const targetA = await createTarget(session);
    const targetB = await createTarget(session, { url: "https://second.example.com" });

    const queuedRes = await createScanViaApi(session, targetA);
    const queuedId = JSON.parse(queuedRes.payload).scan.id;

    const runningRes = await createScanViaApi(session, targetB);
    const runningId = JSON.parse(runningRes.payload).scan.id;
    await startScan(scans, runningId);

    const runningFiltered = await authedRequest("GET", "/scans?status=running", session);
    expect(JSON.parse(runningFiltered.payload).scans.map((s: { id: string }) => s.id)).toEqual([runningId]);

    const queuedFiltered = await authedRequest("GET", "/scans?status=queued", session);
    expect(JSON.parse(queuedFiltered.payload).scans.map((s: { id: string }) => s.id)).toEqual([queuedId]);
  });

  it("filters by targetId", async () => {
    const session = await createSession("owner-a@example.com");
    const targetA = await createTarget(session);
    const targetB = await createTarget(session, { url: "https://second.example.com" });
    await createScanViaApi(session, targetA);
    await createScanViaApi(session, targetB);

    const response = await authedRequest("GET", `/scans?targetId=${targetA}`, session);

    expect(response.statusCode).toBe(200);
    const body = JSON.parse(response.payload);
    expect(body.scans).toHaveLength(1);
    expect(body.scans[0].targetId).toBe(targetA);
  });

  it("does not leak another user's scans through a targetId filter", async () => {
    const sessionA = await createSession("owner-a@example.com");
    const sessionB = await createSession("owner-b@example.com");
    const targetB = await createTarget(sessionB);
    await createScanViaApi(sessionB, targetB);

    const response = await authedRequest("GET", `/scans?targetId=${targetB}`, sessionA);

    expect(response.statusCode).toBe(200);
    expect(JSON.parse(response.payload).scans).toEqual([]);
  });

  it("paginates with limit/offset and reports hasMore", async () => {
    const session = await createSession("owner-a@example.com");
    for (let i = 0; i < 3; i += 1) {
      const targetId = await createTarget(session, { url: `https://target-${i}.example.com` });
      await createScanViaApi(session, targetId);
    }

    const firstPage = await authedRequest("GET", "/scans?limit=2&offset=0", session);
    const secondPage = await authedRequest("GET", "/scans?limit=2&offset=2", session);

    const firstBody = JSON.parse(firstPage.payload);
    const secondBody = JSON.parse(secondPage.payload);
    expect(firstBody.scans).toHaveLength(2);
    expect(firstBody.hasMore).toBe(true);
    expect(secondBody.scans).toHaveLength(1);
    expect(secondBody.hasMore).toBe(false);
  });

  it("rejects an out-of-range limit with 400", async () => {
    const session = await createSession("owner-a@example.com");

    const response = await authedRequest("GET", "/scans?limit=1000", session);

    expect(response.statusCode).toBe(400);
  });
});

describe("GET /scans/:id — isolation", () => {
  it("returns a scan requested by the authenticated user", async () => {
    const session = await createSession("owner-a@example.com");
    const targetId = await createTarget(session);
    const created = JSON.parse((await createScanViaApi(session, targetId)).payload);

    const response = await authedRequest("GET", `/scans/${created.scan.id}`, session);

    expect(response.statusCode).toBe(200);
    expect(JSON.parse(response.payload).scan.id).toBe(created.scan.id);
  });

  it("user A cannot retrieve user B's scan", async () => {
    const sessionA = await createSession("owner-a@example.com");
    const sessionB = await createSession("owner-b@example.com");
    const targetB = await createTarget(sessionB);
    const created = JSON.parse((await createScanViaApi(sessionB, targetB)).payload);

    const response = await authedRequest("GET", `/scans/${created.scan.id}`, sessionA);

    expect(response.statusCode).toBe(404);
    expect(JSON.parse(response.payload).code).toBe("SCAN_NOT_FOUND");
  });

  it("returns 404 for a nonexistent (but well-formed) scan id", async () => {
    const session = await createSession("owner-a@example.com");

    const response = await authedRequest("GET", "/scans/00000000-0000-0000-0000-000000000000", session);

    expect(response.statusCode).toBe(404);
  });

  it("returns 400 for a malformed scan id", async () => {
    const session = await createSession("owner-a@example.com");

    const response = await authedRequest("GET", "/scans/not-a-uuid", session);

    expect(response.statusCode).toBe(400);
  });
});

describe("Internal lifecycle transitions (scan.service.ts)", () => {
  async function createQueuedScan(session: string, targetId?: string): Promise<string> {
    const tid = targetId ?? (await createTarget(session, { url: `https://t-${Date.now()}-${Math.random()}.example.com` }));
    const created = JSON.parse((await createScanViaApi(session, tid)).payload);
    return created.scan.id;
  }

  it("queued → running sets startedAt", async () => {
    const session = await createSession("owner-a@example.com");
    const scanId = await createQueuedScan(session);

    const updated = await startScan(scans, scanId);

    expect(updated.status).toBe("running");
    expect(updated.startedAt).toBeInstanceOf(Date);
    expect(updated.completedAt).toBeNull();
  });

  it("queued → cancelled sets completedAt and leaves startedAt null", async () => {
    const session = await createSession("owner-a@example.com");
    const scanId = await createQueuedScan(session);
    const owner = await users.findByEmail("owner-a@example.com");

    const updated = await cancelScan(scans, owner!.id, scanId);

    expect(updated.status).toBe("cancelled");
    expect(updated.startedAt).toBeNull();
    expect(updated.completedAt).toBeInstanceOf(Date);
  });

  it("running → completed sets completedAt", async () => {
    const session = await createSession("owner-a@example.com");
    const scanId = await createQueuedScan(session);
    await startScan(scans, scanId);

    const updated = await completeScan(scans, scanId);

    expect(updated.status).toBe("completed");
    expect(updated.completedAt).toBeInstanceOf(Date);
    expect(updated.startedAt).toBeInstanceOf(Date);
  });

  it("running → failed sets completedAt and errorMessage", async () => {
    const session = await createSession("owner-a@example.com");
    const scanId = await createQueuedScan(session);
    await startScan(scans, scanId);

    const updated = await failScan(scans, scanId, "connection refused");

    expect(updated.status).toBe("failed");
    expect(updated.completedAt).toBeInstanceOf(Date);
    expect(updated.errorMessage).toBe("connection refused");
  });

  it("running → cancelled preserves the already-set startedAt", async () => {
    const session = await createSession("owner-a@example.com");
    const scanId = await createQueuedScan(session);
    const owner = await users.findByEmail("owner-a@example.com");
    const started = await startScan(scans, scanId);

    const updated = await cancelScan(scans, owner!.id, scanId);

    expect(updated.status).toBe("cancelled");
    expect(updated.startedAt?.getTime()).toBe(started.startedAt?.getTime());
    expect(updated.completedAt).toBeInstanceOf(Date);
  });

  describe("invalid transitions are rejected", () => {
    async function terminalScan(status: "completed" | "failed" | "cancelled"): Promise<{ id: string; ownerId: string }> {
      const session = await createSession(`owner-${status}@example.com`);
      const owner = await users.findByEmail(`owner-${status}@example.com`);
      const scanId = await createQueuedScan(session);
      await startScan(scans, scanId);
      if (status === "completed") await completeScan(scans, scanId);
      if (status === "failed") await failScan(scans, scanId);
      if (status === "cancelled") await cancelScan(scans, owner!.id, scanId);
      return { id: scanId, ownerId: owner!.id };
    }

    it("rejects completed → running/completed/failed/cancelled", async () => {
      const { id, ownerId } = await terminalScan("completed");

      await expect(startScan(scans, id)).rejects.toMatchObject({ code: "INVALID_SCAN_TRANSITION" });
      await expect(completeScan(scans, id)).rejects.toMatchObject({ code: "INVALID_SCAN_TRANSITION" });
      await expect(failScan(scans, id)).rejects.toMatchObject({ code: "INVALID_SCAN_TRANSITION" });
      await expect(cancelScan(scans, ownerId, id)).rejects.toMatchObject({ code: "INVALID_SCAN_TRANSITION" });
    });

    it("rejects failed → running/completed/failed/cancelled", async () => {
      const { id, ownerId } = await terminalScan("failed");

      await expect(startScan(scans, id)).rejects.toMatchObject({ code: "INVALID_SCAN_TRANSITION" });
      await expect(completeScan(scans, id)).rejects.toMatchObject({ code: "INVALID_SCAN_TRANSITION" });
      await expect(failScan(scans, id)).rejects.toMatchObject({ code: "INVALID_SCAN_TRANSITION" });
      await expect(cancelScan(scans, ownerId, id)).rejects.toMatchObject({ code: "INVALID_SCAN_TRANSITION" });
    });

    it("rejects cancelled → running/completed/failed/cancelled", async () => {
      const { id, ownerId } = await terminalScan("cancelled");

      await expect(startScan(scans, id)).rejects.toMatchObject({ code: "INVALID_SCAN_TRANSITION" });
      await expect(completeScan(scans, id)).rejects.toMatchObject({ code: "INVALID_SCAN_TRANSITION" });
      await expect(failScan(scans, id)).rejects.toMatchObject({ code: "INVALID_SCAN_TRANSITION" });
      await expect(cancelScan(scans, ownerId, id)).rejects.toMatchObject({ code: "INVALID_SCAN_TRANSITION" });
    });

    it("rejects queued → completed directly", async () => {
      const session = await createSession("owner-a@example.com");
      const scanId = await createQueuedScan(session);

      await expect(completeScan(scans, scanId)).rejects.toMatchObject({ code: "INVALID_SCAN_TRANSITION" });
    });

    it("rejects queued → failed directly", async () => {
      const session = await createSession("owner-a@example.com");
      const scanId = await createQueuedScan(session);

      await expect(failScan(scans, scanId)).rejects.toMatchObject({ code: "INVALID_SCAN_TRANSITION" });
    });
  });
});

describe("POST /scans/:id/cancel", () => {
  it("cancels a queued scan", async () => {
    const session = await createSession("owner-a@example.com");
    const targetId = await createTarget(session);
    const created = JSON.parse((await createScanViaApi(session, targetId)).payload);

    const response = await authedRequest("POST", `/scans/${created.scan.id}/cancel`, session);

    expect(response.statusCode).toBe(200);
    expect(JSON.parse(response.payload).scan.status).toBe("cancelled");
  });

  it("cancels a running scan", async () => {
    const session = await createSession("owner-a@example.com");
    const targetId = await createTarget(session);
    const created = JSON.parse((await createScanViaApi(session, targetId)).payload);
    await startScan(scans, created.scan.id);

    const response = await authedRequest("POST", `/scans/${created.scan.id}/cancel`, session);

    expect(response.statusCode).toBe(200);
    expect(JSON.parse(response.payload).scan.status).toBe("cancelled");
  });

  it("cannot cancel a completed scan", async () => {
    const session = await createSession("owner-a@example.com");
    const targetId = await createTarget(session);
    const created = JSON.parse((await createScanViaApi(session, targetId)).payload);
    await startScan(scans, created.scan.id);
    await completeScan(scans, created.scan.id);

    const response = await authedRequest("POST", `/scans/${created.scan.id}/cancel`, session);

    expect(response.statusCode).toBe(409);
    expect(JSON.parse(response.payload).code).toBe("INVALID_SCAN_TRANSITION");
  });

  it("cannot cancel a failed scan", async () => {
    const session = await createSession("owner-a@example.com");
    const targetId = await createTarget(session);
    const created = JSON.parse((await createScanViaApi(session, targetId)).payload);
    await startScan(scans, created.scan.id);
    await failScan(scans, created.scan.id);

    const response = await authedRequest("POST", `/scans/${created.scan.id}/cancel`, session);

    expect(response.statusCode).toBe(409);
    expect(JSON.parse(response.payload).code).toBe("INVALID_SCAN_TRANSITION");
  });

  it("cannot cancel an already-cancelled scan", async () => {
    const session = await createSession("owner-a@example.com");
    const targetId = await createTarget(session);
    const created = JSON.parse((await createScanViaApi(session, targetId)).payload);
    await authedRequest("POST", `/scans/${created.scan.id}/cancel`, session);

    const response = await authedRequest("POST", `/scans/${created.scan.id}/cancel`, session);

    expect(response.statusCode).toBe(409);
    expect(JSON.parse(response.payload).code).toBe("INVALID_SCAN_TRANSITION");
  });

  it("user A cannot cancel user B's scan", async () => {
    const sessionA = await createSession("owner-a@example.com");
    const sessionB = await createSession("owner-b@example.com");
    const targetB = await createTarget(sessionB);
    const created = JSON.parse((await createScanViaApi(sessionB, targetB)).payload);

    const response = await authedRequest("POST", `/scans/${created.scan.id}/cancel`, sessionA);

    expect(response.statusCode).toBe(404);
    expect(JSON.parse(response.payload).code).toBe("SCAN_NOT_FOUND");

    const stillQueued = await authedRequest("GET", `/scans/${created.scan.id}`, sessionB);
    expect(JSON.parse(stillQueued.payload).scan.status).toBe("queued");
  });

  it("keeps exactly one winner under concurrent cancellation", async () => {
    const session = await createSession("owner-a@example.com");
    const targetId = await createTarget(session);
    const created = JSON.parse((await createScanViaApi(session, targetId)).payload);

    const [first, second] = await Promise.all([
      authedRequest("POST", `/scans/${created.scan.id}/cancel`, session),
      authedRequest("POST", `/scans/${created.scan.id}/cancel`, session),
    ]);

    const statuses = [first.statusCode, second.statusCode].sort();
    expect(statuses).toEqual([200, 409]);

    const final = scans.rows.get(created.scan.id);
    expect(final?.status).toBe("cancelled");
  });
});

describe("ScanRepository — ownership conditions at the query/repository layer", () => {
  it("findByIdForOwner returns null for a scan owned by someone else", async () => {
    const repo = createInMemoryScanRepository();
    const scan = await repo.create({ targetId: "target-1", requestedById: "user-a" });

    await expect(repo.findByIdForOwner(scan.id, "user-b")).resolves.toBeNull();
    await expect(repo.findByIdForOwner(scan.id, "user-a")).resolves.toMatchObject({ id: scan.id });
  });

  it("listForOwner never returns rows for a different owner", async () => {
    const repo = createInMemoryScanRepository();
    await repo.create({ targetId: "target-1", requestedById: "user-a" });
    await repo.create({ targetId: "target-2", requestedById: "user-b" });

    const result = await repo.listForOwner("user-a", { limit: 20, offset: 0 });

    expect(result.scans).toHaveLength(1);
    expect(result.scans[0]).toMatchObject({ requestedById: "user-a" });
  });

  it("transitionStatus with an owner mismatch does not mutate the row", async () => {
    const repo = createInMemoryScanRepository();
    const scan = await repo.create({ targetId: "target-1", requestedById: "user-a" });

    const result = await repo.transitionStatus(scan.id, "queued", { status: "cancelled" }, "user-b");

    expect(result).toBeNull();
    const stored = repo.rows.get(scan.id);
    expect(stored?.status).toBe("queued");
  });

  it("transitionStatus with a stale fromStatus does not mutate the row", async () => {
    const repo = createInMemoryScanRepository();
    const scan = await repo.create({ targetId: "target-1", requestedById: "user-a" });
    await repo.transitionStatus(scan.id, "queued", { status: "running", startedAt: new Date() });

    // Now actually "running"; attempting the CAS against the stale "queued" must fail.
    const result = await repo.transitionStatus(scan.id, "queued", { status: "cancelled" });

    expect(result).toBeNull();
    expect(repo.rows.get(scan.id)?.status).toBe("running");
  });
});
