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

const AUTH_COOKIE = "sentinelscan_token";

let app: FastifyInstance;
let users: InMemoryUserRepository;
let tokens: InMemoryVerificationTokenRepository;
let emailService: MockEmailService;
let targets: InMemoryTargetRepository;

function cookieValue(response: { cookies: Array<Record<string, unknown>> }, name: string): string | undefined {
  const cookie = response.cookies.find((entry) => entry.name === name);
  return cookie ? String(cookie.value) : undefined;
}

/** Registers a fresh verified user and returns their session cookie value. */
async function createSession(email: string): Promise<string> {
  await app.inject({
    method: "POST",
    url: "/auth/register",
    payload: { email, name: "Target Owner", password: "Str0ngPassphrase" },
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

function authedRequest(method: "GET" | "POST" | "PATCH" | "DELETE", url: string, cookie: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    cookies: { [AUTH_COOKIE]: cookie },
    ...(payload === undefined ? {} : { payload }),
  });
}

const validTarget = {
  name: "Acme Staging",
  url: "https://staging.acme.example.com/app",
  description: "Pre-production environment authorized for testing.",
};

beforeAll(async () => {
  users = createInMemoryUserRepository();
  tokens = createInMemoryVerificationTokenRepository();
  emailService = new MockEmailService();
  targets = createInMemoryTargetRepository();
  app = buildApp({
    userRepository: users,
    tokenRepository: tokens,
    emailService,
    targetRepository: targets,
  });
  await app.ready();
});

beforeEach(() => {
  users.reset();
  tokens.reset();
  emailService.reset();
  targets.reset();
});

afterAll(async () => {
  await app.close();
});

describe("Authentication", () => {
  it("rejects an unauthenticated GET /targets with 401", async () => {
    const response = await app.inject({ method: "GET", url: "/targets" });

    expect(response.statusCode).toBe(401);
    expect(JSON.parse(response.payload).code).toBe("UNAUTHORIZED");
  });

  it("rejects an unauthenticated POST /targets with 401 and creates nothing", async () => {
    const response = await app.inject({ method: "POST", url: "/targets", payload: validTarget });

    expect(response.statusCode).toBe(401);
    expect(targets.rows.size).toBe(0);
  });

  it("rejects unauthenticated GET/PATCH/DELETE on a specific target with 401", async () => {
    const getRes = await app.inject({ method: "GET", url: "/targets/00000000-0000-0000-0000-000000000000" });
    const patchRes = await app.inject({
      method: "PATCH",
      url: "/targets/00000000-0000-0000-0000-000000000000",
      payload: { name: "New name" },
    });
    const deleteRes = await app.inject({
      method: "DELETE",
      url: "/targets/00000000-0000-0000-0000-000000000000",
    });

    expect(getRes.statusCode).toBe(401);
    expect(patchRes.statusCode).toBe(401);
    expect(deleteRes.statusCode).toBe(401);
  });
});

describe("POST /targets — creation", () => {
  it("creates a target for the authenticated user, deriving ownership from the session", async () => {
    const session = await createSession("owner-a@example.com");

    const response = await authedRequest("POST", "/targets", session, validTarget);

    expect(response.statusCode).toBe(201);
    const body = JSON.parse(response.payload);
    expect(body.target).toMatchObject({
      name: "Acme Staging",
      url: "https://staging.acme.example.com/app",
      description: "Pre-production environment authorized for testing.",
      status: "active",
    });
    expect(typeof body.target.id).toBe("string");
    expect(body.target).not.toHaveProperty("ownerId");

    const owner = await users.findByEmail("owner-a@example.com");
    const stored = [...targets.rows.values()][0];
    expect(stored.ownerId).toBe(owner?.id);
  });

  it("ignores a client-supplied ownerId and derives it from the session instead", async () => {
    const session = await createSession("owner-a@example.com");
    const otherUserId = "11111111-1111-1111-1111-111111111111";

    const response = await authedRequest("POST", "/targets", session, {
      ...validTarget,
      ownerId: otherUserId,
    });

    expect(response.statusCode).toBe(201);
    const stored = [...targets.rows.values()][0];
    expect(stored.ownerId).not.toBe(otherUserId);
  });

  it("normalizes the URL (default port dropped, no trailing-slash inconsistency)", async () => {
    const session = await createSession("owner-a@example.com");

    const response = await authedRequest("POST", "/targets", session, {
      name: "Normalize me",
      url: "HTTPS://Example.COM:443/path",
    });

    expect(response.statusCode).toBe(201);
    expect(JSON.parse(response.payload).target.url).toBe("https://example.com/path");
  });

  it.each([
    ["a missing name", { url: validTarget.url }],
    ["a whitespace-only name", { name: "   ", url: validTarget.url }],
    ["a missing url", { name: "Acme" }],
    ["a javascript: URL", { name: "Acme", url: "javascript:alert(1)" }],
    ["a file: URL", { name: "Acme", url: "file:///etc/passwd" }],
    ["a data: URL", { name: "Acme", url: "data:text/html,<script>alert(1)</script>" }],
    ["a relative URL", { name: "Acme", url: "/just/a/path" }],
    ["a bare hostname", { name: "Acme", url: "example.com" }],
    ["a URL with embedded credentials", { name: "Acme", url: "https://user:pass@example.com" }],
  ])("rejects %s with 400 and creates nothing", async (_label, payload) => {
    const session = await createSession("owner-a@example.com");

    const response = await authedRequest("POST", "/targets", session, payload);

    expect(response.statusCode).toBe(400);
    expect(JSON.parse(response.payload).code).toBe("VALIDATION_ERROR");
    expect(targets.rows.size).toBe(0);
  });

  it("rejects a duplicate URL for the same owner with 409", async () => {
    const session = await createSession("owner-a@example.com");
    await authedRequest("POST", "/targets", session, validTarget);

    const response = await authedRequest("POST", "/targets", session, validTarget);

    expect(response.statusCode).toBe(409);
    expect(JSON.parse(response.payload).code).toBe("TARGET_ALREADY_EXISTS");
    expect(targets.rows.size).toBe(1);
  });

  it("ignores a client-supplied status on create, always starting a target active", async () => {
    const session = await createSession("owner-a@example.com");

    const response = await authedRequest("POST", "/targets", session, {
      ...validTarget,
      status: "inactive",
    });

    expect(response.statusCode).toBe(201);
    expect(JSON.parse(response.payload).target.status).toBe("active");
  });

  it("allows two different owners to register the same URL", async () => {
    const sessionA = await createSession("owner-a@example.com");
    const sessionB = await createSession("owner-b@example.com");

    const resA = await authedRequest("POST", "/targets", sessionA, validTarget);
    const resB = await authedRequest("POST", "/targets", sessionB, validTarget);

    expect(resA.statusCode).toBe(201);
    expect(resB.statusCode).toBe(201);
    expect(targets.rows.size).toBe(2);
  });
});

describe("GET /targets — listing", () => {
  it("returns only the authenticated user's targets", async () => {
    const sessionA = await createSession("owner-a@example.com");
    const sessionB = await createSession("owner-b@example.com");
    await authedRequest("POST", "/targets", sessionA, validTarget);
    await authedRequest("POST", "/targets", sessionB, { ...validTarget, url: "https://other.example.com" });

    const response = await authedRequest("GET", "/targets", sessionA);

    expect(response.statusCode).toBe(200);
    const body = JSON.parse(response.payload);
    expect(body.targets).toHaveLength(1);
    expect(body.targets[0].url).toBe(validTarget.url);
  });

  it("returns an empty list for a user with no targets", async () => {
    const session = await createSession("owner-a@example.com");

    const response = await authedRequest("GET", "/targets", session);

    expect(response.statusCode).toBe(200);
    expect(JSON.parse(response.payload).targets).toEqual([]);
  });
});

describe("GET /targets/:id — isolation", () => {
  it("returns a target owned by the authenticated user", async () => {
    const session = await createSession("owner-a@example.com");
    const created = JSON.parse((await authedRequest("POST", "/targets", session, validTarget)).payload);

    const response = await authedRequest("GET", `/targets/${created.target.id}`, session);

    expect(response.statusCode).toBe(200);
    expect(JSON.parse(response.payload).target.id).toBe(created.target.id);
  });

  it("user A cannot GET user B's target", async () => {
    const sessionA = await createSession("owner-a@example.com");
    const sessionB = await createSession("owner-b@example.com");
    const created = JSON.parse((await authedRequest("POST", "/targets", sessionB, validTarget)).payload);

    const response = await authedRequest("GET", `/targets/${created.target.id}`, sessionA);

    expect(response.statusCode).toBe(404);
    expect(JSON.parse(response.payload).code).toBe("TARGET_NOT_FOUND");
  });

  it("returns 404 for a nonexistent (but well-formed) target id", async () => {
    const session = await createSession("owner-a@example.com");

    const response = await authedRequest("GET", "/targets/00000000-0000-0000-0000-000000000000", session);

    expect(response.statusCode).toBe(404);
    expect(JSON.parse(response.payload).code).toBe("TARGET_NOT_FOUND");
  });

  it("returns 400 for a malformed target id", async () => {
    const session = await createSession("owner-a@example.com");

    const response = await authedRequest("GET", "/targets/not-a-uuid", session);

    expect(response.statusCode).toBe(400);
    expect(JSON.parse(response.payload).code).toBe("VALIDATION_ERROR");
  });

  it("returns identical error shapes for another user's target and a nonexistent one", async () => {
    const sessionA = await createSession("owner-a@example.com");
    const sessionB = await createSession("owner-b@example.com");
    const created = JSON.parse((await authedRequest("POST", "/targets", sessionB, validTarget)).payload);

    const foreignRes = await authedRequest("GET", `/targets/${created.target.id}`, sessionA);
    const missingRes = await authedRequest("GET", "/targets/00000000-0000-0000-0000-000000000000", sessionA);

    expect(foreignRes.statusCode).toBe(missingRes.statusCode);
    expect(JSON.parse(foreignRes.payload)).toEqual(JSON.parse(missingRes.payload));
  });
});

describe("PATCH /targets/:id", () => {
  it("updates name, url, description and status", async () => {
    const session = await createSession("owner-a@example.com");
    const created = JSON.parse((await authedRequest("POST", "/targets", session, validTarget)).payload);

    const response = await authedRequest("PATCH", `/targets/${created.target.id}`, session, {
      name: "Renamed",
      url: "https://renamed.example.com",
      description: "Updated description",
      status: "inactive",
    });

    expect(response.statusCode).toBe(200);
    const body = JSON.parse(response.payload);
    expect(body.target).toMatchObject({
      name: "Renamed",
      url: "https://renamed.example.com/",
      description: "Updated description",
      status: "inactive",
    });
  });

  it("supports partial updates, leaving other fields untouched", async () => {
    const session = await createSession("owner-a@example.com");
    const created = JSON.parse((await authedRequest("POST", "/targets", session, validTarget)).payload);

    const response = await authedRequest("PATCH", `/targets/${created.target.id}`, session, {
      status: "inactive",
    });

    expect(response.statusCode).toBe(200);
    const body = JSON.parse(response.payload);
    expect(body.target.status).toBe("inactive");
    expect(body.target.name).toBe(validTarget.name);
    expect(body.target.url).toBe(validTarget.url);
  });

  it("clears the description when explicitly set to null", async () => {
    const session = await createSession("owner-a@example.com");
    const created = JSON.parse((await authedRequest("POST", "/targets", session, validTarget)).payload);

    const response = await authedRequest("PATCH", `/targets/${created.target.id}`, session, {
      description: null,
    });

    expect(response.statusCode).toBe(200);
    expect(JSON.parse(response.payload).target.description).toBeNull();
  });

  it("user A cannot PATCH user B's target", async () => {
    const sessionA = await createSession("owner-a@example.com");
    const sessionB = await createSession("owner-b@example.com");
    const created = JSON.parse((await authedRequest("POST", "/targets", sessionB, validTarget)).payload);

    const response = await authedRequest("PATCH", `/targets/${created.target.id}`, sessionA, {
      name: "Hijacked",
    });

    expect(response.statusCode).toBe(404);
    expect(JSON.parse(response.payload).code).toBe("TARGET_NOT_FOUND");

    // The target itself is untouched.
    const stillOwnedByB = await authedRequest("GET", `/targets/${created.target.id}`, sessionB);
    expect(JSON.parse(stillOwnedByB.payload).target.name).toBe(validTarget.name);
  });

  it("rejects an invalid status value with 400", async () => {
    const session = await createSession("owner-a@example.com");
    const created = JSON.parse((await authedRequest("POST", "/targets", session, validTarget)).payload);

    const response = await authedRequest("PATCH", `/targets/${created.target.id}`, session, {
      status: "archived",
    });

    expect(response.statusCode).toBe(400);
    expect(JSON.parse(response.payload).code).toBe("VALIDATION_ERROR");
  });

  it("rejects an invalid url on update with 400", async () => {
    const session = await createSession("owner-a@example.com");
    const created = JSON.parse((await authedRequest("POST", "/targets", session, validTarget)).payload);

    const response = await authedRequest("PATCH", `/targets/${created.target.id}`, session, {
      url: "javascript:alert(1)",
    });

    expect(response.statusCode).toBe(400);
    expect(JSON.parse(response.payload).code).toBe("VALIDATION_ERROR");
  });

  it("returns 404 for a nonexistent target", async () => {
    const session = await createSession("owner-a@example.com");

    const response = await authedRequest(
      "PATCH",
      "/targets/00000000-0000-0000-0000-000000000000",
      session,
      { name: "Anything" },
    );

    expect(response.statusCode).toBe(404);
  });

  it("rejects renaming a URL to one that collides with another of the owner's targets", async () => {
    const session = await createSession("owner-a@example.com");
    await authedRequest("POST", "/targets", session, validTarget);
    const second = JSON.parse(
      (await authedRequest("POST", "/targets", session, { ...validTarget, url: "https://second.example.com" }))
        .payload,
    );

    const response = await authedRequest("PATCH", `/targets/${second.target.id}`, session, {
      url: validTarget.url,
    });

    expect(response.statusCode).toBe(409);
    expect(JSON.parse(response.payload).code).toBe("TARGET_ALREADY_EXISTS");
  });
});

describe("DELETE /targets/:id", () => {
  it("deletes a target owned by the authenticated user", async () => {
    const session = await createSession("owner-a@example.com");
    const created = JSON.parse((await authedRequest("POST", "/targets", session, validTarget)).payload);

    const response = await authedRequest("DELETE", `/targets/${created.target.id}`, session);

    expect(response.statusCode).toBe(204);
    expect(targets.rows.size).toBe(0);
  });

  it("user A cannot DELETE user B's target", async () => {
    const sessionA = await createSession("owner-a@example.com");
    const sessionB = await createSession("owner-b@example.com");
    const created = JSON.parse((await authedRequest("POST", "/targets", sessionB, validTarget)).payload);

    const response = await authedRequest("DELETE", `/targets/${created.target.id}`, sessionA);

    expect(response.statusCode).toBe(404);
    expect(JSON.parse(response.payload).code).toBe("TARGET_NOT_FOUND");
    expect(targets.rows.size).toBe(1);
  });

  it("returns 404 for a nonexistent target", async () => {
    const session = await createSession("owner-a@example.com");

    const response = await authedRequest("DELETE", "/targets/00000000-0000-0000-0000-000000000000", session);

    expect(response.statusCode).toBe(404);
  });

  it("returns 400 for a malformed target id", async () => {
    const session = await createSession("owner-a@example.com");

    const response = await authedRequest("DELETE", "/targets/not-a-uuid", session);

    expect(response.statusCode).toBe(400);
  });
});
