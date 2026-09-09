import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";
import { FastifyInstance } from "fastify";
import { buildApp } from "../src/app.js";
import { isGoogleOAuthConfigured } from "../src/config.js";
import { authenticateWithGoogle } from "../src/modules/auth/auth.service.js";
import { createInMemoryUserRepository, type InMemoryUserRepository } from "./helpers/in-memory-user.repository.js";

/**
 * These tests exercise the Google identity boundary without touching Google:
 * the account-resolution logic is driven directly with an already-verified
 * identity, and the HTTP routes are checked in their unconfigured state, which
 * is how CI runs (no `GOOGLE_*` variables are set).
 */

const identity = {
  googleId: "google-sub-12345",
  email: "Analyst@SentinelScan.io",
  name: "Google Analyst",
  emailVerified: true,
};

let app: FastifyInstance;
let users: InMemoryUserRepository;

beforeAll(async () => {
  users = createInMemoryUserRepository();
  app = buildApp({ userRepository: users });
  await app.ready();
});

beforeEach(() => {
  users.reset();
});

afterAll(async () => {
  await app.close();
});

// Skipped for a developer who has real Google credentials in their local .env;
// CI always runs unconfigured, which is the path these tests cover.
describe.skipIf(isGoogleOAuthConfigured())("Google OAuth routes without configuration", () => {
  it("responds to GET /auth/google with 503 instead of a routing error", async () => {
    const response = await app.inject({ method: "GET", url: "/auth/google" });

    expect(response.statusCode).toBe(503);
    expect(JSON.parse(response.payload).code).toBe("GOOGLE_OAUTH_NOT_CONFIGURED");
  });

  it("responds to GET /auth/google/callback with 503", async () => {
    const response = await app.inject({ method: "GET", url: "/auth/google/callback?code=irrelevant" });

    expect(response.statusCode).toBe(503);
    expect(JSON.parse(response.payload).code).toBe("GOOGLE_OAUTH_NOT_CONFIGURED");
  });

  it("does not leak configuration details in the error body", async () => {
    const response = await app.inject({ method: "GET", url: "/auth/google" });

    expect(response.payload).not.toContain("GOOGLE_CLIENT_SECRET");
    expect(response.payload).not.toContain("client_secret");
  });
});

describe("authenticateWithGoogle", () => {
  it("provisions a passwordless account for a first-time Google user", async () => {
    const user = await authenticateWithGoogle(users, identity);

    expect(user.email).toBe("analyst@sentinelscan.io");
    expect(user.googleId).toBe(identity.googleId);
    expect(user.passwordHash).toBeNull();
    expect(user.emailVerified).toBe(true);
    expect(users.rows.size).toBe(1);
  });

  it("reuses the account on a repeat sign-in", async () => {
    const first = await authenticateWithGoogle(users, identity);
    const second = await authenticateWithGoogle(users, identity);

    expect(second.id).toBe(first.id);
    expect(users.rows.size).toBe(1);
  });

  it("links an existing local account instead of creating a duplicate", async () => {
    const local = await users.create({
      email: "analyst@sentinelscan.io",
      name: "Security Analyst",
      passwordHash: "$2b$12$notarealhashbutlongenoughtolooklikeone000000000000000",
    });

    const linked = await authenticateWithGoogle(users, identity);

    expect(linked.id).toBe(local.id);
    expect(linked.googleId).toBe(identity.googleId);
    // The local credential survives linking, so the user keeps both sign-in paths.
    expect(linked.passwordHash).toBe(local.passwordHash);
    expect(linked.emailVerified).toBe(true);
    expect(users.rows.size).toBe(1);
  });

  it("records the sign-in timestamp", async () => {
    const user = await authenticateWithGoogle(users, identity);

    expect(user.lastLoginAt).toBeInstanceOf(Date);
  });
});
