import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";
import bcrypt from "bcryptjs";
import { FastifyInstance } from "fastify";
import { buildApp } from "../src/app.js";
import { createInMemoryUserRepository, type InMemoryUserRepository } from "./helpers/in-memory-user.repository.js";

const AUTH_COOKIE = "sentinelscan_token";

const validRegistration = {
  email: "Analyst@SentinelScan.io",
  name: "Security Analyst",
  password: "Str0ngPassphrase",
};

let app: FastifyInstance;
let users: InMemoryUserRepository;

function cookieValue(response: { cookies: Array<Record<string, unknown>> }, name: string): string | undefined {
  const cookie = response.cookies.find((entry) => entry.name === name);
  return cookie ? String(cookie.value) : undefined;
}

async function register(body: Record<string, unknown> | undefined = validRegistration) {
  return app.inject({ method: "POST", url: "/auth/register", payload: body });
}

async function login(email = validRegistration.email, password = validRegistration.password) {
  return app.inject({ method: "POST", url: "/auth/login", payload: { email, password } });
}

/** Registers the default user and returns a usable session cookie value. */
async function registerAndLogin(): Promise<string> {
  await register();
  const response = await login();
  const token = cookieValue(response, AUTH_COOKIE);
  if (!token) {
    throw new Error("login did not set an authentication cookie");
  }
  return token;
}

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

describe("POST /auth/register", () => {
  it("creates the account and returns a safe user representation", async () => {
    const response = await register();

    expect(response.statusCode).toBe(201);
    const body = JSON.parse(response.payload);
    expect(body.user).toMatchObject({
      email: "analyst@sentinelscan.io",
      name: "Security Analyst",
      emailVerified: false,
      hasPassword: true,
      googleLinked: false,
    });
    expect(typeof body.user.id).toBe("string");
    expect(typeof body.user.createdAt).toBe("string");
  });

  it("never returns the password or its hash", async () => {
    const response = await register();

    expect(response.payload).not.toContain(validRegistration.password);
    expect(response.payload).not.toContain("passwordHash");
    expect(response.payload).not.toContain("$2b$");
    const body = JSON.parse(response.payload);
    expect(body.user).not.toHaveProperty("password");
    expect(body.user).not.toHaveProperty("passwordHash");
  });

  it("stores a bcrypt hash rather than the plaintext password", async () => {
    await register();

    const stored = [...users.rows.values()][0];
    expect(stored).toBeDefined();
    expect(stored?.passwordHash).toBeTypeOf("string");
    expect(stored?.passwordHash).not.toBe(validRegistration.password);
    expect(stored?.passwordHash).toMatch(/^\$2[aby]\$\d{2}\$/);
    await expect(bcrypt.compare(validRegistration.password, stored?.passwordHash ?? "")).resolves.toBe(true);
  });

  it("normalizes the email before persisting it", async () => {
    await register({ ...validRegistration, email: "  MiXeD@Example.COM  " });

    const stored = [...users.rows.values()][0];
    expect(stored?.email).toBe("mixed@example.com");
  });

  it("rejects a duplicate email regardless of casing", async () => {
    await register();
    const response = await register({ ...validRegistration, email: "ANALYST@sentinelscan.io" });

    expect(response.statusCode).toBe(409);
    const body = JSON.parse(response.payload);
    expect(body.code).toBe("EMAIL_ALREADY_REGISTERED");
    expect(users.rows.size).toBe(1);
  });

  it.each([
    ["an empty body", {}],
    ["an invalid email", { ...validRegistration, email: "not-an-email" }],
    ["a missing name", { email: "user@example.com", password: "Str0ngPassphrase" }],
    ["a too-short password", { ...validRegistration, password: "Sh0rt" }],
    ["a password without a digit", { ...validRegistration, password: "NoDigitsHereAtAll" }],
    ["a password without an uppercase letter", { ...validRegistration, password: "str0ngpassphrase" }],
  ])("rejects %s with 400", async (_label, payload) => {
    const response = await register(payload);

    expect(response.statusCode).toBe(400);
    const body = JSON.parse(response.payload);
    expect(body.code).toBe("VALIDATION_ERROR");
    expect(Array.isArray(body.details)).toBe(true);
    expect(users.rows.size).toBe(0);
  });
});

describe("POST /auth/login", () => {
  it("authenticates a registered user and sets an HttpOnly session cookie", async () => {
    await register();
    const response = await login();

    expect(response.statusCode).toBe(200);
    const body = JSON.parse(response.payload);
    expect(body.user.email).toBe("analyst@sentinelscan.io");
    expect(response.payload).not.toContain(validRegistration.password);
    expect(response.payload).not.toContain("passwordHash");

    const cookie = response.cookies.find((entry) => entry.name === AUTH_COOKIE);
    expect(cookie).toBeDefined();
    expect(cookie?.httpOnly).toBe(true);
    expect(String(cookie?.sameSite).toLowerCase()).toBe("lax");
    expect(cookie?.path).toBe("/");
    expect(String(cookie?.value).split(".")).toHaveLength(3);
  });

  it("accepts the email in any casing", async () => {
    await register();
    const response = await login("  ANALYST@SentinelScan.IO ");

    expect(response.statusCode).toBe(200);
  });

  it("rejects a wrong password without revealing that the account exists", async () => {
    await register();
    const response = await login(validRegistration.email, "Wr0ngPassphrase");

    expect(response.statusCode).toBe(401);
    const body = JSON.parse(response.payload);
    expect(body.code).toBe("INVALID_CREDENTIALS");
    expect(body.message).toBe("Invalid email or password");
    expect(cookieValue(response, AUTH_COOKIE)).toBeUndefined();
  });

  it("returns the same error for an unknown email as for a wrong password", async () => {
    await register();
    const unknown = await login("nobody@sentinelscan.io", "Str0ngPassphrase");
    const wrongPassword = await login(validRegistration.email, "Wr0ngPassphrase");

    expect(unknown.statusCode).toBe(401);
    expect(JSON.parse(unknown.payload).message).toBe(JSON.parse(wrongPassword.payload).message);
    expect(JSON.parse(unknown.payload).code).toBe(JSON.parse(wrongPassword.payload).code);
  });

  it("rejects a password login for a Google-only account", async () => {
    await users.create({
      email: "google-only@sentinelscan.io",
      name: "Google Only",
      passwordHash: null,
      googleId: "google-sub-1",
      emailVerified: true,
    });

    const response = await login("google-only@sentinelscan.io", "Str0ngPassphrase");

    expect(response.statusCode).toBe(401);
    expect(JSON.parse(response.payload).code).toBe("INVALID_CREDENTIALS");
  });

  it("rejects an invalid body with 400", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/auth/login",
      payload: { email: "nope", password: "" },
    });

    expect(response.statusCode).toBe(400);
    expect(JSON.parse(response.payload).code).toBe("VALIDATION_ERROR");
  });
});

describe("GET /auth/me", () => {
  it("returns the current user for a cookie session", async () => {
    const token = await registerAndLogin();

    const response = await app.inject({
      method: "GET",
      url: "/auth/me",
      cookies: { [AUTH_COOKIE]: token },
    });

    expect(response.statusCode).toBe(200);
    const body = JSON.parse(response.payload);
    expect(body.user.email).toBe("analyst@sentinelscan.io");
    expect(body.user).not.toHaveProperty("passwordHash");
    expect(response.payload).not.toContain("$2b$");
  });

  it("also accepts a bearer token for non-browser clients", async () => {
    const token = await registerAndLogin();

    const response = await app.inject({
      method: "GET",
      url: "/auth/me",
      headers: { authorization: `Bearer ${token}` },
    });

    expect(response.statusCode).toBe(200);
    expect(JSON.parse(response.payload).user.email).toBe("analyst@sentinelscan.io");
  });

  it("rejects an unauthenticated request with 401", async () => {
    const response = await app.inject({ method: "GET", url: "/auth/me" });

    expect(response.statusCode).toBe(401);
    const body = JSON.parse(response.payload);
    expect(body.statusCode).toBe(401);
    expect(body.code).toBe("UNAUTHORIZED");
  });

  it("rejects a malformed token with 401", async () => {
    const response = await app.inject({
      method: "GET",
      url: "/auth/me",
      cookies: { [AUTH_COOKIE]: "not-a-jwt" },
    });

    expect(response.statusCode).toBe(401);
    expect(JSON.parse(response.payload).code).toBe("INVALID_TOKEN");
  });

  it("rejects a malformed Authorization header with 401", async () => {
    const response = await app.inject({
      method: "GET",
      url: "/auth/me",
      headers: { authorization: "Bearer one two three" },
    });

    expect(response.statusCode).toBe(401);
  });

  it("rejects a tampered token with 401", async () => {
    const forged = app.jwt.sign({ sub: "someone", email: "attacker@example.com" });
    const tampered = `${forged.slice(0, -3)}abc`;

    const response = await app.inject({
      method: "GET",
      url: "/auth/me",
      cookies: { [AUTH_COOKIE]: tampered },
    });

    expect(response.statusCode).toBe(401);
    expect(JSON.parse(response.payload).code).toBe("INVALID_TOKEN");
  });

  it("rejects an expired token with 401", async () => {
    await register();
    const stored = [...users.rows.values()][0];
    const expired = app.jwt.sign({ sub: stored?.id ?? "", email: stored?.email ?? "" }, { expiresIn: "-1s" });

    const response = await app.inject({
      method: "GET",
      url: "/auth/me",
      cookies: { [AUTH_COOKIE]: expired },
    });

    expect(response.statusCode).toBe(401);
    expect(JSON.parse(response.payload).code).toBe("TOKEN_EXPIRED");
  });

  it("rejects a valid token whose user no longer exists", async () => {
    const token = await registerAndLogin();
    users.reset();

    const response = await app.inject({
      method: "GET",
      url: "/auth/me",
      cookies: { [AUTH_COOKIE]: token },
    });

    expect(response.statusCode).toBe(401);
    expect(JSON.parse(response.payload).code).toBe("INVALID_TOKEN");
  });
});

describe("POST /auth/logout", () => {
  it("clears the session cookie", async () => {
    const token = await registerAndLogin();

    const response = await app.inject({
      method: "POST",
      url: "/auth/logout",
      cookies: { [AUTH_COOKIE]: token },
    });

    expect(response.statusCode).toBe(200);
    expect(JSON.parse(response.payload)).toEqual({ success: true });

    const cleared = response.cookies.find((entry) => entry.name === AUTH_COOKIE);
    expect(cleared).toBeDefined();
    expect(cleared?.value).toBe("");
    expect(cleared?.httpOnly).toBe(true);
  });

  it("succeeds without an active session", async () => {
    const response = await app.inject({ method: "POST", url: "/auth/logout" });

    expect(response.statusCode).toBe(200);
  });

  it("leaves the browser unable to reach a protected route afterwards", async () => {
    const token = await registerAndLogin();
    await app.inject({ method: "POST", url: "/auth/logout", cookies: { [AUTH_COOKIE]: token } });

    // The browser now sends back the cleared (empty) cookie.
    const response = await app.inject({
      method: "GET",
      url: "/auth/me",
      cookies: { [AUTH_COOKIE]: "" },
    });

    expect(response.statusCode).toBe(401);
  });
});
