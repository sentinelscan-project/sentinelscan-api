import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import fp from "fastify-plugin";
import cookie from "@fastify/cookie";
import jwt from "@fastify/jwt";
import { env } from "../config.js";
import { UnauthorizedError } from "../lib/errors.js";
import type { UserRecord, UserRepository } from "../repositories/user.repository.js";

/** Claims carried by a SentinelScan session token. */
export interface AuthTokenPayload {
  /** User id. */
  sub: string;
  email: string;
}

export interface AuthenticationPluginOptions {
  userRepository: UserRepository;
}

const isProduction = env.NODE_ENV === "production";

/**
 * Cookie attributes for the session cookie.
 *
 * In production:
 * - `httpOnly`: keeps the token out of reach of client-side JavaScript.
 * - `secure`: required for SameSite=None in all modern browsers.
 * - `sameSite`: "none" allows cross-site requests between the Vercel frontend
 *   (https://sentinelscan-web.vercel.app) and the Render API
 *   (https://sentinelscan-api.onrender.com).
 * - `path`: "/" ensures the cookie is sent for all API paths.
 *
 * In local development / test:
 * - `secure`: false (allows plain HTTP).
 * - `sameSite`: "lax" (modern browsers reject SameSite=None over insecure HTTP).
 */
export const sessionCookieOptions = {
  httpOnly: true,
  secure: isProduction,
  sameSite: isProduction ? ("none" as const) : ("lax" as const),
  path: "/",
} as const;

/** Normalizes every @fastify/jwt failure into a 401 with a stable error code. */
function toAuthError(error: unknown): UnauthorizedError {
  const code = typeof error === "object" && error !== null && "code" in error ? String(error.code) : "";

  switch (code) {
    case "FST_JWT_AUTHORIZATION_TOKEN_EXPIRED":
      return new UnauthorizedError("Authentication token has expired", "TOKEN_EXPIRED");
    case "FST_JWT_NO_AUTHORIZATION_IN_HEADER":
    case "FST_JWT_NO_AUTHORIZATION_IN_COOKIE":
    case "FST_JWT_BAD_COOKIE_REQUEST":
      return new UnauthorizedError("Authentication required", "UNAUTHORIZED");
    default:
      return new UnauthorizedError("Invalid authentication token", "INVALID_TOKEN");
  }
}

/**
 * Registers the stateless JWT session mechanism.
 *
 * Tokens are signed with `JWT_SECRET`, expire after `JWT_EXPIRES_IN`, and are
 * delivered in an HttpOnly cookie. An `Authorization: Bearer <token>` header is
 * also accepted so non-browser clients (CI, future CLI tooling) can
 * authenticate without a cookie jar.
 */
async function authenticationPlugin(
  fastify: FastifyInstance,
  options: AuthenticationPluginOptions,
): Promise<void> {
  const { userRepository } = options;

  await fastify.register(cookie);
  await fastify.register(jwt, {
    secret: env.JWT_SECRET,
    sign: { expiresIn: env.JWT_EXPIRES_IN },
    cookie: { cookieName: env.AUTH_COOKIE_NAME, signed: false },
  });

  fastify.decorate("userRepository", userRepository);

  fastify.decorate("issueSession", (reply: FastifyReply, user: UserRecord): string => {
    const payload: AuthTokenPayload = { sub: user.id, email: user.email };
    const token = fastify.jwt.sign(payload);
    reply.setCookie(env.AUTH_COOKIE_NAME, token, sessionCookieOptions);
    return token;
  });

  fastify.decorate("clearSession", (reply: FastifyReply): void => {
    reply.clearCookie(env.AUTH_COOKIE_NAME, sessionCookieOptions);
  });

  fastify.decorateRequest("currentUser", null);

  fastify.decorate("authenticate", async (request: FastifyRequest, _reply: FastifyReply): Promise<void> => {
    let payload: AuthTokenPayload;
    try {
      payload = await request.jwtVerify<AuthTokenPayload>();
    } catch (error) {
      throw toAuthError(error);
    }

    // Re-read the user on every request so that deleted or changed accounts
    // stop being usable before the token itself expires.
    const user = await userRepository.findById(payload.sub);
    if (!user) {
      throw new UnauthorizedError("Invalid authentication token", "INVALID_TOKEN");
    }

    request.currentUser = user;
  });
}

export default fp(authenticationPlugin, {
  name: "authentication",
  fastify: "5.x",
});
