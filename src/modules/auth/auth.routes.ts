import type { FastifyInstance, FastifyPluginAsync } from "fastify";
import { UnauthorizedError } from "../../lib/errors.js";
import { parseOrThrow } from "../../lib/validation.js";
import { toPublicUser } from "../../repositories/user.repository.js";
import {
  loginBodySchema,
  registerBodySchema,
  resendVerificationBodySchema,
  verifyEmailBodySchema,
} from "./auth.schemas.js";
import {
  loginUser,
  registerUser,
  resendVerificationEmail,
  verifyEmail,
} from "./auth.service.js";
import { googleAuthRoutes } from "./google.routes.js";

/**
 * Identity endpoints, mounted under `/auth`.
 *
 * Authorization (who may touch which target/scan/report) is deliberately not
 * handled here — these routes only establish *who* the caller is.
 */
export const authRoutes: FastifyPluginAsync = async (fastify: FastifyInstance) => {
  fastify.post("/register", async (request, reply) => {
    const body = parseOrThrow(registerBodySchema, request.body);
    const user = await registerUser(
      fastify.userRepository,
      fastify.tokenRepository,
      fastify.emailService,
      body,
    );
    return reply.status(201).send({
      user: toPublicUser(user),
      message: "Registration successful. Please check your email to verify your account.",
    });
  });

  fastify.post("/verify-email", async (request, reply) => {
    const body = parseOrThrow(verifyEmailBodySchema, request.body);
    const user = await verifyEmail(fastify.userRepository, fastify.tokenRepository, body.token);
    fastify.issueSession(reply, user);
    return reply.status(200).send({
      user: toPublicUser(user),
      message: "Email verified successfully.",
    });
  });

  fastify.post("/resend-verification", async (request, reply) => {
    const body = parseOrThrow(resendVerificationBodySchema, request.body);
    const result = await resendVerificationEmail(
      fastify.userRepository,
      fastify.tokenRepository,
      fastify.emailService,
      body.email,
    );
    return reply.status(200).send(result);
  });

  fastify.post("/login", async (request, reply) => {
    const body = parseOrThrow(loginBodySchema, request.body);
    const user = await loginUser(fastify.userRepository, body);
    fastify.issueSession(reply, user);
    return reply.status(200).send({ user: toPublicUser(user) });
  });

  fastify.get("/me", { preHandler: [fastify.authenticate] }, async (request, reply) => {
    const user = request.currentUser;
    if (!user) {
      throw new UnauthorizedError();
    }
    return reply.status(200).send({ user: toPublicUser(user) });
  });

  // Public and idempotent: clearing a session must succeed even when the
  // presented token is already expired or absent.
  fastify.post("/logout", async (_request, reply) => {
    fastify.clearSession(reply);
    return reply.status(200).send({ success: true });
  });

  await fastify.register(googleAuthRoutes);
};
