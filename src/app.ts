import fastify, { FastifyInstance, FastifyError } from "fastify";
import cors from "@fastify/cors";
import { ZodError } from "zod";
import { env } from "./config.js";
import { AppError } from "./lib/errors.js";
import { formatZodIssues } from "./lib/validation.js";
import authentication from "./plugins/authentication.js";
import { healthRoutes } from "./routes/health.js";
import { authRoutes } from "./modules/auth/auth.routes.js";
import { prismaUserRepository } from "./repositories/prisma-user.repository.js";
import type { UserRepository } from "./repositories/user.repository.js";

export interface BuildAppOptions {
  /**
   * Persistence boundary for users. Defaults to the Prisma-backed repository;
   * tests inject an in-memory implementation so the suite needs no database.
   */
  userRepository?: UserRepository;
}

export function buildApp(options: BuildAppOptions = {}): FastifyInstance {
  const { userRepository = prismaUserRepository } = options;

  const app = fastify({
    logger: process.env.NODE_ENV === "test" ? false : { level: "info" },
  });

  // Cookie-based sessions require an explicit origin allowlist: a wildcard
  // origin cannot be combined with credentialed requests.
  app.register(cors, {
    origin: [env.WEB_APP_URL],
    credentials: true,
  });

  app.register(authentication, { userRepository });

  // Centralized error handling
  app.setErrorHandler((error: FastifyError | Error, request, reply) => {
    if (error instanceof AppError) {
      request.log.warn({ err: error, code: error.code }, "Request failed");
      return reply.status(error.statusCode).send({
        statusCode: error.statusCode,
        error: error.name,
        code: error.code,
        message: error.message,
        ...(error.details === undefined ? {} : { details: error.details }),
      });
    }

    if (error instanceof ZodError) {
      request.log.warn({ err: error }, "Request validation failed");
      return reply.status(400).send({
        statusCode: 400,
        error: "ValidationError",
        code: "VALIDATION_ERROR",
        message: "Request validation failed",
        details: formatZodIssues(error),
      });
    }

    app.log.error(error);
    const statusCode = ("statusCode" in error && typeof error.statusCode === "number")
      ? error.statusCode
      : 500;
    const message = statusCode === 500 ? "Internal Server Error" : error.message;

    return reply.status(statusCode).send({
      statusCode,
      error: error.name || "Error",
      message,
    });
  });

  // Register routes
  app.register(healthRoutes);
  app.register(authRoutes, { prefix: "/auth" });

  return app;
}
