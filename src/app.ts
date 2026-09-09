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
import { prismaVerificationTokenRepository } from "./repositories/token.repository.js";
import type { VerificationTokenRepository } from "./repositories/token.repository.js";
import { defaultEmailService, type EmailService } from "./lib/email-service.js";
import { targetRoutes } from "./modules/targets/target.routes.js";
import { prismaTargetRepository } from "./repositories/prisma-target.repository.js";
import type { TargetRepository } from "./repositories/target.repository.js";
import { scanRoutes } from "./modules/scans/scan.routes.js";
import { prismaScanRepository } from "./repositories/prisma-scan.repository.js";
import type { ScanRepository } from "./repositories/scan.repository.js";

export interface BuildAppOptions {
  /**
   * Persistence boundary for users. Defaults to the Prisma-backed repository;
   * tests inject an in-memory implementation so the suite needs no database.
   */
  userRepository?: UserRepository;
  /**
   * Persistence boundary for verification tokens. Defaults to the Prisma-backed repository.
   */
  tokenRepository?: VerificationTokenRepository;
  /**
   * Email delivery abstraction. Defaults to the configured provider (development, Resend, etc.).
   */
  emailService?: EmailService;
  /**
   * Persistence boundary for targets. Defaults to the Prisma-backed repository.
   */
  targetRepository?: TargetRepository;
  /**
   * Persistence boundary for scans. Defaults to the Prisma-backed repository.
   */
  scanRepository?: ScanRepository;
}

export function buildApp(options: BuildAppOptions = {}): FastifyInstance {
  const {
    userRepository = prismaUserRepository,
    tokenRepository = prismaVerificationTokenRepository,
    emailService = defaultEmailService,
    targetRepository = prismaTargetRepository,
    scanRepository = prismaScanRepository,
  } = options;

  const app = fastify({
    logger: process.env.NODE_ENV === "test" ? false : { level: "info" },
  });

  // Cookie-based sessions require an explicit origin allowlist: a wildcard
  // origin cannot be combined with credentialed requests.
  app.register(cors, {
    origin: [env.WEB_APP_URL],
    credentials: true,
  });

  app.decorate("tokenRepository", tokenRepository);
  app.decorate("emailService", emailService);
  app.decorate("targetRepository", targetRepository);
  app.decorate("scanRepository", scanRepository);

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

    // Check for Prisma errors and log actionable diagnostics for production server logs
    if (typeof error === "object" && error !== null && "code" in error && typeof error.code === "string") {
      if (error.code === "P2021") {
        request.log.error(
          { code: error.code, message: error.message },
          "[Database Error] Database table does not exist. Migrations must be deployed using 'npx prisma migrate deploy'.",
        );
      } else {
        request.log.error(
          { code: error.code, message: error.message },
          `[Database Error] Prisma error ${error.code} occurred during request execution.`,
        );
      }
    } else {
      app.log.error(error);
    }

    const statusCode = ("statusCode" in error && typeof error.statusCode === "number")
      ? error.statusCode
      : 500;
    const isInternal = statusCode >= 500;
    const errorName = isInternal ? "Internal Server Error" : (error.name || "Error");
    const message = isInternal ? "Internal Server Error" : error.message;

    return reply.status(statusCode).send({
      statusCode,
      error: errorName,
      code: isInternal ? "INTERNAL_SERVER_ERROR" : (("code" in error && typeof error.code === "string") ? error.code : "ERROR"),
      message,
    });
  });

  // Register routes
  app.register(healthRoutes);
  app.register(authRoutes, { prefix: "/auth" });
  app.register(targetRoutes, { prefix: "/targets" });
  app.register(scanRoutes, { prefix: "/scans" });

  return app;
}
