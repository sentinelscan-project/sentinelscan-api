import fastify, { FastifyInstance, FastifyError } from "fastify";
import cors from "@fastify/cors";
import { healthRoutes } from "./routes/health.js";

export function buildApp(): FastifyInstance {
  const app = fastify({
    logger: process.env.NODE_ENV === "test" ? false : { level: "info" },
  });

  // Basic CORS configuration
  app.register(cors, {
    origin: true,
  });

  // Centralized error handling
  app.setErrorHandler((error: FastifyError | Error, _request, reply) => {
    app.log.error(error);
    const statusCode = ("statusCode" in error && typeof error.statusCode === "number")
      ? error.statusCode
      : 500;
    const message = statusCode === 500 ? "Internal Server Error" : error.message;

    reply.status(statusCode).send({
      statusCode,
      error: error.name || "Error",
      message,
    });
  });

  // Register routes
  app.register(healthRoutes);

  return app;
}
