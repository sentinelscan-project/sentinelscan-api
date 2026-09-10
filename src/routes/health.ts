import { FastifyInstance, FastifyPluginAsync } from "fastify";

export const healthRoutes: FastifyPluginAsync = async (fastify: FastifyInstance) => {
  fastify.get("/health", async (_request, reply) => {
    return reply.status(200).send({ status: "ok" });
  });

  /**
   * Application-level ZAP connectivity check — not a proxy for ZAP's own
   * administration API, which stays entirely off this API's surface. The
   * response is intentionally minimal: whether ZAP is reachable and, if so,
   * its version. No internal network details, and no API key: `ZapClient`
   * never exposes the key it may be configured with, and this route couldn't
   * leak it even if it wanted to.
   */
  fastify.get("/health/zap", async (_request, reply) => {
    const health = await fastify.zapClient.health();
    return reply.status(health.reachable ? 200 : 503).send(health);
  });
};
