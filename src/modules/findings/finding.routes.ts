import type { FastifyInstance, FastifyPluginAsync, FastifyRequest } from "fastify";
import { UnauthorizedError } from "../../lib/errors.js";
import { parseOrThrow } from "../../lib/validation.js";
import { toPublicFinding } from "../../repositories/finding.repository.js";
import { findingIdParamsSchema } from "./finding.schemas.js";
import { getFinding } from "./finding.service.js";

/** Mirrors `scan.routes.ts`'s `requireOwnerId`. */
function requireOwnerId(request: FastifyRequest): string {
  const user = request.currentUser;
  if (!user) {
    throw new UnauthorizedError();
  }
  return user.id;
}

/**
 * `GET /findings/:id` — a single finding, only when it belongs to a scan the
 * authenticated caller owns. Findings-for-a-scan (`GET
 * /scans/:scanId/findings`) is registered in `scan.routes.ts` instead,
 * mirroring Stage 4's precedent of nesting scan creation under its parent
 * target resource.
 */
export const findingRoutes: FastifyPluginAsync = async (fastify: FastifyInstance) => {
  fastify.addHook("preHandler", fastify.authenticate);

  fastify.get("/:id", async (request, reply) => {
    const ownerId = requireOwnerId(request);
    const params = parseOrThrow(findingIdParamsSchema, request.params);
    const finding = await getFinding(fastify.findingRepository, ownerId, params.id);
    return reply.status(200).send({ finding: toPublicFinding(finding) });
  });
};
