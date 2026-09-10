import type { FastifyInstance, FastifyPluginAsync, FastifyRequest } from "fastify";
import { UnauthorizedError } from "../../lib/errors.js";
import { parseOrThrow } from "../../lib/validation.js";
import { toPublicAnalysis } from "../../repositories/analysis.repository.js";
import { analysisIdParamsSchema } from "./analysis.schemas.js";
import { getAnalysis } from "./analysis.service.js";

/** Mirrors `finding.routes.ts`'s `requireOwnerId`. */
function requireOwnerId(request: FastifyRequest): string {
  const user = request.currentUser;
  if (!user) {
    throw new UnauthorizedError();
  }
  return user.id;
}

/**
 * `GET /analysis/:id` — a single security analysis, only when it belongs to
 * a scan the authenticated caller owns. `POST /scans/:scanId/analyze` and
 * `GET /scans/:scanId/analysis` are registered in `scan.routes.ts` instead,
 * mirroring Stage 5's precedent of nesting `GET /scans/:id/findings` under
 * its parent scan resource.
 */
export const analysisRoutes: FastifyPluginAsync = async (fastify: FastifyInstance) => {
  fastify.addHook("preHandler", fastify.authenticate);

  fastify.get("/:id", async (request, reply) => {
    const ownerId = requireOwnerId(request);
    const params = parseOrThrow(analysisIdParamsSchema, request.params);
    const analysis = await getAnalysis(fastify.analysisRepository, ownerId, params.id);
    return reply.status(200).send({ analysis: toPublicAnalysis(analysis) });
  });
};
