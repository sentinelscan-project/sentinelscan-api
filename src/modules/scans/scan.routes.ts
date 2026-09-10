import type { FastifyInstance, FastifyPluginAsync, FastifyRequest } from "fastify";
import { UnauthorizedError } from "../../lib/errors.js";
import { parseOrThrow } from "../../lib/validation.js";
import { toPublicScan } from "../../repositories/scan.repository.js";
import { toPublicFinding } from "../../repositories/finding.repository.js";
import { listFindingsQuerySchema } from "../findings/finding.schemas.js";
import { listFindingsForScan } from "../findings/finding.service.js";
import { listScansQuerySchema, scanIdParamsSchema } from "./scan.schemas.js";
import { cancelScan, getScan, listScans } from "./scan.service.js";

/**
 * `fastify.authenticate` already guarantees `request.currentUser` is set by
 * the time a handler below runs (it throws first otherwise); this only
 * avoids an `as`/`!` assertion at every call site. Mirrors
 * `target.routes.ts`'s `requireOwnerId`.
 */
function requireOwnerId(request: FastifyRequest): string {
  const user = request.currentUser;
  if (!user) {
    throw new UnauthorizedError();
  }
  return user.id;
}

/**
 * Scan orchestration, mounted under `/scans`. Every route requires
 * authentication and is scoped to `request.currentUser.id` as the requester
 * — never to an id the client supplies.
 *
 * `POST /targets/:targetId/scans`, the scan-creation endpoint, is registered
 * in `target.routes.ts` instead — it is nested under the target resource
 * path, and creation depends on the target's own ownership-scoped lookup.
 *
 * Stage 3 is orchestration only: no route here starts, advances, or
 * completes execution of a scan. `POST /scans/:id/cancel` only ever moves a
 * scan into `cancelled`; nothing transitions a scan to `running`,
 * `completed`, or `failed` via HTTP in this stage (see `scan.service.ts`'s
 * internal lifecycle functions, reserved for Stage 4's executor).
 */
export const scanRoutes: FastifyPluginAsync = async (fastify: FastifyInstance) => {
  fastify.addHook("preHandler", fastify.authenticate);

  fastify.get("/", async (request, reply) => {
    const ownerId = requireOwnerId(request);
    const query = parseOrThrow(listScansQuerySchema, request.query);
    const result = await listScans(fastify.scanRepository, ownerId, query);
    return reply.status(200).send({
      scans: result.scans.map(toPublicScan),
      limit: query.limit,
      offset: query.offset,
      hasMore: result.hasMore,
    });
  });

  fastify.get("/:id", async (request, reply) => {
    const ownerId = requireOwnerId(request);
    const params = parseOrThrow(scanIdParamsSchema, request.params);
    const scan = await getScan(fastify.scanRepository, ownerId, params.id);
    return reply.status(200).send({ scan: toPublicScan(scan) });
  });

  fastify.post("/:id/cancel", async (request, reply) => {
    const ownerId = requireOwnerId(request);
    const params = parseOrThrow(scanIdParamsSchema, request.params);
    const scan = await cancelScan(fastify.scanRepository, ownerId, params.id);
    return reply.status(200).send({ scan: toPublicScan(scan) });
  });

  // Nested under its parent scan, mirroring `target.routes.ts`'s nesting of
  // `POST /targets/:targetId/scans`. `:id` here is the scan id (reusing
  // `scanIdParamsSchema`, the same params shape `GET /scans/:id` already uses).
  fastify.get("/:id/findings", async (request, reply) => {
    const ownerId = requireOwnerId(request);
    const params = parseOrThrow(scanIdParamsSchema, request.params);
    const query = parseOrThrow(listFindingsQuerySchema, request.query);
    const result = await listFindingsForScan(
      fastify.scanRepository,
      fastify.findingRepository,
      ownerId,
      params.id,
      query,
    );
    return reply.status(200).send({
      findings: result.findings.map(toPublicFinding),
      counts: result.counts,
      limit: query.limit,
      offset: query.offset,
      hasMore: result.hasMore,
    });
  });
};
