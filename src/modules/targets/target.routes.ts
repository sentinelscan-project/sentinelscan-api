import type { FastifyInstance, FastifyPluginAsync, FastifyRequest } from "fastify";
import { UnauthorizedError } from "../../lib/errors.js";
import { parseOrThrow } from "../../lib/validation.js";
import { toPublicTarget } from "../../repositories/target.repository.js";
import {
  createTargetBodySchema,
  targetIdParamsSchema,
  updateTargetBodySchema,
} from "./target.schemas.js";
import { createTarget, deleteTarget, getTarget, listTargets, updateTarget } from "./target.service.js";

/**
 * Every target belongs to whoever created it. `fastify.authenticate` already
 * guarantees `request.currentUser` is set by the time a handler below runs
 * (it throws first otherwise), so this only exists to get a non-nullable id
 * out without an `as`/`!` assertion at every call site.
 */
function requireOwnerId(request: FastifyRequest): string {
  const user = request.currentUser;
  if (!user) {
    throw new UnauthorizedError();
  }
  return user.id;
}

/**
 * Authorized-target management, mounted under `/targets`.
 *
 * Every route here requires authentication, and every operation is scoped to
 * `request.currentUser.id` as the owner — never to an id the client supplies.
 * This is registration and management only: nothing here makes a network
 * request to a target's `url`, resolves DNS, or talks to ZAP. That is Stage 3+.
 */
export const targetRoutes: FastifyPluginAsync = async (fastify: FastifyInstance) => {
  fastify.addHook("preHandler", fastify.authenticate);

  fastify.post("/", async (request, reply) => {
    const ownerId = requireOwnerId(request);
    const body = parseOrThrow(createTargetBodySchema, request.body);
    const target = await createTarget(fastify.targetRepository, ownerId, body);
    return reply.status(201).send({ target: toPublicTarget(target) });
  });

  fastify.get("/", async (request, reply) => {
    const ownerId = requireOwnerId(request);
    const targets = await listTargets(fastify.targetRepository, ownerId);
    return reply.status(200).send({ targets: targets.map(toPublicTarget) });
  });

  fastify.get("/:id", async (request, reply) => {
    const ownerId = requireOwnerId(request);
    const params = parseOrThrow(targetIdParamsSchema, request.params);
    const target = await getTarget(fastify.targetRepository, ownerId, params.id);
    return reply.status(200).send({ target: toPublicTarget(target) });
  });

  fastify.patch("/:id", async (request, reply) => {
    const ownerId = requireOwnerId(request);
    const params = parseOrThrow(targetIdParamsSchema, request.params);
    const body = parseOrThrow(updateTargetBodySchema, request.body);
    const target = await updateTarget(fastify.targetRepository, ownerId, params.id, body);
    return reply.status(200).send({ target: toPublicTarget(target) });
  });

  fastify.delete("/:id", async (request, reply) => {
    const ownerId = requireOwnerId(request);
    const params = parseOrThrow(targetIdParamsSchema, request.params);
    await deleteTarget(fastify.targetRepository, ownerId, params.id);
    return reply.status(204).send();
  });
};
