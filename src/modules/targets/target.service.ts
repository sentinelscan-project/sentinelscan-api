import { ConflictError, NotFoundError } from "../../lib/errors.js";
import { isUniqueConstraintError } from "../../lib/prisma-errors.js";
import type {
  TargetRecord,
  TargetRepository,
  UpdateTargetInput,
} from "../../repositories/target.repository.js";
import type { CreateTargetBody, UpdateTargetBody } from "./target.schemas.js";

function duplicateTargetError(): ConflictError {
  return new ConflictError("A target with this URL already exists", "TARGET_ALREADY_EXISTS");
}

/**
 * Identical whether `id` does not exist at all or belongs to a different
 * user — the two must never be distinguishable to the caller, or a 403-style
 * response would let one user enumerate another user's target ids.
 */
function targetNotFoundError(): NotFoundError {
  return new NotFoundError("Target not found", "TARGET_NOT_FOUND");
}

export async function createTarget(
  repository: TargetRepository,
  ownerId: string,
  body: CreateTargetBody,
): Promise<TargetRecord> {
  try {
    return await repository.create({
      ownerId,
      name: body.name,
      url: body.url,
      description: body.description ?? null,
    });
  } catch (error) {
    // Two concurrent requests can both pass a pre-check; the unique index on
    // (ownerId, url) is the real arbiter.
    if (isUniqueConstraintError(error)) {
      throw duplicateTargetError();
    }
    throw error;
  }
}

export function listTargets(repository: TargetRepository, ownerId: string): Promise<TargetRecord[]> {
  return repository.listByOwner(ownerId);
}

export async function getTarget(
  repository: TargetRepository,
  ownerId: string,
  id: string,
): Promise<TargetRecord> {
  const target = await repository.findByIdForOwner(id, ownerId);
  if (!target) {
    throw targetNotFoundError();
  }
  return target;
}

export async function updateTarget(
  repository: TargetRepository,
  ownerId: string,
  id: string,
  body: UpdateTargetBody,
): Promise<TargetRecord> {
  const input: UpdateTargetInput = {};
  if (body.name !== undefined) input.name = body.name;
  if (body.url !== undefined) input.url = body.url;
  if (body.description !== undefined) input.description = body.description;
  if (body.status !== undefined) input.status = body.status;

  try {
    const updated = await repository.updateForOwner(id, ownerId, input);
    if (!updated) {
      throw targetNotFoundError();
    }
    return updated;
  } catch (error) {
    if (isUniqueConstraintError(error)) {
      throw duplicateTargetError();
    }
    throw error;
  }
}

export async function deleteTarget(repository: TargetRepository, ownerId: string, id: string): Promise<void> {
  const deleted = await repository.deleteForOwner(id, ownerId);
  if (!deleted) {
    throw targetNotFoundError();
  }
}
