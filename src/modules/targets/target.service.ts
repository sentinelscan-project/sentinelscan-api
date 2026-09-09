import { ConflictError, NotFoundError } from "../../lib/errors.js";
import { isForeignKeyConstraintError, isUniqueConstraintError } from "../../lib/prisma-errors.js";
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
 * Stage 3 gives `Scan.targetId` an `onDelete: Restrict` foreign key
 * (deliberately, to preserve scan history — see the comment on `Scan` in
 * `schema.prisma`), so deleting a target that has scan history now fails at
 * the database. Translated here into the same clean, non-leaking error shape
 * as every other conflict, rather than letting a raw Prisma constraint
 * violation reach the client.
 */
function targetHasScansError(): ConflictError {
  return new ConflictError(
    "This target has scan history and cannot be deleted",
    "TARGET_HAS_SCANS",
  );
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
  try {
    const deleted = await repository.deleteForOwner(id, ownerId);
    if (!deleted) {
      throw targetNotFoundError();
    }
  } catch (error) {
    if (isForeignKeyConstraintError(error)) {
      throw targetHasScansError();
    }
    throw error;
  }
}
