/**
 * Persistence boundary for the `Target` model.
 *
 * Every read and write method that takes an `ownerId` filters by it as part
 * of the query itself (not as a check applied to the result afterwards), so
 * ownership is enforced at the data-access layer rather than relying solely
 * on the service layer remembering to check it. `findByIdForOwner`,
 * `updateForOwner` and `deleteForOwner` all return "not found" for a target
 * that exists but belongs to someone else — identical to a target that does
 * not exist at all — so a non-owner can never distinguish the two.
 */

export type TargetStatus = "active" | "inactive";

/** A full target row. `ownerId` is internal — see {@link PublicTarget}. */
export interface TargetRecord {
  id: string;
  ownerId: string;
  name: string;
  url: string;
  description: string | null;
  status: TargetStatus;
  createdAt: Date;
  updatedAt: Date;
}

export interface CreateTargetInput {
  ownerId: string;
  name: string;
  url: string;
  description?: string | null;
}

/** Only the fields being changed should be present; the rest are left alone. */
export interface UpdateTargetInput {
  name?: string;
  url?: string;
  description?: string | null;
  status?: TargetStatus;
}

export interface TargetRepository {
  create(input: CreateTargetInput): Promise<TargetRecord>;
  /** All targets owned by `ownerId`, newest first. */
  listByOwner(ownerId: string): Promise<TargetRecord[]>;
  findByIdForOwner(id: string, ownerId: string): Promise<TargetRecord | null>;
  /** Returns `null` rather than throwing when `id` does not belong to `ownerId`. */
  updateForOwner(id: string, ownerId: string, input: UpdateTargetInput): Promise<TargetRecord | null>;
  /** Returns whether a row was actually deleted. */
  deleteForOwner(id: string, ownerId: string): Promise<boolean>;
}

/**
 * The only target shape that may cross the API boundary.
 *
 * `ownerId` is deliberately absent: the caller already knows who they are
 * (every target returned here is theirs), and not echoing it back removes any
 * temptation for a client to treat it as a settable, trustworthy field.
 */
export interface PublicTarget {
  id: string;
  name: string;
  url: string;
  description: string | null;
  status: TargetStatus;
  createdAt: string;
  updatedAt: string;
}

export function toPublicTarget(target: TargetRecord): PublicTarget {
  return {
    id: target.id,
    name: target.name,
    url: target.url,
    description: target.description,
    status: target.status,
    createdAt: target.createdAt.toISOString(),
    updatedAt: target.updatedAt.toISOString(),
  };
}
