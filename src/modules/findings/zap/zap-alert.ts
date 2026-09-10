/**
 * ZAP's raw alert shape, as returned by `/JSON/core/view/alerts/` (confirmed
 * empirically against a live ZAP 2.17.0 daemon — not guessed). Each element
 * is one *occurrence* (one URL/parameter/attack combination), not one
 * deduplicated rule — the same `pluginId` commonly appears many times across
 * different URLs in one result set. Grouping these into one `NormalizedFinding`
 * per `pluginId` is `zap-alert-normalizer.ts`'s job, not this file's.
 *
 * This is the *only* place in the codebase that knows this shape. Nothing
 * outside `modules/findings/zap/` imports `ZapRawAlert`.
 *
 * A few ZAP-specific quirks worth calling out, since they are easy to get
 * wrong:
 * - `cweid`/`wascid` are strings, and `"0"` means "not set" (not CWE-0 /
 *   WASC-0) in this ZAP version — see `toOptionalNumericId` below.
 * - `reference` is a single string with references separated by newlines,
 *   not a JSON array.
 * - `pluginId` (not `alertRef`) is ZAP's stable, rule-level identifier —
 *   `alertRef` can vary by variant/sub-rule and is not used for grouping.
 */
export interface ZapRawAlert {
  alert?: unknown;
  name?: unknown;
  risk?: unknown;
  confidence?: unknown;
  description?: unknown;
  solution?: unknown;
  reference?: unknown;
  pluginId?: unknown;
  alertRef?: unknown;
  cweid?: unknown;
  wascid?: unknown;
  url?: unknown;
  method?: unknown;
  param?: unknown;
  attack?: unknown;
  evidence?: unknown;
  other?: unknown;
  messageId?: unknown;
  sourceid?: unknown;
  id?: unknown;
}

function asString(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

/** Trims, and treats an empty result as absent — ZAP frequently sends `""` for "no value" fields. */
export function asNonEmptyString(value: unknown): string | undefined {
  const str = asString(value);
  if (str === undefined) return undefined;
  const trimmed = str.trim();
  return trimmed === "" ? undefined : trimmed;
}

/**
 * Parses a ZAP numeric-id-as-string field (`cweid`, `wascid`). `"0"`,
 * missing, blank, and non-numeric values all mean "not provided" — ZAP uses
 * `0` as its own "unset" sentinel for these two fields, never a real CWE-0 or
 * WASC-0 identifier.
 */
export function toOptionalNumericId(value: unknown): number | null {
  const str = asNonEmptyString(value);
  if (str === undefined) return null;
  const num = Number(str);
  if (!Number.isFinite(num) || num <= 0) return null;
  return num;
}

/** Splits ZAP's newline-delimited `reference` string into a clean list of non-blank entries. */
export function parseReferenceList(value: unknown): string[] {
  const str = asString(value);
  if (str === undefined) return [];
  return str
    .split(/\r?\n/)
    .map((entry) => entry.trim())
    .filter((entry) => entry !== "");
}

export { asString };
